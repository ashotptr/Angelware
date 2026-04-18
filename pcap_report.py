"""
====================================================
 Angelware — C2 Analysis Report Generator
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective generates a detailed per-capture HTML report (via Jinja2)
  and converts it to PDF (via pdfkit/wkhtmltopdf) containing:
    • Capture metadata and SHA256
    • Configured detection thresholds
    • A scored indicator dial (N/M detected)
    • Detailed tables for every detection type
    • Enrichment data

  Angelware had:
    • generate_graphs.py   — 3 research PNG graphs (different purpose)
    • honeypot_setup.py --report — Cowrie NIST IR report from log events

  Neither produced a per-capture C2 analysis HTML+PDF.

Usage:
    from pcap_report import PcapReportGenerator

    generator = PcapReportGenerator(
        output_dir="reports/",
        thresholds={...},
        statistics={...},
        detection_results={...},
        enriched_iocs={},
        scorer=scorer,
        dga_enabled=True,
        threat_feed_enabled=True,
    )
    generator.write_detected_iocs_json()
    generator.write_enriched_iocs_json()
    generator.create_html_report()
    generator.create_pdf_report()   # requires wkhtmltopdf installed

CLI:
    python3 pcap_report.py --detected detected_iocs.json \
                           --enriched enriched_iocs.json \
                           --stats extracted_data.json \
                           --output-dir reports/
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_HERE         = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_PATH = os.path.join(_HERE, "templates", "c2_report.html")


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class PcapReportGenerator:
    """
    Generate HTML and PDF analysis reports from C2 detection results.

    Parameters
    ----------
    output_dir          : directory for output files
    thresholds          : dict of detection thresholds (for display)
    statistics          : dict from PcapIOCExtractor.statistics
    detection_results   : combined dict of all detection findings
    enriched_iocs       : dict from IOCEnricher.enrich()
    scorer              : DetectionScorer instance (optional)
    dga_enabled         : whether DGA detection was run
    threat_feed_enabled : whether C2ThreatFeed was used
    """

    def __init__(
        self,
        output_dir:          str,
        thresholds:          Dict,
        statistics:          Dict,
        detection_results:   Dict,
        enriched_iocs:       Dict,
        scorer              = None,    # DetectionScorer
        dga_enabled:         bool = False,
        threat_feed_enabled: bool = False,
    ):
        self.output_dir          = output_dir
        self.thresholds          = thresholds
        self.statistics          = statistics
        self.detection_results   = detection_results
        self.enriched_iocs       = enriched_iocs
        self.scorer              = scorer
        self.dga_enabled         = dga_enabled
        self.threat_feed_enabled = threat_feed_enabled
        self.timestamp           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        os.makedirs(output_dir, exist_ok=True)

        self.html_path         = os.path.join(output_dir, "c2_analysis_report.html")
        self.pdf_path          = os.path.join(output_dir, "c2_analysis_report.pdf")
        self.iocs_json_path    = os.path.join(output_dir, "detected_iocs.json")
        self.enriched_json_path = os.path.join(output_dir, "enriched_iocs.json")

    # ------------------------------------------------------------------
    def write_detected_iocs_json(self):
        print(f"[{_ts()}] [INFO] Writing detected IOCs → '{self.iocs_json_path}' …")
        with open(self.iocs_json_path, "w") as fh:
            json.dump(self.detection_results, fh, indent=4, default=str)

    def write_enriched_iocs_json(self):
        if not self.enriched_iocs:
            return
        print(f"[{_ts()}] [INFO] Writing enriched IOCs → '{self.enriched_json_path}' …")
        with open(self.enriched_json_path, "w") as fh:
            json.dump(self.enriched_iocs, fh, indent=4, default=str)

    # ------------------------------------------------------------------
    def create_html_report(self):
        print(f"[{_ts()}] [INFO] Generating HTML report → '{self.html_path}' …")
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            print(f"[{_ts()}] [ERROR] Jinja2 not installed. "
                  "Run: pip install jinja2")
            self._write_basic_html()
            return

        template_dir = os.path.dirname(TEMPLATE_PATH)
        template_name = os.path.basename(TEMPLATE_PATH)

        if not os.path.exists(TEMPLATE_PATH):
            print(f"[{_ts()}] [WARNING] Template not found at {TEMPLATE_PATH} — "
                  "generating basic HTML")
            self._write_basic_html()
            return

        env  = Environment(loader=FileSystemLoader(template_dir))
        tmpl = env.get_template(template_name)

        score_dict = self.scorer.to_dict() if self.scorer else {}

        html = tmpl.render(
            current_datetime    = self.timestamp,
            thresholds          = self.thresholds,
            statistics          = self.statistics,
            detection_results   = self.detection_results,
            enriched_iocs       = self.enriched_iocs,
            score               = score_dict,
            dga_enabled         = self.dga_enabled,
            threat_feed_enabled = self.threat_feed_enabled,
        )
        with open(self.html_path, "w") as fh:
            fh.write(html)
        print(f"[{_ts()}] [INFO] HTML report generated")

    # ------------------------------------------------------------------
    def create_pdf_report(self):
        if not os.path.exists(self.html_path):
            print(f"[{_ts()}] [ERROR] HTML report not found — run create_html_report() first")
            return
        try:
            import pdfkit
            from bs4 import BeautifulSoup
        except ImportError:
            print(f"[{_ts()}] [ERROR] pdfkit or beautifulsoup4 not installed. "
                  "Run: pip install pdfkit beautifulsoup4   and  apt install wkhtmltopdf")
            return

        print(f"[{_ts()}] [INFO] Converting to PDF → '{self.pdf_path}' …")
        opts = {
            "page-size":      "A3",
            "margin-top":     "0.25in",
            "margin-right":   "0.25in",
            "margin-bottom":  "0.25in",
            "margin-left":    "0.25in",
            "orientation":    "Landscape",
        }
        try:
            with open(self.html_path) as fh:
                soup = BeautifulSoup(fh, "html.parser")
            # Remove any JS-only features that break wkhtmltopdf
            for script in soup.find_all("script"):
                script.decompose()
            pdfkit.from_string(str(soup), self.pdf_path, options=opts)
            print(f"[{_ts()}] [INFO] PDF report generated")
        except Exception as e:
            print(f"[{_ts()}] [ERROR] PDF generation failed: {e}")
            logger.error("PDF generation failed: %s", e)

    # ------------------------------------------------------------------
    def _write_basic_html(self):
        """Minimal fallback HTML when Jinja2 or template is missing."""
        det = self.detection_results
        score = self.scorer.summary() if self.scorer else {}
        fired = score.get("fired", 0)
        total = score.get("total_checks", "?")

        lines = [
            "<!DOCTYPE html><html><head><title>C2 Analysis Report</title>",
            "<style>body{font-family:monospace;margin:2em;} "
            "table{border-collapse:collapse;width:100%;} "
            "td,th{border:1px solid #ccc;padding:6px;} "
            "th{background:#f0f0f0;}</style></head><body>",
            "<h1>Angelware — C2 Analysis Report</h1>",
            f"<p>Generated: {self.timestamp}</p>",
            f"<h2>Detection Score: {fired} / {total}</h2>",
            "<h2>Capture Statistics</h2><table>",
        ]
        for k, v in self.statistics.items():
            lines.append(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>")
        lines.append("</table><h2>Detection Results</h2><pre>")
        lines.append(json.dumps(det, indent=2, default=str))
        lines.append("</pre></body></html>")

        with open(self.html_path, "w") as fh:
            fh.write("\n".join(lines))
        print(f"[{_ts()}] [INFO] Basic HTML report generated (Jinja2 unavailable)")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="pcap_report",
        description="C2 Analysis Report Generator — Angelware add-on"
    )
    ap.add_argument("--detected",    metavar="JSON",
                    help="detected_iocs.json from c2_analyzer.py")
    ap.add_argument("--enriched",    metavar="JSON",
                    help="enriched_iocs.json (optional)")
    ap.add_argument("--stats",       metavar="JSON",
                    help="extracted_data.json from pcap_ioc_extractor.py")
    ap.add_argument("--output-dir",  metavar="DIR", default="reports",
                    help="Output directory (default: reports/)")
    ap.add_argument("--no-pdf",      action="store_true",
                    help="Skip PDF generation")
    args = ap.parse_args()

    if not args.detected:
        ap.print_help()
        return

    detected = {}
    enriched = {}
    statistics = {}

    try:
        with open(args.detected) as fh:
            detected = json.load(fh)
    except Exception as e:
        print(f"[ERROR] Cannot load {args.detected}: {e}")
        sys.exit(1)

    if args.enriched and os.path.exists(args.enriched):
        with open(args.enriched) as fh:
            enriched = json.load(fh)

    if args.stats and os.path.exists(args.stats):
        with open(args.stats) as fh:
            statistics = json.load(fh)

    gen = PcapReportGenerator(
        output_dir        = args.output_dir,
        thresholds        = detected.get("thresholds", {}),
        statistics        = statistics,
        detection_results = detected,
        enriched_iocs     = enriched,
    )
    gen.write_detected_iocs_json()
    gen.write_enriched_iocs_json()
    gen.create_html_report()
    if not args.no_pdf:
        gen.create_pdf_report()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
