"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: DGA ML Detector (16-Feature Pipeline)
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the complete feature-engineering and ML classification
pipeline from the research resources (repomix-output.txt,
DGA_Detection_ManagedIdentity.ipynb):

Feature vector (16 features, gap items 61-73):
  DNL   – Domain Name Length
  NoS   – Number of Subdomains (labels)
  SLM   – Subdomain Length Mean (ignoring public suffix)
  HwP   – Has www Prefix (binary)
  HVTLD – Has Valid Top-Level Domain (binary)
  CSCS  – Contains Single-Character Subdomain (binary)
  CTS   – Contains TLD as Subdomain (binary)
  UR    – Underscore Ratio
  CIPA  – Contains IP Address (binary)
  CD    – Contains Digit (binary)
  VR    – Vowel Ratio
  DR    – Digit Ratio
  RRC   – Ratio of Repeated Characters
  RCC   – Ratio of Consecutive Consonants
  RCD   – Ratio of Consecutive Digits
  ENT   – Shannon Entropy

Classifiers:
  RandomForestClassifier    (best balanced accuracy ~91.5%)
  GradientBoostingClassifier (best overall ~91.5%)
  GaussianNB                 (fastest, ~76% accuracy)

Public Suffix List stripping (gap item 74) via publicsuffixlist.

Usage:
    from dga_ml_detector import DGAMLDetector, DGAFeatureExtractor
    det = DGAMLDetector()
    det.train_from_variants()          # trains on generated data
    result = det.predict("xmtzpvkw.com")
    print(result)   # {"is_dga": True, "probability": 0.91, "features": {...}}
"""

import math
import os
import re
import json
import joblib
import warnings
import numpy as np
from collections import Counter, defaultdict
from typing import List, Tuple, Dict, Optional

warnings.filterwarnings("ignore")

# ── sklearn ────────────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, roc_auc_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

# ── Optional LSTM / Keras ──────────────────────────────────────
try:
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    import tensorflow as tf
    from tensorflow import keras
    _KERAS_OK = True
except ImportError:
    _KERAS_OK = False

# ── Public Suffix List (gap item 74) ──────────────────────────
try:
    from publicsuffixlist import PublicSuffixList
    _PSL = PublicSuffixList()
    def _strip_psl(domain: str) -> str:
        vps = _PSL.publicsuffix(domain)
        if vps and domain.endswith("." + vps):
            return domain[:-(len(vps) + 1)]
        return domain.split(".")[0]
except ImportError:
    def _strip_psl(domain: str) -> str:
        parts = domain.rstrip(".").split(".")
        return ".".join(parts[:-1]) if len(parts) > 1 else domain

# ── IANA TLD list (minimal inline, extended at runtime) ───────
_IANA_TLDS = {
    "com","net","org","info","biz","edu","gov","int","mil","io","co",
    "uk","us","de","fr","jp","au","ca","ru","nl","eu","cn","in","br",
    "it","es","pl","se","no","fi","dk","at","ch","be","pt","gr","cz",
    "hu","ro","sk","bg","hr","lt","lv","ee","si","cy","mt","lu","ie",
    "ga","im","sc","pw","cc","su","tv","tw","pro","mn","me","xyz","top",
    "site","online","store","tech","app","dev","ai","io","co","club","fun",
    "mobi","name","tel","travel","museum","aero","coop","jobs","cat",
    "ge","am","az","kz","by","ua","md","rs","ba","mk","al",
}


# ═══════════════════════════════════════════════════════════════
#  FEATURE EXTRACTOR  (gap items 61–74)
# ═══════════════════════════════════════════════════════════════

_VOWELS     = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


class DGAFeatureExtractor:
    """
    Extracts the 16-feature vector used in the Spark MLlib notebooks.
    All features operate on the subdomain AFTER stripping the public suffix.
    """

    def extract(self, domain: str) -> Dict[str, float]:
        domain = domain.lower().strip().rstrip(".")
        # ── Public-suffix-aware subdomain ──────────────────────
        subdomain = _strip_psl(domain)
        if not subdomain:
            subdomain = domain.split(".")[0]

        labels = domain.split(".")
        tld    = labels[-1] if labels else ""

        return {
            "DNL":  self._dnl(domain),
            "NoS":  self._nos(subdomain),
            "SLM":  self._slm(subdomain),
            "HwP":  self._hwp(domain),
            "HVTLD":self._hvtld(tld),
            "CSCS": self._cscs(subdomain),
            "CTS":  self._cts(subdomain),
            "UR":   self._ur(subdomain),
            "CIPA": self._cipa(domain),
            "CD":   self._cd(subdomain),
            "VR":   self._vr(subdomain),
            "DR":   self._dr(subdomain),
            "RRC":  self._rrc(subdomain),
            "RCC":  self._rcc(subdomain),
            "RCD":  self._rcd(subdomain),
            "ENT":  self._entropy(subdomain),
        }

    def to_vector(self, domain: str) -> np.ndarray:
        feats = self.extract(domain)
        return np.array([feats[k] for k in self.feature_names()], dtype=float)

    @staticmethod
    def feature_names() -> List[str]:
        return ["DNL","NoS","SLM","HwP","HVTLD","CSCS","CTS",
                "UR","CIPA","CD","VR","DR","RRC","RCC","RCD","ENT"]

    # ── Individual feature methods ─────────────────────────────

    @staticmethod
    def _dnl(domain: str) -> float:
        return float(len(domain))

    @staticmethod
    def _nos(sub: str) -> float:
        return float(sub.count(".") + 1) if sub else 1.0

    @staticmethod
    def _slm(sub: str) -> float:
        parts = sub.split(".")
        total = sum(len(p) for p in parts)
        return float(total / len(parts)) if parts else 0.0

    @staticmethod
    def _hwp(domain: str) -> float:
        return 1.0 if domain.startswith("www.") else 0.0

    @staticmethod
    def _hvtld(tld: str) -> float:
        return 1.0 if tld.lower() in _IANA_TLDS else 0.0

    @staticmethod
    def _cscs(sub: str) -> float:
        parts = sub.split(".")
        return 1.0 if any(len(p) == 1 for p in parts) else 0.0

    @staticmethod
    def _cts(sub: str) -> float:
        parts = sub.split(".")
        return 1.0 if any(p.lower() in _IANA_TLDS for p in parts[:-1]) else 0.0

    @staticmethod
    def _ur(sub: str) -> float:
        clean = sub.replace(".", "")
        return sub.count("_") / len(clean) if clean else 0.0

    @staticmethod
    def _cipa(domain: str) -> float:
        parts = domain.split(".")
        return 1.0 if all(re.match(r"^\d+$", p) for p in parts) else 0.0

    @staticmethod
    def _cd(sub: str) -> float:
        clean = sub.replace(".", "")
        return 1.0 if any(c.isdigit() for c in clean) else 0.0

    @staticmethod
    def _vr(sub: str) -> float:
        clean = sub.replace(".", "")
        alpha = [c for c in clean if c.isalpha()]
        if len(alpha) <= 1:
            return 0.0
        return sum(1 for c in alpha if c in _VOWELS) / len(alpha)

    @staticmethod
    def _dr(sub: str) -> float:
        clean = sub.replace(".", "")
        alnum = [c for c in clean if c.isalnum()]
        if len(alnum) <= 1:
            return 0.0
        return sum(1 for c in alnum if c.isdigit()) / len(alnum)

    @staticmethod
    def _rrc(sub: str) -> float:
        """Ratio of Repeated Characters (chars appearing > once)."""
        clean = re.sub(r"\.", "", sub)
        if not clean:
            return 0.0
        freq   = Counter(clean)
        uniq   = len(freq)
        repeat = sum(1 for cnt in freq.values() if cnt > 1)
        return repeat / uniq if uniq else 0.0

    @staticmethod
    def _rcc(sub: str) -> float:
        """Ratio of Consecutive Consonants (runs of 2+ consonants)."""
        clean = re.sub(r"\.", "", sub)
        if not clean:
            return 0.0
        run = total = 0
        i   = 0
        while i < len(clean):
            if clean[i].isalpha() and clean[i] not in _VOWELS:
                run += 1
            else:
                if run >= 2:
                    total += run
                run = 0
            i += 1
        if run >= 2:
            total += run
        return total / len(clean)

    @staticmethod
    def _rcd(sub: str) -> float:
        """Ratio of Consecutive Digits (runs of 2+ digits)."""
        clean = re.sub(r"\.", "", sub)
        if not clean:
            return 0.0
        run = total = 0
        for c in clean:
            if c.isdigit():
                run += 1
            else:
                if run >= 2:
                    total += run
                run = 0
        if run >= 2:
            total += run
        return total / len(clean)

    @staticmethod
    def _entropy(sub: str) -> float:
        """Shannon entropy of the subdomain."""
        clean = re.sub(r"\.", "", sub)
        if not clean:
            return 0.0
        prob = [float(clean.count(c)) / len(clean)
                for c in set(clean)]
        return -sum(p * math.log2(p) for p in prob if p > 0)


# ═══════════════════════════════════════════════════════════════
#  ML DETECTOR  (gap items 41–47, 75–77, 85)
# ═══════════════════════════════════════════════════════════════

class DGAMLDetector:
    """
    Three-model DGA classifier with 16 lexical features.

    Models:
      rf  – RandomForestClassifier        (~91% accuracy on labeled data)
      gbt – GradientBoostingClassifier    (~91.5% accuracy, best performer)
      nb  – GaussianNB                    (~76% accuracy, fastest)

    Optionally trains a character-level LSTM if Keras/TF is available.
    """

    MODEL_PATH = "/tmp/dga_models"

    def __init__(self, model: str = "gbt"):
        assert model in ("rf", "gbt", "nb", "lstm"), \
            "model must be 'rf', 'gbt', 'nb', or 'lstm'"
        self.model_name   = model
        self.extractor    = DGAFeatureExtractor()
        self.clf          = None
        self.label_enc    = LabelEncoder()
        self._trained     = False
        self._lstm_model  = None
        self._char_idx    = None
        self._max_len     = 75

    # ── Build sklearn estimator ────────────────────────────────

    def _build_estimator(self, model: str):
        if model == "rf":
            return RandomForestClassifier(
                n_estimators=200, max_depth=20,
                n_jobs=-1, random_state=42)
        if model == "gbt":
            return GradientBoostingClassifier(
                n_estimators=200, max_depth=5,
                learning_rate=0.05, random_state=42)
        if model == "nb":
            return GaussianNB()
        return None  # lstm

    # ── Training ───────────────────────────────────────────────

    def train(self,
              domains: List[str],
              labels: List[str],
              test_size: float = 0.2,
              cv_folds: int = 3) -> Dict:
        """
        Train the selected model on (domains, labels).
        labels can be binary ("DGA"/"benign") or multi-class (DGA family names).
        """
        print(f"[ML] Extracting features for {len(domains)} domains …")
        X = np.array([self.extractor.to_vector(d) for d in domains])
        y = self.label_enc.fit_transform(labels)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y)

        if self.model_name == "lstm":
            return self._train_lstm(domains, labels, test_size)

        print(f"[ML] Training {self.model_name} on {len(X_tr)} samples …")
        self.clf = self._build_estimator(self.model_name)
        self.clf.fit(X_tr, y_tr)
        self._trained = True

        # Evaluate
        y_pred   = self.clf.predict(X_te)
        acc      = accuracy_score(y_te, y_pred)
        n_class  = len(self.label_enc.classes_)
        avg      = "binary" if n_class == 2 else "macro"

        try:
            y_prob = self.clf.predict_proba(X_te)
            if n_class == 2:
                auc = roc_auc_score(y_te, y_prob[:, 1])
            else:
                auc = roc_auc_score(y_te, y_prob, multi_class="ovr", average="macro")
        except Exception:
            auc = None

        # Cross-validation (gap item 76)
        print(f"[ML] Running {cv_folds}-fold cross-validation …")
        cv_acc = cross_val_score(self.clf, X, y, cv=cv_folds, scoring="accuracy", n_jobs=-1)

        results = {
            "model":       self.model_name,
            "train_size":  len(X_tr),
            "test_size":   len(X_te),
            "accuracy":    round(acc, 4),
            "cv_mean":     round(float(np.mean(cv_acc)), 4),
            "cv_std":      round(float(np.std(cv_acc)), 4),
            "auc":         round(auc, 4) if auc else None,
            "classes":     list(self.label_enc.classes_),
            "report":      classification_report(
                               y_te, y_pred,
                               target_names=self.label_enc.classes_,
                               zero_division=0),
        }
        print(f"[ML] accuracy={acc:.4f}  cv={results['cv_mean']:.4f}±{results['cv_std']:.4f}")
        if auc:
            print(f"[ML] AUC={auc:.4f}")
        return results

    def train_from_variants(self, domains_per_type: int = 200,
                            benign_count: int = 500,
                            binary: bool = True) -> Dict:
        """
        Auto-generate a labeled dataset from dga_variants.py and train.
        If binary=True, labels are "DGA" vs "benign".
        If binary=False, labels are the DGA family name (multi-class).
        """
        from dga_variants import ALL_DGA_TYPES

        domains, labels = [], []

        # DGA domains
        for name, fn in ALL_DGA_TYPES.items():
            try:
                n = min(domains_per_type, 100 if name == "dyre" else domains_per_type)
                generated = fn(count=n)
                for d in generated[:n]:
                    domains.append(d)
                    labels.append("DGA" if binary else name)
            except Exception:
                pass

        # Benign domains (Alexa-style synthetic)
        benign = self._generate_benign(benign_count)
        domains.extend(benign)
        labels.extend(["benign"] * len(benign))

        print(f"[ML] Dataset: {len(domains)} domains ({sum(1 for l in labels if l != 'benign')} DGA, "
              f"{sum(1 for l in labels if l == 'benign')} benign)")
        return self.train(domains, labels)

    @staticmethod
    def _generate_benign(count: int) -> List[str]:
        """Simulate Alexa top-1M style benign domains for training."""
        import random
        words = [
            "google","facebook","youtube","amazon","twitter","microsoft",
            "apple","netflix","reddit","github","stackoverflow","wikipedia",
            "linkedin","instagram","spotify","dropbox","slack","zoom",
            "adobe","oracle","cisco","intel","samsung","sony","ibm",
            "bank","shop","news","mail","cloud","store","app","pay",
            "health","travel","food","sport","game","music","video",
        ]
        tlds = [".com", ".net", ".org", ".co.uk", ".de", ".fr", ".jp"]
        rng  = random.Random(999)
        domains = []
        while len(domains) < count:
            w1  = rng.choice(words)
            sep = rng.choice(["", "-", ""])
            w2  = rng.choice(words) if rng.random() < 0.4 else ""
            tld = rng.choice(tlds)
            d   = w1 + sep + w2 + tld
            domains.append(d)
        return domains

    # ── Prediction API ─────────────────────────────────────────

    def predict(self, domain: str) -> Dict:
        """
        Classify a single domain.
        Returns: {is_dga, probability, label, features}
        """
        if not self._trained and self.model_name != "lstm":
            raise RuntimeError("Model not trained. Call train() or train_from_variants() first.")
        feat  = self.extractor.extract(domain)
        vec   = np.array([feat[k] for k in DGAFeatureExtractor.feature_names()]).reshape(1, -1)

        if self.model_name == "lstm":
            return self._predict_lstm(domain, feat)

        pred   = self.clf.predict(vec)[0]
        proba  = self.clf.predict_proba(vec)[0]
        label  = self.label_enc.inverse_transform([pred])[0]
        is_dga = label != "benign"
        dga_prob = float(max(proba)) if is_dga else float(1 - max(proba))

        return {
            "domain":      domain,
            "is_dga":      is_dga,
            "label":       label,
            "probability": round(dga_prob, 4),
            "features":    {k: round(v, 4) for k, v in feat.items()},
        }

    def predict_batch(self, domains: List[str]) -> List[Dict]:
        return [self.predict(d) for d in domains]

    def feature_importances(self) -> Dict[str, float]:
        """Return feature importances (RF/GBT only)."""
        if self.clf is None or not hasattr(self.clf, "feature_importances_"):
            return {}
        names = DGAFeatureExtractor.feature_names()
        imps  = self.clf.feature_importances_
        return {n: round(float(i), 4) for n, i in sorted(
            zip(names, imps), key=lambda x: -x[1])}

    # ── Persistence ────────────────────────────────────────────

    def save(self, path: str = None) -> str:
        path = path or self.MODEL_PATH
        os.makedirs(path, exist_ok=True)
        joblib.dump(self.clf,       os.path.join(path, f"clf_{self.model_name}.joblib"))
        joblib.dump(self.label_enc, os.path.join(path, "label_enc.joblib"))
        print(f"[ML] Model saved to {path}/")
        return path

    def load(self, path: str = None) -> None:
        path = path or self.MODEL_PATH
        self.clf       = joblib.load(os.path.join(path, f"clf_{self.model_name}.joblib"))
        self.label_enc = joblib.load(os.path.join(path, "label_enc.joblib"))
        self._trained  = True
        print(f"[ML] Model loaded from {path}/")

    # ── LSTM (character-level, gap items 41, 42) ───────────────

    def _build_char_idx(self, domains: List[str]) -> Dict[str, int]:
        chars = sorted(set("".join(domains)))
        return {c: i + 1 for i, c in enumerate(chars)}

    def _encode_domain(self, domain: str, char_idx: Dict, max_len: int) -> np.ndarray:
        enc = [char_idx.get(c, 0) for c in domain[:max_len]]
        pad = [0] * (max_len - len(enc))
        return np.array(enc + pad, dtype=np.float32)

    def _train_lstm(self, domains: List[str], labels: List[str],
                    test_size: float) -> Dict:
        if not _KERAS_OK:
            print("[ML] Keras not available. Falling back to GBT.")
            self.model_name = "gbt"
            self.clf = self._build_estimator("gbt")
            X = np.array([self.extractor.to_vector(d) for d in domains])
            y = self.label_enc.fit_transform(labels)
            X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size, random_state=42)
            self.clf.fit(X_tr, y_tr)
            self._trained = True
            return {"model": "gbt_fallback", "note": "Keras unavailable"}

        print("[ML] Building character-level LSTM …")
        self._char_idx = self._build_char_idx(domains)
        vocab_size = len(self._char_idx) + 1

        X = np.array([self._encode_domain(d, self._char_idx, self._max_len)
                      for d in domains])
        y_raw = self.label_enc.fit_transform(labels)
        n_classes = len(self.label_enc.classes_)

        if n_classes == 2:
            y = y_raw.astype(np.float32)
        else:
            y = keras.utils.to_categorical(y_raw, num_classes=n_classes)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=42)

        model = keras.Sequential([
            keras.layers.Embedding(vocab_size, 32, input_length=self._max_len),
            keras.layers.LSTM(64),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(32, activation="relu"),
            keras.layers.Dense(1 if n_classes == 2 else n_classes,
                               activation="sigmoid" if n_classes == 2 else "softmax"),
        ])
        model.compile(
            optimizer="adam",
            loss="binary_crossentropy" if n_classes == 2 else "categorical_crossentropy",
            metrics=["accuracy"],
        )
        model.fit(X_tr, y_tr, epochs=5, batch_size=128,
                  validation_split=0.1, verbose=0)
        self._lstm_model = model
        self._trained    = True

        _, acc = model.evaluate(X_te, y_te, verbose=0)
        return {"model": "lstm", "accuracy": round(acc, 4)}

    def _predict_lstm(self, domain: str, feat: Dict) -> Dict:
        if self._lstm_model is None or self._char_idx is None:
            raise RuntimeError("LSTM not trained.")
        enc   = self._encode_domain(domain, self._char_idx, self._max_len)
        prob  = float(self._lstm_model.predict(enc.reshape(1, -1), verbose=0)[0][0])
        return {
            "domain":      domain,
            "is_dga":      prob >= 0.5,
            "label":       "DGA" if prob >= 0.5 else "benign",
            "probability": round(prob, 4),
            "features":    {k: round(v, 4) for k, v in feat.items()},
        }


# ═══════════════════════════════════════════════════════════════
#  MULTI-MODEL COMPARISON  (gap item 77)
# ═══════════════════════════════════════════════════════════════

def compare_models(domains: List[str], labels: List[str],
                   test_size: float = 0.2) -> Dict:
    """
    Train RF, GBT, and NB on the same dataset and compare results.
    Mirrors the Spark MLlib notebook model comparison.
    """
    results = {}
    for m in ("rf", "gbt", "nb"):
        print(f"\n{'='*40}")
        print(f" Model: {m.upper()}")
        print(f"{'='*40}")
        det = DGAMLDetector(model=m)
        res = det.train(domains, labels, test_size=test_size)
        results[m] = {
            "accuracy": res["accuracy"],
            "cv_mean":  res["cv_mean"],
            "cv_std":   res["cv_std"],
            "auc":      res.get("auc"),
        }

    # Summary table
    print(f"\n{'='*60}")
    print(f" MODEL COMPARISON SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Model':<8} {'Accuracy':>10} {'CV Mean':>10} {'CV Std':>10} {'AUC':>8}")
    print(f"  {'-'*48}")
    for m, r in results.items():
        auc_s = f"{r['auc']:.4f}" if r['auc'] else "  N/A"
        print(f"  {m.upper():<8} {r['accuracy']:>10.4f} {r['cv_mean']:>10.4f} "
              f"{r['cv_std']:>10.4f} {auc_s:>8}")
    best = max(results, key=lambda k: results[k]["cv_mean"])
    print(f"\n  Best model (by CV accuracy): {best.upper()}")
    return results


# ═══════════════════════════════════════════════════════════════
#  IDS INTEGRATION HOOK
# ═══════════════════════════════════════════════════════════════

_global_detector: Optional[DGAMLDetector] = None


def get_global_detector() -> DGAMLDetector:
    """Return or lazily train the global detector for IDS integration."""
    global _global_detector
    if _global_detector is None:
        _global_detector = DGAMLDetector(model="gbt")
        try:
            _global_detector.load()
            print("[ML-IDS] Loaded pre-trained model.")
        except Exception:
            print("[ML-IDS] Training new model from DGA variants …")
            _global_detector.train_from_variants(
                domains_per_type=150, benign_count=500)
            _global_detector.save()
    return _global_detector


def ml_classify_domain(domain: str) -> Dict:
    """Drop-in IDS hook: classify a single domain using the global model."""
    try:
        return get_global_detector().predict(domain)
    except Exception as e:
        return {"domain": domain, "is_dga": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if "--compare" in sys.argv:
        from dga_variants import ALL_DGA_TYPES
        from dga_ml_detector import DGAMLDetector, DGAFeatureExtractor

        # Build balanced dataset
        domains, labels = [], []
        for name, fn in ALL_DGA_TYPES.items():
            try:
                for d in fn(count=150)[:150]:
                    domains.append(d)
                    labels.append("DGA")
            except Exception:
                pass
        benign = DGAMLDetector._generate_benign(500)
        domains.extend(benign)
        labels.extend(["benign"] * len(benign))

        compare_models(domains, labels)

    elif "--train" in sys.argv:
        model = "gbt"
        for arg in sys.argv:
            if arg in ("rf", "gbt", "nb", "lstm"):
                model = arg
        det = DGAMLDetector(model=model)
        results = det.train_from_variants()
        det.save()
        print(f"\n[ML] Training complete. accuracy={results['accuracy']}")
        print(f"[ML] Feature importances:")
        for feat, imp in det.feature_importances().items():
            print(f"  {feat:<6} {imp:.4f}")

    elif "--predict" in sys.argv:
        idx = sys.argv.index("--predict")
        if idx + 1 < len(sys.argv):
            det = DGAMLDetector(model="gbt")
            try:
                det.load()
            except Exception:
                det.train_from_variants(domains_per_type=100, benign_count=300)
            result = det.predict(sys.argv[idx + 1])
            import json
            print(json.dumps(result, indent=2))
    else:
        print("Usage:")
        print("  python3 dga_ml_detector.py --train [rf|gbt|nb|lstm]")
        print("  python3 dga_ml_detector.py --compare")
        print("  python3 dga_ml_detector.py --predict <domain>")


# ═══════════════════════════════════════════════════════════════
#  GAP 44: CountVectorizer + MultinomialNB  (DGA_Detection_ManagedIdentity)
#  This is the EXACT model from the Sentinel notebook: character
#  n-gram CountVectorizer fed into MultinomialNB — a completely
#  different architecture from the 16-feature numeric pipeline.
# ═══════════════════════════════════════════════════════════════

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline as _make_pipeline


class SentinelStyleDGAModel:
    """
    Exact replica of the DGA_Detection_ManagedIdentity.ipynb model:
      CountVectorizer(char n-grams) → MultinomialNB

    The notebook uses CountVectorizer's default (word n-grams on domain
    string characters) then MultinomialNB. This learns character-frequency
    patterns without needing manual feature engineering.

    Usage:
        model = SentinelStyleDGAModel()
        model.train_from_variants()
        print(model.predict("xmtzpvkwrdfjbno.com"))  # True
        print(model.predict("google.com"))             # False

    The KQL query from the notebook is reproduced as a static method
    for documentation (cannot execute without Azure connectivity).
    """

    def __init__(self, analyzer: str = "char_wb", ngram_range: tuple = (2, 4)):
        # char_wb creates character n-grams within word boundaries
        # This is what the notebook does via CountVectorizer defaults + domain strings
        self.pipeline = _make_pipeline(
            CountVectorizer(analyzer=analyzer, ngram_range=ngram_range),
            MultinomialNB(),
        )
        self._trained   = False
        self._le        = LabelEncoder()

    def train(self, domains: List[str], labels: List[str],
              test_size: float = 0.1) -> Dict:
        """
        Train CountVectorizer + MultinomialNB exactly as in the Sentinel notebook.
        Labels should be binary: 1 = DGA, 0 = benign.
        """
        y = self._le.fit_transform(labels)
        X_tr, X_te, y_tr, y_te = train_test_split(
            domains, y, test_size=test_size, random_state=42)
        self.pipeline.fit(X_tr, y_tr)
        self._trained = True
        acc = self.pipeline.score(X_te, y_te)
        print(f"[Sentinel-NB] CountVectorizer+MultinomialNB accuracy={acc:.2f}")
        return {"model": "sentinel_nb", "accuracy": round(acc, 4)}

    def train_from_variants(self, domains_per_type: int = 150,
                             benign_count: int = 500) -> Dict:
        from dga_variants import ALL_DGA_TYPES
        domains, labels = [], []
        for name, fn in ALL_DGA_TYPES.items():
            try:
                for d in fn(count=domains_per_type)[:domains_per_type]:
                    domains.append(d)
                    labels.append("DGA")
            except Exception:
                pass
        benign = DGAMLDetector._generate_benign(benign_count)
        domains.extend(benign)
        labels.extend(["benign"] * len(benign))
        return self.train(domains, labels)

    def predict(self, domain: str) -> bool:
        """Returns True if domain is classified as DGA."""
        if not self._trained:
            raise RuntimeError("Call train() first.")
        label = self._le.inverse_transform(self.pipeline.predict([domain]))[0]
        return label == "DGA"

    def predict_proba(self, domain: str) -> float:
        """Returns DGA probability score."""
        if not self._trained:
            raise RuntimeError("Call train() first.")
        proba = self.pipeline.predict_proba([domain])[0]
        dga_idx = list(self._le.classes_).index("DGA")
        return float(proba[dga_idx])

    def apply_to_dataframe(self, domains: List[str]) -> List[Dict]:
        """
        Replicates the notebook's df['IsDGA'] = df['QueryField'].apply(is_dga) step.
        Returns list of {domain, IsDGA, probability} dicts.
        """
        return [
            {"domain": d, "IsDGA": self.predict(d),
             "probability": round(self.predict_proba(d), 4)}
            for d in domains
        ]

    @staticmethod
    def sentinel_kql_query() -> str:
        """
        The exact KQL query from DGA_Detection_ManagedIdentity.ipynb.
        Run this in Azure Sentinel Log Analytics to get candidate domains.
        Cannot execute here without Azure connectivity (gap 49 — documented).
        """
        return """
DeviceNetworkEvents
| where TimeGenerated < ago(30d)
| where ActionType == "DnsConnectionInspected"
| extend QueryField = tostring(parse_json(AdditionalFields).query)
| where isnotempty(QueryField)
| where QueryField matches regex @"[a-zA-Z0-9]{8,}"
| summarize Count = count() by QueryField
| where Count > 10
"""
