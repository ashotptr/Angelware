"""
====================================================
 fake_portal_biometrics.py
 Behavioral Biometrics Integration for fake_portal.py

 Gap closed: behavioral_biometrics.py is fully implemented
 with a detailed integration guide in its docstring, but
 fake_portal.py never imports it and the login page template
 has no keyboard/mouse event collection JavaScript.

 This module provides:
   1. The exact LOGIN_PAGE_TMPL addition (JS + hidden fields)
   2. The /login handler code addition (parse + score + log)
   3. A drop-in integration helper get_biometrics_result()
      that fake_portal.py can call with zero boilerplate

 HOW TO APPLY (edit fake_portal.py):

   STEP 1 — Add import block after the TOTP import (~line 8698):
   ─────────────────────────────────────────────────────────────
   # ── Behavioral biometrics (typing + mouse) ─────────────────
   try:
       import behavioral_biometrics as _bio_module
       BIO_ENABLED  = True
       _bio_scorer  = _bio_module.get_scorer()
       print("[PORTAL] Behavioral biometrics: ENABLED (behavioral_biometrics.py)")
   except ImportError:
       BIO_ENABLED  = False
       _bio_scorer  = None
       print("[PORTAL] INFO: behavioral_biometrics.py not found -- biometrics disabled")

   STEP 2 — Replace LOGIN_PAGE_TMPL's form block to add JS + hidden fields.
   Find:
       <input type="password" name="password" placeholder="Password" required>
       {csrf_field}
       <button type="submit">Login</button>
   Replace with:
       <input type="password" name="password" placeholder="Password" required>
       {csrf_field}
       <button type="submit">Login</button>
       <input type="hidden" name="ikt_data">
       <input type="hidden" name="mouse_data">
   And add before </body>:
       {biometrics_script}

   STEP 3 — In /login POST handler, after parsing email/password,
   add (~line 9040):
       ikt_data_raw   = data.get("ikt_data",   "[]")
       mouse_data_raw = data.get("mouse_data", "[]")
       bio_result = get_biometrics_result(
           email, src_ip, ikt_data_raw, mouse_data_raw
       )

   STEP 4 — Add bio_result to the attempt log entry (~line 9232):
       "bio_bot_prob": bio_result.get("bot_probability", 0.0),
       "bio_signal":   bio_result.get("bot_signal", ""),

 OR: import this module from fake_portal.py for auto-wiring:
   import fake_portal_biometrics
   fake_portal_biometrics.apply(app, globals())
====================================================
"""

import json
import logging
import time
from typing import Optional


# ── Biometrics JS snippet (from behavioral_biometrics.py docstring) ──
BIOMETRICS_JS = """<script>
  /* Behavioral biometrics collection — behavioral_biometrics.py integration
     Collects inter-keystroke timing (IKT) and mouse movement entropy.
     Data is submitted as JSON in hidden fields and scored server-side.
     Bots submitting credentials via API/urllib will have empty arrays →
     scored as insufficient_data (not flagged, but noted in attempt log).
     Bots using Selenium/Playwright will produce unnaturally uniform IKT
     (< 50 ms mean → paste_injection signal) or straight-line mouse paths
     (low entropy → bot_like_mouse signal). */
  const ikt = []; let lastKey = 0;
  const pwdField = document.querySelector('[name=password]');
  if (pwdField) {
    pwdField.addEventListener('keydown', e => {
      const now = Date.now();
      if (lastKey) ikt.push(now - lastKey);
      lastKey = now;
    });
  }
  const mouse = [];
  document.addEventListener('mousemove', e => {
    mouse.push({x: e.clientX, y: e.clientY, t: Date.now()});
  });
  const loginForm = document.querySelector('form');
  if (loginForm) {
    loginForm.addEventListener('submit', () => {
      const iktField   = document.querySelector('[name=ikt_data]');
      const mouseField = document.querySelector('[name=mouse_data]');
      if (iktField)   iktField.value   = JSON.stringify(ikt);
      if (mouseField) mouseField.value = JSON.stringify(mouse.slice(-50));
    });
  }
</script>"""

# ── Updated LOGIN_PAGE_TMPL form block ────────────────────────
# This is the complete replacement for the form in fake_portal.py.
# The {csrf_field} and {biometrics_script} placeholders are filled
# by _render_login_page() after applying STEP 2.
LOGIN_PAGE_FORM_REPLACEMENT = """
  <h2>Login to MyApp</h2>
  <form method="POST" action="/login">
    <input type="email"    name="email"    placeholder="Email"    required>
    <input type="password" name="password" placeholder="Password" required>
    {csrf_field}
    <button type="submit">Login</button>
    <input type="hidden" name="ikt_data">
    <input type="hidden" name="mouse_data">
  </form>
  <p class="note">AUA CS 232/337 Lab Portal — isolated environment</p>
{biometrics_script}
"""


# ══════════════════════════════════════════════════════════════
#  INTEGRATION HELPER
# ══════════════════════════════════════════════════════════════

_bio_scorer = None
BIO_ENABLED = False


def _load_scorer():
    global _bio_scorer, BIO_ENABLED
    if _bio_scorer is not None:
        return
    try:
        import behavioral_biometrics as _bm
        _bio_scorer  = _bm.get_scorer()
        BIO_ENABLED  = True
    except ImportError:
        _bio_scorer  = None
        BIO_ENABLED  = False


def get_biometrics_result(email: str, src_ip: str,
                          ikt_data_raw: str,
                          mouse_data_raw: str) -> dict:
    """
    Score a login session's biometric signals.

    Call from fake_portal.py /login handler:
        from fake_portal_biometrics import get_biometrics_result
        bio_result = get_biometrics_result(
            email, src_ip,
            data.get("ikt_data", "[]"),
            data.get("mouse_data", "[]"),
        )
        # bot_probability 0.0 – 1.0
        # bot_signal: "organic"|"paste_injection"|"metronomic"|
        #             "bot_like_mouse"|"insufficient_data"

    Returns a dict with at minimum:
        {
          "bot_probability": float,   # 0.0 = human, 1.0 = confirmed bot
          "bot_signal":      str,     # human-readable classification
          "ikt_score":       dict,    # typing cadence details
          "mouse_score":     dict,    # mouse movement details
        }
    Returns {} if biometrics module is unavailable or data is empty.
    """
    _load_scorer()
    if not BIO_ENABLED or _bio_scorer is None:
        return {}

    try:
        ikt_samples  = json.loads(ikt_data_raw)  if ikt_data_raw  else []
        mouse_events = json.loads(mouse_data_raw) if mouse_data_raw else []
    except (json.JSONDecodeError, TypeError):
        ikt_samples  = []
        mouse_events = []

    try:
        result = _bio_scorer.score_session(
            email        = email,
            ikt_samples  = ikt_samples,
            mouse_events = mouse_events,
            src_ip       = src_ip,
        )
    except Exception as e:
        logging.warning(f"[BIOMETRICS] score_session error: {e}")
        return {}

    # Log summary for the portal's own console
    prob   = result.get("bot_probability", 0.0)
    signal = result.get("bot_signal", "unknown")
    if prob > 0.50:
        logging.warning(
            f"BIOMETRICS | src={src_ip} | email={email} | "
            f"bot_prob={prob:.2f} | signal={signal}"
        )
    elif prob > 0.25:
        logging.info(
            f"BIOMETRICS | src={src_ip} | email={email} | "
            f"bot_prob={prob:.2f} | signal={signal} | SUSPECT"
        )

    return result


def should_escalate(bio_result: dict,
                    threshold: float = 0.75) -> bool:
    """
    Returns True if the biometrics score warrants escalation
    (e.g. triggering CAPTCHA or step-up 2FA).

    Article reference: behavioral_biometrics.py docstring:
      "if bio_score['bot_probability'] > 0.75:
           # Treat as bot — escalate to 2FA / CAPTCHA / tarpit"
    """
    return bio_result.get("bot_probability", 0.0) > threshold


# ══════════════════════════════════════════════════════════════
#  AUTO-WIRE: apply(app, ids_globals)
#  Monkey-patches a running fake_portal.py Flask app.
# ══════════════════════════════════════════════════════════════

def apply(app, portal_globals: dict) -> None:
    """
    Auto-wire biometrics into a running fake_portal.py.

    Usage (add to end of fake_portal.py):
        import fake_portal_biometrics
        fake_portal_biometrics.apply(app, globals())
    """
    _load_scorer()
    portal_globals["BIO_ENABLED"]   = BIO_ENABLED
    portal_globals["_bio_scorer"]   = _bio_scorer
    portal_globals["BIOMETRICS_JS"] = BIOMETRICS_JS

    if not BIO_ENABLED:
        print("[PORTAL] Biometrics auto-wire: behavioral_biometrics.py not found")
        return

    # Patch the LOGIN_PAGE_TMPL to include biometrics script + hidden fields
    orig_tmpl = portal_globals.get("LOGIN_PAGE_TMPL", "")
    if "{biometrics_script}" not in orig_tmpl:
        # Insert hidden fields before </form> and script before </body>
        patched = orig_tmpl.replace(
            "<button type=\"submit\">Login</button>",
            "<button type=\"submit\">Login</button>\n"
            "    <input type=\"hidden\" name=\"ikt_data\">\n"
            "    <input type=\"hidden\" name=\"mouse_data\">"
        ).replace(
            "</body>",
            BIOMETRICS_JS + "\n</body>"
        )
        portal_globals["LOGIN_PAGE_TMPL"] = patched
        print("[PORTAL] Biometrics auto-wire: LOGIN_PAGE_TMPL patched with JS + hidden fields")

    # Wrap the /login view function to inject biometric scoring
    login_view = app.view_functions.get("login")
    if login_view is None:
        print("[PORTAL] Biometrics auto-wire: WARNING — 'login' view not found")
        return

    from flask import request
    import functools

    @functools.wraps(login_view)
    def _biometrics_wrapped_login(*args, **kwargs):
        if request.method == "POST":
            src_ip = request.remote_addr
            email  = (request.get_json() or {}).get("email") \
                     if request.is_json else request.form.get("email", "")
            ikt_raw   = (request.get_json() or {}).get("ikt_data", "[]") \
                        if request.is_json else request.form.get("ikt_data", "[]")
            mouse_raw = (request.get_json() or {}).get("mouse_data", "[]") \
                        if request.is_json else request.form.get("mouse_data", "[]")

            bio = get_biometrics_result(email or "", src_ip, ikt_raw, mouse_raw)
            # Store in request context so the view can access it
            request.bio_result = bio
        return login_view(*args, **kwargs)

    app.view_functions["login"] = _biometrics_wrapped_login
    print("[PORTAL] Biometrics auto-wire: /login wrapped — biometrics scoring active")
    print("[PORTAL]   Signals: paste_injection (<50ms IKT), metronomic, "
          "bot_like_mouse, organic")


# ══════════════════════════════════════════════════════════════
#  SELF-TEST
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Behavioral Biometrics Integration — self-test\n")
    _load_scorer()
    if not BIO_ENABLED:
        print("ERROR: behavioral_biometrics.py not importable.")
        print("  Install: place behavioral_biometrics.py in the lab directory.")
        exit(1)

    # Simulate a bot (paste injection: all IKTs < 15ms)
    bot_ikt   = [10, 12, 8, 11, 9, 14, 10, 12, 11, 10]
    bot_mouse = []   # no mouse (API bot)
    r = get_biometrics_result("victim@example.com", "192.168.100.11",
                               json.dumps(bot_ikt), json.dumps(bot_mouse))
    print(f"Bot (paste injection):")
    print(f"  bot_probability = {r.get('bot_probability', 0):.2f}")
    print(f"  bot_signal      = {r.get('bot_signal', '?')}")
    print(f"  escalate?       = {should_escalate(r)}\n")

    # Simulate a human (natural timing 80-300ms IKTs, varied mouse path)
    import random, math
    human_ikt   = [random.randint(80, 350) for _ in range(12)]
    human_mouse = [
        {"x": int(200 + 50*math.cos(t/3)), "y": int(200 + 30*math.sin(t/2)),
         "t": int(time.time()*1000) + t * 120}
        for t in range(30)
    ]
    r2 = get_biometrics_result("alice@example.com", "192.168.100.1",
                                json.dumps(human_ikt), json.dumps(human_mouse))
    print(f"Human (natural typing):")
    print(f"  bot_probability = {r2.get('bot_probability', 0):.2f}")
    print(f"  bot_signal      = {r2.get('bot_signal', '?')}")
    print(f"  escalate?       = {should_escalate(r2)}")
