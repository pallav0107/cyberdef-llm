"""OWASP-category scoring acceptance (written before the scoring function). Run from repo root with PYTHONPATH=src.
 - CWE_OWASP only maps allowed CWEs to the official 2021 categories; expected: 22->A01, 78/89->A03, 327->A02, 522->A04, 798->A07; everything else is outside Top 10
 - scripts/reason_CSC_classacc.py owasp_correct(label, [true cwes]): exact label match for mapped CWEs; OWASP_OUTSIDE label is correct for outside-Top-10 CWEs
 - negatives: wrong category for a mapped CWE is NOT correct; an A-category label for an unmapped CWE (e.g. 787) is NOT correct; 'always correct' mutant is caught."""
import sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
fails = []
try:
    from cyberdef.cwe_oracle import CWE_OWASP, OWASP_OUTSIDE, ALLOWED_CWES, OWASP, owasp_expected
    want = {22: "A01 Broken Access Control", 78: "A03 Injection", 89: "A03 Injection", 327: "A02 Cryptographic Failures", 522: "A04 Insecure Design",
            798: "A07 Identification and Authentication Failures"}
    if CWE_OWASP != want:
        fails.append(f"CWE_OWASP != expected {CWE_OWASP}")
    if not set(CWE_OWASP) <= set(ALLOWED_CWES) or not set(CWE_OWASP.values()) <= set(OWASP):
        fails.append("map outside allowed lists")
    import importlib.util
    spec = importlib.util.spec_from_file_location("ca", "scripts/reason_CSC_classacc.py"); ca = importlib.util.module_from_spec(spec)
    sys.argv = ["x", "/dev/null", "none"]
    src = open("scripts/reason_CSC_classacc.py").read().split("f, kind =")[0]      # import only the function definitions
    ns = {}; exec(src, ns)
    oc = ns["owasp_correct"]
    checks = [(oc("A01 Broken Access Control", [22]), True), (oc("A03 Injection", [78]), True), (oc(OWASP_OUTSIDE, [787]), True),
              (oc(OWASP_OUTSIDE, [134]), True), (oc("A03 Injection", [22]), False), (oc("A03 Injection", [787]), False), (oc(OWASP_OUTSIDE, [78]), False),
              (oc(None, [22]), False)]
    bad = [i for i, (g, w) in enumerate(checks) if g is not w]
    if bad:
        fails.append(f"owasp_correct wrong on checks {bad}")
except Exception as e:
    fails.append(f"unavailable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
