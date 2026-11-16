"""FIXED CWE -> oracle (monitor) map for SC-CoT schema v2. Written BEFORE the validator. One oracle per class: the model must recognise the
vulnerability CLASS and route its witness to the monitor that can verify it. oracle "none" = no runtime monitor (static evidence only).

Oracles: asan | ubsan | lsan | tsan | integer | cmd_injection | path_traversal | sqli | format_string | resource | none.
Injection-type oracles (cmd_injection, path_traversal, sqli, format_string): the witness payload must contain the literal token CANARY where the
injected command / path / query / format fragment goes; the harness substitutes and detects it (convention to be confirmed with the monitor builder).
"""
CANARY = "CANARY"
ORACLES = ["asan", "ubsan", "lsan", "tsan", "integer", "cmd_injection", "path_traversal", "sqli", "format_string", "resource", "none"]
INJECTION_ORACLES = {"cmd_injection", "path_traversal", "sqli", "format_string"}

CWE_ORACLE = {
    # memory safety -> asan
    119: "asan", 120: "asan", 121: "asan", 122: "asan", 124: "asan", 125: "asan", 126: "asan", 127: "asan", 129: "asan", 131: "asan",
    415: "asan", 416: "asan", 476: "asan", 590: "asan", 761: "asan", 787: "asan", 788: "asan", 822: "asan", 824: "asan", 825: "asan",
    457: "asan", 908: "asan",            # uninitialised use: grouped sanitizer-detectable by the shared spec (ASan cannot see all of it)
    # integer / arithmetic -> integer monitor
    190: "integer", 191: "integer", 194: "integer", 369: "integer", 680: "integer",
    # leaks, races
    401: "lsan", 362: "tsan",
    # resource exhaustion / hang / assert / runaway recursion
    400: "resource", 617: "resource", 674: "resource", 770: "resource", 835: "resource",
    # injection-type behaviour monitors
    78: "cmd_injection", 22: "path_traversal", 89: "sqli", 134: "format_string",
    # no runtime monitor: static evidence only
    253: "none", 327: "none", 522: "none", 628: "none", 798: "none", 843: "none",
}
ALLOWED_CWES = sorted(CWE_ORACLE)

OWASP = ["A01 Broken Access Control", "A02 Cryptographic Failures", "A03 Injection", "A04 Insecure Design", "A05 Security Misconfiguration",
         "A06 Vulnerable and Outdated Components", "A07 Identification and Authentication Failures", "A08 Software and Data Integrity Failures",
         "A09 Security Logging and Monitoring Failures", "A10 Server-Side Request Forgery", "MEM Memory safety (outside OWASP Top 10)"]


# ---- CWE -> OWASP Top 10:2021 (fixed; sourced from OWASP's official 2021 "List of Mapped CWEs" pages, fetched 2026-11-15 and verified, not from memory).
# Only CWEs that appear in a 2021 list are mapped; every other allowed CWE (memory, integer, leak, race, resource, 134, 253, 628, 843, ...) is "outside Top 10".
OWASP_OUTSIDE = "MEM Memory safety (outside OWASP Top 10)"
CWE_OWASP = {
    22: "A01 Broken Access Control",
    78: "A03 Injection", 89: "A03 Injection",
    327: "A02 Cryptographic Failures",
    522: "A04 Insecure Design",
    798: "A07 Identification and Authentication Failures",
}
OWASP_SOURCES = {
    "A01 Broken Access Control": "https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/",
    "A02 Cryptographic Failures": "https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/",
    "A03 Injection": "https://owasp.org/Top10/2021/A03_2021-Injection/",
    "A04 Insecure Design": "https://owasp.org/Top10/2021/A04_2021-Insecure_Design/",
    "A05 Security Misconfiguration": "https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/",
    "A06 Vulnerable and Outdated Components": "https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07 Identification and Authentication Failures": "https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/",
    "A08 Software and Data Integrity Failures": "https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09 Security Logging and Monitoring Failures": "https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10 Server-Side Request Forgery": "https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}
# Known label-set limitation: the schema has no generic "other" label, so OWASP_OUTSIDE (the memory-safety label) is the label that counts as correct for every CWE outside the Top 10.


def owasp_expected(cwe):
    return CWE_OWASP.get(cwe, OWASP_OUTSIDE)
