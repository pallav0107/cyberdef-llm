"""cyberdef-llm: defensive-security LLM pipeline (blue-team only).

Capabilities (modular; vuln_detect implemented end-to-end first):
  - vuln_detect   : classify a code snippet VULNERABLE/SAFE (+CWE)   [IMPLEMENTED]
  - secure_code   : CyberSecEval insecure-code + attack-resistance   [module stub]
  - soc_triage    : CTIBench / SECURE incident+threat triage         [module stub]
  - robustness    : prompt-injection / jailbreak resistance          [module stub]
"""
__version__ = "0.1.0"
