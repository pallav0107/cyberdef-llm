# Pre-registered plan: a new dataset of recent real CVEs (written 14 Nov 2026, before collection)

Purpose: a contamination-resistant, TEST-ONLY benchmark of real vulnerabilities disclosed after the
base model's release (Qwen2.5, September 2024), so no model in this study could have seen the fixes.

## Collection rules (fixed now)
- Sources: public CVE records — NVD (US government, public domain) and the GitHub Advisory Database
  / OSV (CC BY 4.0) — for CVEs PUBLISHED from 2024-10-01 up to the collection date.
- Include a CVE only if its record links a specific fixing commit in a public GitHub repository, and
  the commit modifies source files in C, C++, Java, Python, JavaScript or TypeScript.
- Every eligible CVE is processed in a fixed order (by CVE id); none are hand-picked. Exclusions are
  rule-based and counted: no fix-commit link, repository unavailable, commit touching more than 10
  functions or more than 300 changed lines (to limit label noise), non-source changes only.
- Vulnerable label: the pre-fix version of each function the fixing commit changes. Safe label:
  functions in the same files that the commit does not change. Post-fix versions are recorded but not
  used as "safe" examples (they are near-duplicates of the vulnerable ones).
- De-duplicated (normalised exact match) against PrimeVul, DiverseVul, Devign, ReVeal, D2A, CASTLE and
  the multi-language training data; removed counts reported.
- Label quality: a random sample of 100 vulnerable functions (fixed seed) is reviewed by a human
  (the author) and agreement reported; any AI-assisted pre-screening is disclosed as such.

## Release
- Metadata (CVE id, CWE, CVSS, repository, commit, file, function, label) under CC BY 4.0 with
  attribution to NVD and the GitHub Advisory Database. Code is NOT redistributed for projects with
  restrictive licences; a rebuild script fetches it from the original repositories. Permissively
  licensed code may be included with its licence notice.
- Used only as a test set in this study (never for training or tuning). Results are reported for every
  model scored, whatever they show.

## Amendment (14 Nov 2026, before function extraction or any labels): precise labels
Published audits (summarised in the PrimeVul paper) found that labelling EVERY function changed by a
fixing commit as vulnerable is only about 25-60% accurate. The main test set therefore uses
PrimeVul-style precise rules. A pre-fix function is labelled VULNERABLE only if
(a) the fixing commit changes exactly one function in source files, OR
(b) the function's name appears in the CVE description or the GitHub advisory text.
Functions changed by the fix that meet neither rule go to a separate "uncertain" split (reported,
never mixed into the main test set). Safe examples are unchanged functions from the same files.
The 100-function human review samples the main (precise) set. Counts for both splits are reported.
