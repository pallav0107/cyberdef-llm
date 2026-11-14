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

## Amendment 2 (14 Nov 2026, before function extraction or any labels): tightening
1. Coverage: no time budget — every eligible CVE in the window is processed; the final size and
   per-language counts are reported with confidence intervals; no size claim is made.
2. Labels: the precise rules of Amendment 1 apply (one-function commits or functions named in the
   CVE/advisory); everything else goes to the separate "uncertain" split.
3. Label validation: the author reviews 200 MAIN-set vulnerable functions, stratified by language
   (fixed seed 0). Two independent open-weight models from different families (excluding the
   models under evaluation and their base, Qwen2.5-7B) judge the same 200 functions as a clearly
   labelled SECONDARY signal; agreement between the author and each model, and between the
   models, is reported. The headline label-precision estimate comes from the human review only,
   with a Wilson 95% confidence interval.
4. Sampling bias is measured: the dataset's distribution by CWE, language and ecosystem is compared
   with ALL CVEs published in the same window (including excluded ones), and the comparison is
   reported.
5. Contamination: the claim is that every CVE was DISCLOSED after 2024-10-01. In addition, a
   "code-unseen" subset is identified — vulnerable functions whose file did not exist, or whose
   function first appeared, after 2024-10-01 according to repository history — and reported
   separately. No claim is made that the remaining code was unseen.
6. Reproducibility: a content hash is published for every function (metadata and code-free rows
   alike) so a rebuilt copy can be verified identical; results are reported on the full evaluated
   set and on the publicly redistributable subset.
7. Splits: project and month metadata are released with recommended project-based and time-based
   splits for users who want them; this study uses the set for testing only.
8. Deduplication is extended to BigVul, CrossVul, MegaVul, ReposVul, CleanVul and SVEN where they
   can be obtained within the download limit (CVEfixes, 12.7 GB, is excluded and stated), and
   near-duplicates are removed with MinHash (threshold fixed before running) using the leakcheck
   tool, in addition to exact matching. Removed counts are reported per source.
