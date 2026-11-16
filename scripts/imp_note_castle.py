import json
json.dump({"id": "CASTLE-674-10.c", "label_in_castle": "SAFE", "status": "SUSPECTED CASTLE LABEL ERROR (kept as labelled in all metrics; reported separately)",
 "evidence": "main() reads n; for n>0 it prints fibonacci(i) for i = 0..n-1; fibonacci(0) calls fibonacci(-1), fibonacci(-2), ... with no base case for n<=0 => unbounded recursion (CWE-674).",
 "execution": "AFL++ (imp-castle-san, ASan) found an ASan stack-overflow crash after ~450 ms from an empty/newline seed; replay in the sandbox confirmed (results/imp_2_fuzz_empty_b60.json run3, kept in results/imp_superseded/).",
 "treatment": "left in the data; sensitivity AUROC without it is in results/imp_2_summary.json (sensitivity_without_CASTLE-674-10)"},
 open("results/imp_castle_label_note.json", "w"), indent=1)
