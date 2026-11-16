"""Appends the three oracle false-positive investigations to results/imp_castle_label_note.json (no label or oracle is changed)."""
import json

old = json.load(open("results/imp_castle_label_note.json"))
notes = [old] if "id" in old else old["notes"]
notes = [n for n in notes if n["id"] not in ("CASTLE-362-10.c", "CASTLE-787-9.c", "CASTLE-770-7.c")]
notes += [
    {"id": "CASTLE-362-10.c", "label_in_castle": "SAFE", "oracle_report": "ThreadSanitizer: data race (variant C, floor arm, empty input)",
     "classification": "SUSPECTED CASTLE LABEL ERROR (a real race in a program labelled SAFE)",
     "evidence": "main passes &t (the address of its own loop variable) to each thread; the thread dereferences it (line 11: sprintf(..., *t)) while main concurrently executes t++ (line 32). "
                 "Re-run under TSan (seccomp=unconfined container): Write of size 8 by main thread at c362-10.c:32, previous read of size 8 by thread T1 at c362-10.c:11, location is the stack of the main thread. "
                 "This is the classic pass-the-address-of-the-loop-variable race (it also makes the printed thread id a pointer value).",
     "treatment": "labels and oracle unchanged; counted as a false positive in the spec tables and reported here as probably a true positive on a mislabelled program"},
    {"id": "CASTLE-787-9.c", "label_in_castle": "SAFE", "oracle_report": "cpu_hang (variant A, empty input: timeout >= 3 s with >= 2 s CPU)",
     "classification": "ORACLE FALSE POSITIVE with respect to the label (CWE-787 safe), but a real unrelated defect: unbounded spin on EOF",
     "evidence": "main() loops do { prompt; scanf(\"%9d\", &length); ... } while (length < 8 || length > 16) and never checks the return value of scanf. With empty stdin (EOF) scanf fails, "
                 "length stays uninitialised and out of range, and the loop spins forever printing prompts: a re-run measured about 3.3 GB of output in 3 s. With valid input (12) it terminates and prints a password. "
                 "The buffer handling (password[MAX_LENGTH+1], length <= 16) is correct, so there is no CWE-787.",
     "treatment": "unchanged; the cpu_hang oracle cannot tell an EOF-induced spin from the intended class. Not tuned."},
    {"id": "CASTLE-770-7.c", "label_in_castle": "SAFE", "oracle_report": "cpu_hang (variant A, empty input)",
     "classification": "ORACLE FALSE POSITIVE with respect to the label (CWE-770 safe: the program caps the buffer at MAX_BUFFER_SIZE), but a real unrelated defect: unbounded spin on EOF",
     "evidence": "the getchar loop treats EOF like a newline (c == newline || read_val == EOF): it prints 'You entered:' and prompts again, and only breaks on the literal line 'exit' or the size cap, "
                 "so at EOF it loops forever (re-run: about 3.3 GB of output in 3 s). With 'exit' input it exits normally.",
     "treatment": "unchanged; same mechanism as 787-9."},
]
json.dump({"notes": notes,
           "summary": "3 false positives on SAFE programs under the oracle-spec floor arm: 1 suspected CASTLE label error (362-10, genuine TSan race) and 2 oracle false positives caused by programs that spin forever "
                      "when stdin is at EOF (787-9, 770-7). Both cpu_hang cases would disappear if the hang oracle required the spin to persist on a NON-EOF input; that is NOT applied (no tuning after seeing "
                      "results) and is only a suggestion for a future pre-registered revision.",
           "data_policy": "no label and no oracle was changed; all three stay in every metric as labelled"}, open("results/imp_castle_label_note.json", "w"), indent=1)
print(len(notes), "notes")
