"""Idempotent completion edits to MODEL_CARD.md static sections (never touches the
auto-generated <!-- BEGIN_RESULTS -->..<!-- END_RESULTS --> block, which make_results_table
owns). Updates the stale DRAFT banner now that the recognized-benchmark gate is met, names
the released champion adapter, and adds the PrimeVul increment to Training data."""
import pathlib, sys

p = pathlib.Path("MODEL_CARD.md")
s = p.read_text(encoding="utf-8")
orig = s

OLD_BANNER = """> **Status: DRAFT — not published.** Publish only once the recognized-benchmark
> delta (below) is positive and reproducible. The current synthetic-trained adapter
> does **not** beat the base model on the recognized benchmark and must not be
> presented as a contribution."""
NEW_BANNER = """> **Status: READY TO PUBLISH — pending author action (not yet published).** The gate
> this card set — a positive, reproducible delta on recognized public benchmarks — is now
> **met and verified**: the PrimeVul-trained 7B adapter leads an in-class leaderboard
> (AUROC 0.786 vs base 0.658) and its edge transfers to an unseen dataset (DiverseVul) across
> four seeds with non-overlapping ranges. What remains is **not technical** — the model must be
> published under the author's own account and version control, and the evidentiary value comes
> from external adoption/recognition rather than from the build. The earlier synthetic-trained
> adapter did **not** beat base on a recognized benchmark and is kept below only as an honesty trail."""

if OLD_BANNER in s:
    s = s.replace(OLD_BANNER, NEW_BANNER)
    print("banner: updated")
elif NEW_BANNER.split("\n", 1)[0] in s:
    print("banner: already updated (skip)")
else:
    print("banner: NOT FOUND - aborting", file=sys.stderr); sys.exit(2)

OLD_ADAPTER = "- **Adapter type:** LoRA (r=16, α=32) trained with 4-bit QLoRA (nf4)\n"
ADAPTER_ADD = ("- **Released adapter:** `out/qlora-primevul` (7B, PrimeVul-trained) — the "
               "champion; sibling adapters `out/qlora-devign` (7B) and `out/qlora-1.5b`, "
               "`out/qlora-14b` (scaling) are included for the comparisons below.\n")
if OLD_ADAPTER in s and "Released adapter:" not in s:
    s = s.replace(OLD_ADAPTER, OLD_ADAPTER + ADAPTER_ADD)
    print("released-adapter line: added")
else:
    print("released-adapter line: present or anchor missing (skip)")

INC3 = ("- **Increment 3 (real, the released champion):** the **PrimeVul** dataset "
        "(`colin/PrimeVul`; curated, lower-noise vulnerability labels). Trained on the TRAIN "
        "split only, leakage-deduped against the 48,736 validation/test functions. This is the "
        "adapter (`out/qlora-primevul`) behind the headline leaderboard result; the same recipe "
        "was also applied at 1.5B and 14B for the scaling table. No model-generated or "
        "commercial-API outputs were used as training data at any size.\n")
# insert right before the "## Evaluation & results" heading
ANCHOR = "\n## Evaluation & results"
if "Increment 3 (real" not in s and ANCHOR in s:
    s = s.replace(ANCHOR, "\n" + INC3 + ANCHOR, 1)
    print("increment 3: added")
else:
    print("increment 3: present or anchor missing (skip)")

if s != orig:
    p.write_text(s, encoding="utf-8")
    print("MODEL_CARD.md written")
else:
    print("no change")
