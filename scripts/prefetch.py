"""Robust, resumable model prefetch. Xet is disabled by the caller (HF_HUB_DISABLE_XET=1)
because it errors on this box's network; classic HTTP resumes partial files across retries."""
import sys, time
from huggingface_hub import snapshot_download

mid = sys.argv[1]
pats = ["*.json", "*.safetensors", "tokenizer*", "vocab*", "merges*", "*.model", "*.txt"]
last = None
for a in range(10):
    try:
        p = snapshot_download(mid, allow_patterns=pats, max_workers=2)
        print("DOWNLOAD_OK", p)
        break
    except Exception as e:  # noqa
        last = repr(e)[:180]
        print(f"prefetch attempt {a} failed: {last}", flush=True)
        time.sleep(15)
else:
    raise SystemExit(f"prefetch failed after retries: {last}")
