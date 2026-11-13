"""Resilient, resumable download of Qwen2.5-32B-Instruct (Apache-2.0, ungated) into the HF
cache. Run inside the Spark training container with the HF cache mounted. Xet disabled by
the launcher; classic HTTP resumes across the flaky uplink."""
import time, sys
from huggingface_hub import snapshot_download

MID = "Qwen/Qwen2.5-32B-Instruct"
PATS = ["*.json", "*.safetensors", "tokenizer*", "merges*", "vocab*", "*.txt", "*.model"]
last = None
for a in range(60):
    try:
        p = snapshot_download(MID, allow_patterns=PATS, max_workers=1)
        print("DOWNLOAD_OK", p, flush=True)
        break
    except Exception as e:  # noqa
        last = repr(e)[:140]
        print(f"retry {a} failed: {last}", flush=True)
        time.sleep(15)
else:
    raise SystemExit(f"32B download failed after retries: {last}")
