"""Resilient, resumable, token-authenticated download of Qwen2.5-14B-Instruct (Apache-2.0)
into the box HF cache. Resumes from whatever shards are already present. Run on the box over
ac1; classic HTTP resumes across a flaky uplink."""
import time, sys
from huggingface_hub import snapshot_download

MID = "Qwen/Qwen2.5-14B-Instruct"
PATS = ["*.json", "*.safetensors", "tokenizer*", "merges*", "vocab*", "*.txt", "*.model"]
last = None
for a in range(80):
    try:
        p = snapshot_download(MID, allow_patterns=PATS, max_workers=3)
        print("DOWNLOAD_OK", p, flush=True)
        break
    except Exception as e:  # noqa
        last = repr(e)[:160]
        print(f"retry {a} failed: {last}", flush=True)
        time.sleep(12)
else:
    raise SystemExit(f"14B download failed after retries: {last}")
