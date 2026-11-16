"""Synthetic SQLi pool, STEP 1 (Spark, vLLM, open-weight model ONLY): the model writes sqlite3 C programs, each as a VULNERABLE program and a SAFE twin, from 20 scenarios x N samples.
Output results/imp_sqli_raw.json (raw model text + parsed code blocks). Verification and dedupe happen on the box (scripts/imp_build_sqli.py).
  python3 scripts/imp_sqli_gen.py --model Qwen/Qwen2.5-14B-Instruct --n 20 --out results/imp_sqli_raw.json
Never use a commercial API; the generator model name is recorded in the output."""
import argparse, json, re, sys, time
sys.path.insert(0, "src")
import cyberdef  # noqa: E402,F401  (chat default: no thinking)

SCENARIOS = [
    "user login: look up a user by username (the input line) and print the stored role",
    "product search: find products whose name equals the input line",
    "order lookup by customer name given on the input line",
    "delete a record from a notes table whose title equals the input line",
    "update the email of the user whose username is the input line",
    "insert a comment whose text is the input line into a comments table",
    "look up an employee by numeric id read as text from the input line (id is an integer column)",
    "LIKE search: find books whose title contains the input line",
    "login check: username and password are both taken from the input line separated by a space",
    "filter products by category given on the input line and price below 100",
    "count the rows in the sessions table for the token on the input line",
    "fetch an account balance for the account name on the input line",
    "list messages sent to the recipient on the input line, newest first",
    "find a customer by email address on the input line",
    "look up a city by name on the input line in a cities table",
    "delete the session whose token is the input line",
    "select a student's grade by student name on the input line",
    "retrieve a document by title on the input line from a documents table",
    "check whether a coupon code on the input line exists",
    "find the author of a post whose slug is the input line",
]
SYSTEM = ("You are a C developer writing small test programs for a security training corpus. Reply with EXACTLY two C source files, each in its own fenced block, in this order: "
          "first a block starting with the line '### VULNERABLE' then a ```c block, then a line '### SAFE' and a ```c block. Rules for BOTH programs: self-contained, compile with gcc -lsqlite3, "
          "#include <sqlite3.h>, int main(void), open sqlite3_open(\":memory:\"), create the needed table and insert two sample rows with sqlite3_exec, then read EXACTLY ONE line of input with fgets from stdin "
          "into a char buffer of at most 200 bytes (strip the newline), build and run ONE query for the scenario, print results from a callback, close the database. No argv, no files, no network. "
          "The VULNERABLE program must build the query by string concatenation or snprintf/sqlite3_mprintf(\"%s\") of the raw input line into the SQL text (a classic SQL injection). "
          "The SAFE twin must be functionally the same but safe: use sqlite3_prepare_v2 with a ? placeholder and sqlite3_bind_text, OR escape every single quote by doubling it before building the SQL. "
          "Both programs must be complete, different only where needed for the fix. No explanations.")


def parse(text):
    m = re.search(r"###\s*VULNERABLE.*?```(?:c|C)?\n(.*?)```.*?###\s*SAFE.*?```(?:c|C)?\n(.*?)```", text, re.S)
    return (m.group(1).strip(), m.group(2).strip()) if m else (None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--out", required=True)
    ap.add_argument("--gpu-util", type=float, default=0.6)
    ap.add_argument("--max-tokens", type=int, default=2200)
    a = ap.parse_args()
    assert "claude" not in a.model.lower() and "gpt-4" not in a.model.lower()
    import vllm
    from vllm import LLM, SamplingParams
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(a.model)
    prompts, meta = [], []
    for si, sc in enumerate(SCENARIOS):
        for k in range(a.n):
            prompts.append(tok.apply_chat_template([{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Scenario: {sc}. Variation seed {k}: use different table and column names and a different code style than other variations."}],
                                                   add_generation_prompt=True, tokenize=False))
            meta.append((si, k))
    llm = LLM(a.model, dtype="bfloat16", max_model_len=8192, gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0)
    t0 = time.time()
    outs = llm.generate(prompts, SamplingParams(temperature=0.8, top_p=0.95, max_tokens=a.max_tokens, seed=0))
    rows = []
    for (si, k), o in zip(meta, outs):
        v, s = parse(o.outputs[0].text)
        rows.append({"scenario": si, "sample": k, "vulnerable": v, "safe": s, "finish": o.outputs[0].finish_reason, "raw_head": o.outputs[0].text[:200]})
    json.dump({"generator": a.model, "engine": f"vllm {vllm.__version__} bf16", "temperature": 0.8, "top_p": 0.95, "max_tokens": a.max_tokens, "seconds": round(time.time() - t0),
               "label": "synthetic, open-weight generated, oracle-verified (verification pending)", "n_prompts": len(rows), "n_parsed": sum(1 for r in rows if r["vulnerable"] and r["safe"]), "rows": rows}, open(a.out, "w"))
    print(json.dumps({"prompts": len(rows), "parsed": sum(1 for r in rows if r["vulnerable"] and r["safe"])}))


if __name__ == "__main__":
    main()
