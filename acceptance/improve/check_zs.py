"""Acceptance for the Phase-1 zero-shot probe (scripts/imp_zs_probe.py). Written first; run from the repo root (plain python3, no GPU).
  check_zs.py selftest        spins up a FAKE Ollama server, runs the probe on 40 matched cases and requires:
       Z1 n == len(per_case) == 40, no case dropped; Z2 an unparseable reply is scored 0.5 and COUNTED (parse_rate < 1), never dropped;
       Z3 AUROC recomputed independently from per_case equals the stored one (1e-3); Z4 an oracle server (answers by the true label) gives AUROC 1.0 and an anti-oracle 0.0
       (so the scorer can fail); Z5 truncated/error replies are counted in truncated_or_error
  check_zs.py results FILE    structure + recomputation of a real result file (n == len(per_case) == len(cases file), AUROC recomputed, parse_rate recomputed)"""
import http.server, json, os, subprocess, sys, threading

sys.path.insert(0, "scripts")


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    return sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in P for b in N) / (len(P) * len(N))


def verify(path, cases_file, want_n=None):
    d = json.load(open(path)); fails = []
    cases = json.load(open(cases_file))["cases"]
    pc = d["per_case"]
    if want_n is None:
        want_n = len(cases)
    if d["n"] != len(pc) or len(pc) != want_n:
        fails.append(f"n {d['n']} / per_case {len(pc)} / expected {want_n}")
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
    a = auroc([p["p_vuln"] for p in pc], y)
    if abs(a - d["auroc"]) > 1e-3:
        fails.append(f"auroc stored {d['auroc']} recomputed {a:.4f}")
    if abs(sum(p["parsed"] for p in pc) / len(pc) - d["parse_rate"]) > 1e-3:
        fails.append("parse_rate inconsistent")
    if any((not p["parsed"]) and p["p_vuln"] != 0.5 for p in pc):
        fails.append("an unparsed reply was not scored 0.5")
    return fails, a


class Fake(http.server.BaseHTTPRequestHandler):
    mode = "oracle"
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        user = body["messages"][-1]["content"] if body["messages"] else ""
        idx = sum(map(ord, user)) % 10
        if Fake.mode == "garbage" and idx < 3:
            content, reason = "I think maybe", "stop"
        elif Fake.mode == "trunc" and idx < 2:
            content, reason = "", "length"
        else:
            vuln = "MAGICVULN" in user
            if Fake.mode == "anti":
                vuln = not vuln
            content, reason = f"VERDICT: {'VULNERABLE' if vuln else 'SAFE'}\nCONFIDENCE: 0.9", "stop"
        out = json.dumps({"message": {"content": content, "thinking": "t"}, "eval_count": 7, "done_reason": reason, "total_duration": 1000000000}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(out)


def selftest():
    cases = json.load(open("results/lenmatched_eval_cases.json"))["cases"][:40]
    for c in cases:
        if c["label"] == "VULNERABLE":
            c["code"] = c["code"] + "\n// MAGICVULN"
    json.dump({"cases": cases, "pool": {}}, open("/tmp/imp_zs_cases.json", "w"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    fails = []
    for mode, want in (("oracle", 1.0), ("anti", 0.0), ("garbage", None), ("trunc", None)):
        Fake.mode = mode
        out = f"/tmp/imp_zs_{mode}.json"
        for f in (out, out + ".cache.jsonl"):
            if os.path.exists(f):
                os.remove(f)
        subprocess.run([sys.executable, "scripts/imp_zs_probe.py", "--model", "fake", "--tag", mode, "--cases-file", "/tmp/imp_zs_cases.json", "--out", out, "--url", url, "--workers", "2"],
                       capture_output=True, text=True, timeout=300)
        f, a = verify(out, "/tmp/imp_zs_cases.json", 40)
        fails += [f"{mode}: {x}" for x in f]
        d = json.load(open(out))
        if want is not None and abs(d["auroc"] - want) > 1e-6:
            fails.append(f"{mode}: auroc {d['auroc']} expected {want}")
        if mode == "garbage" and not d["parse_rate"] < 1:
            fails.append("garbage: parse_rate not < 1")
        if mode == "trunc" and not d["truncated_or_error"] > 0:
            fails.append("trunc: truncation not counted")
    if fails:
        print("FAIL:"); [print(" -", x) for x in fails]; return 1
    print("PASS: probe controls Z1-Z5"); return 0


if __name__ == "__main__":
    if sys.argv[1] == "selftest":
        sys.exit(selftest())
    f, a = verify(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "results/lenmatched_eval_cases.json")
    if f:
        print("FAIL:"); [print(" -", x) for x in f]; sys.exit(1)
    print("PASS: %s auroc=%.4f" % (sys.argv[2], a))
