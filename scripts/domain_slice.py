"""Domain-sliced AUROC on existing PrimeVul n=1000 selective results (no new inference).
Joins per_case ids (PrimeVul idx) to the dataset 'project' field, maps project->domain."""
import json, math, sys
sys.path.insert(0, "scripts")
from datasets import load_dataset
from length_baseline import auroc, hanley_mcneil_se

KERNEL = {"linux","linux-2.6","net","nf","ipsec","tty","bpf","wireless-drivers","v4l2loopback"}
OSPKG = {"openssl","curl","libxml2","zlib","libssh","pcre2","ncurses","bash","util-linux","tar","grep",
 "gzip","file","gnutls","libgcrypt","nettle","mbedtls","libexpat","openssh-portable","openldap","samba",
 "cifs-utils","rpm","libarchive","flatpak","u-boot","barebox","glib","libvirt","ntp","heimdal","unbound",
 "exim","rsyslog","pesign","xorg-xserver","xserver","crun","firejail","libslirp","virglrenderer",
 "spice-vd_agent","FreeRTOS-Kernel","gnupg","perl5","subversion","lua","LuaJIT"}
def dom(p): return "kernel" if p in KERNEL else "os_pkg" if p in OSPKG else "application"

ds = load_dataset("colin/PrimeVul", split="test")
meta = {str(r["idx"]): (r["project"], len(r["func"] or "")) for r in ds}
FILES = {"7b_tuned(out/qlora-primevul)":"results/n1000_sel_7b_tuned.json",
         "7b_base":"results/n1000_sel_7b_base.json",
         "7b_d2000_tuned":"results/n1000_sel_7b_d2000_tuned.json"}
MAXC = 4000
def stat(rows, key):
    y=[r["y"] for r in rows]; n1=sum(y); n0=len(y)-n1
    if n1<2 or n0<2: return dict(n=len(y),n_vuln=n1,n_safe=n0,auroc=None,se=None)
    a=auroc([r[key] for r in rows],y)
    return dict(n=len(y),n_vuln=n1,n_safe=n0,auroc=round(a,4),se=round(hanley_mcneil_se(a,n1,n0),4))
out={"mapping":{"kernel":sorted(KERNEL),"os_pkg":sorted(OSPKG),"application":"all other projects"},"models":{}}
for name,f in FILES.items():
    d=json.load(open(f)); rows=[]
    for p in d["per_case"]:
        proj,ln=meta[p["id"]]
        rows.append(dict(y=1 if p["label"]=="VULNERABLE" else 0, p=p["p_vuln"], len_full=ln,
                         len_trunc=min(ln,MAXC), proj=proj, dom=dom(proj)))
    res={"file":f,"overall":{**stat(rows,"p"),"len_full":stat(rows,"len_full")["auroc"],"len_trunc":stat(rows,"len_trunc")["auroc"]},"slices":{}}
    for dm in ("kernel","os_pkg","application"):
        sub=[r for r in rows if r["dom"]==dm]
        s=stat(sub,"p"); lf=stat(sub,"len_full"); lt=stat(sub,"len_trunc")
        s["len_auroc_full"]=lf["auroc"]; s["len_auroc_trunc"]=lt["auroc"]
        s["len_baseline_strict"]=max(x for x in (lf["auroc"],lt["auroc"]) if x is not None) if lf["auroc"] is not None else None
        s["projects"]=len({r["proj"] for r in sub}); res["slices"][dm]=s
    # extra: application excluding the 3 dominant projects (tensorflow, vim, gpac) = project-mix check
    sub=[r for r in rows if r["dom"]=="application" and r["proj"] not in ("tensorflow","vim","gpac")]
    s=stat(sub,"p"); s["len_auroc_full"]=stat(sub,"len_full")["auroc"]; res["slices"]["application_ex_tf_vim_gpac"]=s
    out["models"][name]=res
json.dump(out,open("results/domain_slice_7b.json","w"),indent=2)
for name,r in out["models"].items():
    print(name, "overall", r["overall"])
    for k,s in r["slices"].items(): print("  ",k,s)
