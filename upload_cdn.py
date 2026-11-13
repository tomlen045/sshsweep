#!/usr/bin/env python3
"""上传 shots 到 GitHub + 生成 gcore jsDelivr SHA 锚定图床链接 + 逐张 md5 验证。"""
import base64
import hashlib
import json
import subprocess
import sys
import time
import urllib.request

TOKEN = subprocess.run(["security", "find-generic-password", "-s", "GH_TOKEN", "-w"],
                       capture_output=True, text=True).stdout.strip()
REPO = "tomlen045/sshsweep"
CWD = "/Users/len/CodeBuddy/dx/sshsweep"


def gh(method, path, body=None, tries=4):
    for i in range(tries):
        req = urllib.request.Request("https://api.github.com" + path,
            data=json.dumps(body).encode() if body else None, method=method,
            headers={"Authorization": "Bearer " + TOKEN,
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "sshsweep-cdn"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except Exception:
                return e.code, {}
        except Exception as e:
            print("net retry %d: %s" % (i + 1, type(e).__name__))
            time.sleep(3 * (i + 1))
    return 0, {}


def push_file(local, remote_path, msg):
    content = base64.b64encode(open(local, "rb").read()).decode()
    # 已存在则先取 sha
    st, old = gh("GET", "/repos/%s/contents/%s" % (REPO, remote_path))
    body = {"message": msg, "content": content, "branch": "main"}
    if st == 200 and isinstance(old, dict) and old.get("sha"):
        body["sha"] = old["sha"]
    st, resp = gh("PUT", "/repos/%s/contents/%s" % (REPO, remote_path), body)
    return st, (resp.get("commit", {}) or {}).get("sha", "")


commit_shas = []
shots = ["01_inventory", "02_sweep", "03_drift", "04_suite", "05_selftest"]
for s in shots:
    st, csha = push_file("shots/%s.png" % s, "shots/%s.png" % s,
                         "docs: add %s terminal shot" % s)
    print("upload %s: %s commit=%s" % (s, st, csha[:10]))
    if st not in (200, 201):
        print("UPLOAD FAILED")
        sys.exit(1)
    commit_shas.append(csha)

# HEAD commit (五张图分五个 commit, 取最后)
HEAD = commit_shas[-1]
print("HEAD:", HEAD[:12])

# gcore SHA 锚定 URL 逐张验证: 200 + image/png + md5 一致
report = {}
for s, csha in zip(shots, commit_shas):
    url = "https://gcore.jsdelivr.net/gh/%s@%s/shots/%s.png" % (REPO, csha, s)
    local_md5 = hashlib.md5(open("shots/%s.png" % s, "rb").read()).hexdigest()
    good = False
    for i in range(5):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
                ct = r.headers.get("Content-Type", "")
                cd_md5 = hashlib.md5(data).hexdigest()
                if r.status == 200 and "image/png" in ct and cd_md5 == local_md5:
                    good = True
                    break
                print("  retry %s: status=%s ct=%s md5 %s vs %s" % (i + 1, r.status, ct, cd_md5[:8], local_md5[:8]))
        except Exception as e:
            print("  retry %s: %s" % (i + 1, type(e).__name__))
            time.sleep(5 * (i + 1))
    report[s] = {"url": url, "ok": good, "md5": local_md5}
    print("%s: %s" % (s, "OK" if good else "FAIL"))

json.dump(report, open("cdn_check.json", "w"), indent=2, ensure_ascii=False)
all_ok = all(v["ok"] for v in report.values())
print("CDN-ALL-OK" if all_ok else "CDN-SOME-FAILED")
sys.exit(0 if all_ok else 2)
