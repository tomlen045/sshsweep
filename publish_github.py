#!/usr/bin/env python3
"""GitHub 建仓 + push + 匿名复核（sshsweep）。token 从钥匙串 GH_TOKEN 读。
照 cronproof/publish_github.py；push 带 HTTP/1.1 + 退避重试（GitHub 网络抖动）。"""
import json
import subprocess
import sys
import time
import urllib.request

TOKEN = subprocess.run(["security", "find-generic-password", "-s", "GH_TOKEN", "-w"],
                       capture_output=True, text=True).stdout.strip()
if not TOKEN:
    print("NO_GH_TOKEN")
    sys.exit(1)
REPO = "sshsweep"
CWD = "/Users/len/CodeBuddy/dx/sshsweep"


def gh(method, path, body=None, tries=4):
    for i in range(tries):
        req = urllib.request.Request("https://api.github.com" + path,
            data=json.dumps(body).encode() if body else None, method=method,
            headers={"Authorization": "Bearer " + TOKEN,
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "sshsweep-publish"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except Exception:
                return e.code, {}
        except Exception as e:
            print("api net retry %d: %s" % (i + 1, type(e).__name__))
            time.sleep(3 * (i + 1))
    return 0, {}


code, resp = gh("POST", "/user/repos", {
    "name": REPO,
    "description": "sshsweep - SSH fleet liveness sweep in one file: TCP+RFC4253 banner "
                   "probe, OK/STALE/MISMATCH/DEAD verdicts, baseline drift events "
                   "(HOST_GONE/VERSION_DRIFT/NEW_HOST...), ssh_config inventory expansion, "
                   "28-check selftest (SW-01..14). Zero dependencies, read-only by design.",
    "private": False})
print("create:", code, resp.get("full_name", str(resp)[:160]) if code in (201, 202) else str(resp)[:160])
if code not in (201, 202) and "already exists" not in str(resp):
    sys.exit(1)

subprocess.run(["git", "remote", "remove", "github"], capture_output=True, cwd=CWD)
subprocess.run(["git", "remote", "add", "github",
                "https://tomlen045:%s@github.com/tomlen045/%s.git" % (TOKEN, REPO)], cwd=CWD)

LOCAL = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=CWD).stdout.strip()
ok = False
for i in range(8):
    p = subprocess.run(["git", "-c", "http.version=HTTP/1.1", "push", "-u", "github", "main"],
                       capture_output=True, text=True, cwd=CWD,
                       env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
    print("push round %d rc=%d %s" % (i + 1, p.returncode, ((p.stdout + p.stderr).strip().splitlines() or [""])[-1][:120]))
    if p.returncode == 0:
        time.sleep(4)
        # 远端哈希验证（rev-parse 本地 ref 判 push 成功是错的，必须 ls-remote）
        q = subprocess.run(["git", "ls-remote", "github", "refs/heads/main"],
                           capture_output=True, text=True, cwd=CWD)
        remote = q.stdout.strip().split()[0] if q.stdout.strip() else ""
        print("remote=%s local=%s" % (remote[:12], LOCAL[:12]))
        if remote == LOCAL:
            ok = True
            break
    time.sleep(8 * (i + 1))
if not ok:
    print("NOT_SYNCED")
    sys.exit(2)

# 匿名复核: raw 直读 README @main
try:
    with urllib.request.urlopen(
            "https://raw.githubusercontent.com/tomlen045/%s/main/README.md" % REPO, timeout=15) as r:
        body = r.read()
    good = r.status == 200 and b"sshsweep" in body
    print("anon raw README:", r.status, len(body), "bytes")
except Exception as e:
    print("anon verify FAIL:", e)
    good = False
print("GITHUB_OK https://github.com/tomlen045/%s" % REPO if good else "GITHUB_VERIFY_FAILED")
sys.exit(0 if good else 3)
