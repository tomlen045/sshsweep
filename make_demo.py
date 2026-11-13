#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sshsweep 真机演示: 本机真实 socket SSH-风味舰队 (输出 100% 真实可复跑)。

起 5 个真实 TCP 监听:
  web-1    SSH-2.0-OpenSSH_9.6   (健康)
  web-2    SSH-2.0-OpenSSH_8.9   (健康)
  db-1     SSH-2.0-OpenSSH_7.4   (STALE: 2017 年版本, 三年没升级)
  db-2     HTTP/1.1 400 ...      (MISMATCH: 端口后面挂的是个 HTTP 服务, 运维改错口)
  oldapp   (无监听)              (DEAD: 已下线但没人摘清单)
另: web-2 的多别名合并 (web-2 / web-2-alias 指向同址)。

流程 = 文章狗粮线:
  1. fleet.inv + sweep --baseline      (首巡, 定基线)
  2. 突变: db-1 降级 7.2, oldapp 复活 (模拟「有人动了 fleet 没留痕」)
  3. sweep --compare                   (漂移水落石出)
"""
import json
import subprocess
import sys
import threading
import time
import socket

DEMO = "/Users/len/CodeBuddy/dx/sshsweep/demo"
PY = sys.executable


def listener(banner):
    """每次调用独立 state 字典——默认参数共享字典会让多个监听互相覆盖 banner。"""
    state = {"on": True, "banner": banner}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]

    def serve():
        srv.settimeout(0.2)
        while state["on"]:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            b = state.get("banner", banner)
            try:
                conn.sendall((b + "\r\n").encode())
                time.sleep(0.05)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port, state


def run(cmd, **kw):
    print("$ %s" % " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stdout.write("[stderr] " + r.stderr)
    print("exit=%d" % r.returncode)
    return r


def main():
    import os
    os.makedirs(DEMO, exist_ok=True)

    # ── 舰队 v1: db-1=7.4 stale / db-2=HTTP mismatch / oldapp 死 / web-1、web-2 活
    p_web1, s_web1 = listener("SSH-2.0-OpenSSH_9.6")
    p_web2, s_web2 = listener("SSH-2.0-OpenSSH_8.9")
    p_db1, s_db1 = listener("SSH-2.0-OpenSSH_7.4")
    p_db2, s_db2 = listener("HTTP/1.1 400 Bad Request")
    dead_port = 1  # 127.0.0.1:1 无监听
    stoppers = [s_web1, s_web2, s_db1, s_db2]

    inv = os.path.join(DEMO, "fleet.inv")
    with open(inv, "w", encoding="utf-8") as f:
        f.write("# 本机演示舰队 (127.0.0.1, 端口动态)\n")
        f.write("web-1=127.0.0.1:%d\n" % p_web1)
        f.write("web-2=127.0.0.1:%d\n" % p_web2)
        f.write("web-2-alias=127.0.0.1:%d\n" % p_web2)
        f.write("db-1=127.0.0.1:%d\n" % p_db1)
        f.write("db-2=127.0.0.1:%d\n" % p_db2)
        f.write("oldapp=127.0.0.1:%d\n" % dead_port)
    print("fleet.inv:\n%s" % open(inv).read())

    bl = os.path.join(DEMO, "baseline.json")
    js = os.path.join(DEMO, "sweep1.json")

    # 1. 首巡 + 定基线
    run([PY, "sshsweep.py", "sweep", "--inv", inv, "--baseline", bl, "--json", js])
    doc1 = json.load(open(js))
    assert doc1["results"], "no results"

    # 2. 突变: db-1 网管降级到 7.2; oldapp 重新上线(2.0/6.6)
    time.sleep(0.3)
    s_db1["banner"] = "SSH-2.0-OpenSSH_7.2"
    p_old, s_old = listener("SSH-2.0-OpenSSH_6.6")
    stoppers.append(s_old)

    inv2 = inv + ".mutated"
    with open(inv2, "w", encoding="utf-8") as f:
        f.write("# 突变后的清单: oldapp 复活\n")
        f.write("web-1=127.0.0.1:%d\n" % p_web1)
        f.write("web-2=127.0.0.1:%d\n" % p_web2)
        f.write("db-1=127.0.0.1:%d\n" % p_db1)
        f.write("db-2=127.0.0.1:%d\n" % p_db2)
        f.write("oldapp=127.0.0.1:%d\n" % p_old)

    # 3. 对比巡扫 -> 漂移报告
    js2 = os.path.join(DEMO, "sweep2.json")
    r = run([PY, "sshsweep.py", "sweep", "--inv", inv2, "--compare", bl, "--json", js2])
    doc2 = json.load(open(js2))
    kinds = {e["event"] for e in doc2.get("drift", [])}
    # 剧本: 活机全部换 banner -> VERSION_DRIFT; oldapp 复活但端口是新的 -> NEW_HOST;
    # 死机 oldapp:1 移出清单 -> TARGET_REMOVED (HOST_REVIVED 语义已由 selftest SW-13 覆盖)
    need = {"VERSION_DRIFT", "NEW_HOST", "TARGET_REMOVED"}
    assert need <= kinds, "missing drift kinds: %s in %s" % (need, kinds)
    assert not {"HOST_GONE"} <= kinds, "unexpected HOST_GONE"

    # 4. inventory 展开 + explain 抽查
    run([PY, "sshsweep.py", "inventory", "--inv", inv])

    print("\nDEMO-OK: drift kinds = %s" % sorted(kinds))
    print("DEMO baseline=%s sweep1=%s sweep2=%s" % (bl, js, js2))


if __name__ == "__main__":
    main()
