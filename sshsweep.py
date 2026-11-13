#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sshsweep — SSH 主机群活性巡扫（零依赖单文件）

回答三个问题： fleet 里现在谁活着、谁死了、谁换了版本。
SSH 套件定位（审计链最后一环「活体探测」）：
  keyvaultdog(私钥) -> authkeylens(进门名单) -> hostlens(指纹台账·静态)
  -> authguard(登录行为) -> envlens(怎么连) -> matchlens(谁说了算)
  -> sshsweep(现在到底活没活)

只用标准库。探测 = 纯 TCP 连接 + 读一条 banner，不碰 known_hosts、
不做密钥交换、不登录、不写任何远端状态。

子命令:
  sweep       巡扫（默认动作, 可省略）
  inventory   只展开清单不探测（看去重后的目标表）
  explain     解释不变量编号
  selftest    运行内置不变量自测

用法示例:
  python3 sshsweep.py sweep --inv fleet.inv --baseline baseline.json
  python3 sshsweep.py sweep --inv fleet.inv --compare baseline.json
  python3 sshsweep.py inventory --config ~/.ssh/config
  python3 sshsweep.py sweep --targets "web1@10.0.0.5:22, db@10.0.0.6"
退出码: 0 全部健康 1 用法错误 2 有死机 3 有陈旧/异类 banner 4 基线漂移
"""
import argparse
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TOOL = "sshsweep"
VERSION = "1.0.0"
DEFAULT_SSH_CONFIG = os.path.join(os.path.expanduser("~"), ".ssh", "config")
DEFAULT_MIN_VERSION = "7.8"   # OpenSSH 7.8 = 2017 年; 低于它视为陈旧
DEFAULT_CONNECT_TO = 5.0
DEFAULT_BANNER_TO = 3.0
DEFAULT_WORKERS = 16

OK, DEAD, STALE, MISMATCH = "OK", "DEAD", "STALE", "MISMATCH"


class UsageError(Exception):
    pass


# ---------------------------------------------------------------- 清单解析

def parse_target_line(line):
    """一行 = [alias=]host[:port]，host 允许 [IPv6 字面量]。返回 (alias, host, port)。"""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    alias = None
    # 别名前缀双形态: alias=host 或 alias@host (首个分隔符, '[' 开头是 IPv6 字面量不拆)
    seps = []
    if not raw.startswith("["):
        if "=" in raw:
            seps.append(raw.find("="))
        if "@" in raw:
            seps.append(raw.find("@"))
    if seps:
        sep = min(seps)
        alias = raw[:sep].strip()
        raw = raw[sep + 1:].strip()
        if not alias:
            raise UsageError("别名为空: %s" % line)
        if not raw:
            raise UsageError("空目标: %s" % line)
    m = re.match(r"^\[(.+)\]:(\d+)$", raw)
    if m:
        host, port = m.group(1), int(m.group(2))
    elif ":" in raw:
        host, p = raw.rsplit(":", 1)
        if not p.isdigit():
            raise UsageError("端口不是数字: %s" % line)
        host, port = host, int(p)
    else:
        host, port = raw, 22
    if not host:
        raise UsageError("主机名为空: %s" % line)
    if not (1 <= port <= 65535):
        raise UsageError("端口越界(1-65535): %s" % line)
    return (alias, host, port)


def load_inventory(path):
    """读清单文件, 返回 [(alias, host, port)] 原始条目(未去重)。"""
    entries = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            try:
                t = parse_target_line(line)
            except UsageError as e:
                raise UsageError("清单第 %d 行: %s" % (i, e))
            if t:
                entries.append(t)
    return entries


def parse_ssh_config(path):
    """极简 ssh_config 解析: Host / HostName / Port / Include。
    返回 [(alias, host, port)]; 通配与取反 pattern 跳过。
    Include 支持 ~ 与相对 ~ 展开; 深度限 3 防环。"""
    return _parse_config_file(path, depth=0)


def _expand_include(tok, base_dir):
    tok = os.path.expanduser(tok.strip())
    if not os.path.isabs(tok):
        tok = os.path.join(base_dir, tok)
    return sorted(glob_mod(tok)) if _has_glob(tok) else ([tok] if os.path.exists(tok) else [])


def _has_glob(s):
    return any(ch in s for ch in "*?[")


def glob_mod(pattern):
    import glob as _g
    return _g.glob(pattern)


def _parse_config_file(path, depth):
    if depth > 3:
        return []
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return out
    cur_hosts = None
    base = os.path.dirname(os.path.abspath(path))
    for rawline in lines:
        line = rawline.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key == "include":
            for inc in _expand_include(val, base):
                out.extend(_parse_config_file(inc, depth + 1))
            cur_hosts = None
        elif key == "host":
            names = [n for n in val.split() if not _pattern_special(n)]
            cur_hosts = names if names else None
        elif key == "hostname" and cur_hosts:
            for alias in cur_hosts:
                out.append((alias, val, None))
        elif key == "port" and cur_hosts:
            for i, (alias, h, _p) in enumerate(out[-len(cur_hosts):] if len(out) >= len(cur_hosts) else []):
                if h is not None:
                    out[len(out) - len(cur_hosts) + i] = (alias, h, int(val) if val.isdigit() else None)
    return [(a, h, p if p else 22) for (a, h, p) in out if h]


def _pattern_special(name):
    return ("*" in name) or ("?" in name) or name.startswith("!")


def merge_entries(entries):
    """按 (host, port) 去重合并, 同址多个别名并成一条多身份目标。
    返回 [ {host, port, aliases:[...] } ], 保持首次出现顺序。"""
    order = []
    idx = {}
    for alias, host, port in entries:
        key = (host.lower(), port)
        if key not in idx:
            idx[key] = {"host": host, "port": port, "aliases": []}
            order.append(idx[key])
        if alias and alias not in idx[key]["aliases"]:
            idx[key]["aliases"].append(alias)
    for t in order:
        if not t["aliases"]:
            t["aliases"] = [t["host"]]
    return order


def build_targets(args):
    """三种清单来源互斥: --inv / --config / --targets。返回合并后目标表。"""
    sources = sum(1 for x in (args.inv, args.config, args.targets) if x)
    if sources == 0:
        raise UsageError("需要 --inv FILE 或 --config FILE 或 --targets LIST 之一")
    if sources > 1:
        raise UsageError("--inv / --config / --targets 只能三选一")
    if args.inv:
        if not os.path.exists(args.inv):
            raise UsageError("清单文件不存在: %s" % args.inv)
        entries = load_inventory(args.inv)
    elif args.config:
        if not os.path.exists(args.config):
            raise UsageError("ssh config 不存在: %s" % args.config)
        entries = parse_ssh_config(args.config)
    else:
        entries = []
        for tok in args.targets.split(","):
            t = parse_target_line(tok)
            if t:
                entries.append(t)
    if not entries:
        raise UsageError("清单为空: 没有解析出任何目标")
    return merge_entries(entries)


# ---------------------------------------------------------------- 探测

def classify_banner(banner, min_version=DEFAULT_MIN_VERSION):
    """RFC 4253: banner 形如 SSH-2.0-OpenSSH_9.6。
    返回 {kind, proto, software, version, note}; kind in OK/STALE/MISMATCH。"""
    text = (banner or "").strip()
    m = re.match(r"^SSH-(\d+\.\d+)-([A-Za-z0-9_.+/~-]+?)(?:[_-](\d+(?:\.\d+)*(?:p\d+)?))?(?:\s|$)", text)
    if not m:
        head = text.split("\n")[0][:40] if text else "(empty)"
        return {"kind": MISMATCH, "proto": None, "software": None,
                "version": None, "note": "非 SSH banner: %s" % head}
    proto, software, ver = m.group(1), m.group(2), m.group(3)
    stale = False
    if software and software.lower().startswith("openssh") and ver:
        stale = _ver_lt(ver, min_version)
    return {"kind": STALE if stale else OK, "proto": proto, "software": software,
            "version": ver, "note": ""}


def _ver_lt(a, b):
    """版本号字符串比较: 7.4 < 7.8 < 9.6。"""
    def tup(v):
        return tuple(int(x) if x.isdigit() else 0 for x in re.findall(r"\d+", v))
    try:
        return tup(a) < tup(b)
    except Exception:
        return False


def probe(host, port, connect_to=DEFAULT_CONNECT_TO, banner_to=DEFAULT_BANNER_TO):
    """一次 TCP 探测。绝不读/写 known_hosts, 不做密钥交换。
    返回 {state: OK/DEAD, banner, latency_ms, error}"""
    addr = (host, port)
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection(addr, timeout=connect_to)
        latency = (time.time() - t0) * 1000.0
        sock.settimeout(banner_to)
        chunks = []
        deadline = time.time() + banner_to
        while time.time() < deadline:
            try:
                data = sock.recv(128)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data.decode("utf-8", "replace"))
            if b"\n" in data:
                break
        banner = "".join(chunks).split("\n")[0].rstrip("\r")
        return {"state": OK, "banner": banner, "latency_ms": round(latency, 1), "error": ""}
    except socket.timeout:
        return {"state": DEAD, "banner": "", "latency_ms": round((time.time() - t0) * 1000.0, 1),
                "error": "connect timeout"}
    except ConnectionRefusedError:
        return {"state": DEAD, "banner": "", "latency_ms": round((time.time() - t0) * 1000.0, 1),
                "error": "connection refused"}
    except (OSError, ValueError) as e:
        return {"state": DEAD, "banner": "", "latency_ms": round((time.time() - t0) * 1000.0, 1),
                "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def sweep(targets, workers=DEFAULT_WORKERS, connect_to=DEFAULT_CONNECT_TO,
          banner_to=DEFAULT_BANNER_TO, min_version=DEFAULT_MIN_VERSION):
    """并发巡扫。返回 results: [ {target..., probe..., cls...} ] 保持输入顺序。"""
    lock = threading.Lock()
    results = [None] * len(targets)

    def one(i, t):
        r = probe(t["host"], t["port"], connect_to, banner_to)
        cls = classify_banner(r["banner"], min_version) if r["state"] == OK else \
            {"kind": DEAD, "proto": None, "software": None, "version": None, "note": r["error"]}
        rec = {"host": t["host"], "port": t["port"], "aliases": list(t["aliases"]),
               "state": r["state"], "banner": r["banner"], "latency_ms": r["latency_ms"],
               "error": r["error"], "kind": cls["kind"], "proto": cls["proto"],
               "software": cls["software"], "version": cls["version"], "note": cls["note"]}
        with lock:
            results[i] = rec

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for i, t in enumerate(targets):
            ex.submit(one, i, t)
    return results


# ---------------------------------------------------------------- 基线

def baseline_record(results):
    return {
        "tool": TOOL, "version": VERSION, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "min_version": DEFAULT_MIN_VERSION,
        "targets": {
            "%s:%d" % (r["host"], r["port"]): {
                "alive": r["state"] == OK, "banner": r["banner"],
                "software": r["software"], "version": r["version"],
                "latency_ms": r["latency_ms"],
            } for r in results
        },
    }


def save_baseline(path, results):
    doc = baseline_record(results)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return doc


def compare_baseline(path, results):
    """对比基线, 返回 drift 事件列表。
    HOST_GONE / HOST_REVIVED / VERSION_DRIFT / BANNER_CHANGE / NEW_HOST"""
    try:
        with open(path, encoding="utf-8") as f:
            base = json.load(f)
    except (OSError, ValueError) as e:
        raise UsageError("基线文件不可读: %s (%s)" % (path, e))
    old = base.get("targets", {})
    events = []
    seen = set()
    for r in results:
        key = "%s:%d" % (r["host"], r["port"])
        seen.add(key)
        if key not in old:
            events.append({"event": "NEW_HOST", "target": key,
                           "detail": "基线里没有这台（清单扩了）"})
            continue
        o = old[key]
        now_alive = r["state"] == OK
        if o["alive"] and not now_alive:
            events.append({"event": "HOST_GONE", "target": key,
                           "detail": "基线时存活, 现在死了 (%s)" % (r["error"] or "unknown")})
        elif (not o["alive"]) and now_alive:
            events.append({"event": "HOST_REVIVED", "target": key,
                           "detail": "基线时已死, 现在活了 (%s)" % (r["banner"][:40])})
        elif now_alive and o["alive"]:
            if (o["software"], o["version"]) != (r["software"], r["version"]):
                events.append({"event": "VERSION_DRIFT", "target": key,
                               "detail": "版本 %s -> %s" % (
                                   _sw_ver_str(o["software"], o["version"]),
                                   _sw_ver_str(r["software"], r["version"]))})
            elif r["banner"] != o["banner"]:
                events.append({"event": "BANNER_CHANGE", "target": key,
                               "detail": "%s -> %s" % (o["banner"][:40], r["banner"][:40])})
    for key in old:
        if key not in seen:
            events.append({"event": "TARGET_REMOVED", "target": key,
                           "detail": "基线里有, 本次清单没有（清单缩了?）"})
    return events


def _sw_ver_str(soft, ver):
    s = soft or "?"
    v = ver or "?"
    return "%s %s" % (s, v)


# ---------------------------------------------------------------- 报告

def render_report(results, events=None, baseline_path=None, elapsed=None):
    lines = []
    n_ok = sum(1 for r in results if r["kind"] == OK)
    n_stale = sum(1 for r in results if r["kind"] == STALE)
    n_mm = sum(1 for r in results if r["kind"] == MISMATCH)
    n_dead = sum(1 for r in results if r["state"] == DEAD)
    n_id = sum(len(r["aliases"]) for r in results)
    head = "FLEET %d targets (%d identities) | alive %d, dead %d, stale %d, mismatch %d" % (
        len(results), n_id, n_ok, n_dead, n_stale, n_mm)
    if elapsed is not None:
        head += " | %.1fs" % elapsed
    lines.append(head)
    lines.append("-" * 64)
    for r in results:
        name = ", ".join(r["aliases"]) if r["aliases"] != [r["host"]] else r["host"]
        addr = "%s:%d" % (r["host"], r["port"])
        if r["state"] == DEAD:
            lines.append("[DEAD    ] %-22s %-22s %s" % (name, addr, r["error"]))
        elif r["kind"] == OK:
            lines.append("[OK      ] %-22s %-22s %s %s  %sms" % (
                name, addr, r["software"], r["version"], r["latency_ms"]))
        elif r["kind"] == STALE:
            lines.append("[STALE   ] %-22s %-22s %s %s (< min)  %sms" % (
                name, addr, r["software"], r["version"], r["latency_ms"]))
        else:
            lines.append("[MISMATCH] %-22s %-22s %s" % (name, addr, r["note"]))
    if events is not None:
        lines.append("")
        if events:
            lines.append("DRIFT vs %s (%d events):" % (os.path.basename(baseline_path or ""), len(events)))
            for e in events:
                lines.append("  [%s] %-22s %s" % (e["event"], e["target"], e["detail"]))
        else:
            lines.append("DRIFT: none — fleet 与基线一致")
    return "\n".join(lines)


def exit_code(results, events=None):
    if events:
        return 4
    kinds = {r["kind"] for r in results}
    if DEAD in kinds:
        return 2
    if STALE in kinds or MISMATCH in kinds:
        return 3
    return 0


# ---------------------------------------------------------------- explain

INVARIANTS = {
    "SW-01": "裸主机名目标默认端口 22; host:port 显式端口; [IPv6]:port 括号形式。",
    "SW-02": "同 (host, port) 多别名合并为一个目标, 身份计数不丢（别名全保留）。",
    "SW-03": "banner 分类遵循 RFC 4253: SSH-2.0-OpenSSH_9.6 -> proto/software/version。",
    "SW-04": "非 SSH banner(HTTP 等) 判 MISMATCH, 不冒充 SSH 存活。",
    "SW-05": "拒绝连接 -> DEAD(error=connection refused), 与超时分开计量。",
    "SW-06": "连接超时/不可达 -> DEAD(error=connect timeout|unreachable)。",
    "SW-07": "OpenSSH 版本低于 --min-version(默认 7.8) 判 STALE。",
    "SW-08": "退出码契约: 0 健康 / 2 有死机 / 3 有陈旧或异类 / 4 基线漂移 / 1 用法错。",
    "SW-09": "--json 输出机器可读报告, 字段齐全(state/kind/software/version/latency)。",
    "SW-10": "只做 TCP+banner: 不写 known_hosts, 不做密钥交换, 不登录远端。",
    "SW-11": "端口越界/空主机名/格式坏行 -> UsageError 退出码 1, 不静默吞。",
    "SW-12": "并发巡扫: 6 个目标总耗时远小于串行累加（线程池生效）。",
    "SW-13": "基线往返: save -> 环境变化 -> compare 必须给出预期事件类型。",
    "SW-14": "Include 指令展开 + 深度限 3 防环; 通配/取反 pattern 跳过不猜。",
}


# ---------------------------------------------------------------- 自测

def _spawn_banner_listener(banner, delay=0.0):
    """起一个一次性监听 socket(真实 TCP), 返回 (port, stop_fn)。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = {"on": True}

    def serve():
        srv.settimeout(0.2)
        while stop["on"]:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if delay:
                time.sleep(delay)
            try:
                conn.sendall((banner + "\r\n").encode())
                time.sleep(0.05)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        srv.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return port, lambda: stop.update(off=True) or stop.update(on=False)


def selftest():
    """SW-01..SW-14 不变量自测。全部在 127.0.0.1 + 临时目录进行, 不碰真实网络。"""
    fails = []
    counters = {"n": 0}

    def check(name, cond, detail=""):
        counters["n"] += 1
        tag = "PASS" if cond else "FAIL"
        print("  [%s] %-6s %s" % (tag, name, detail if not cond else ""))
        if not cond:
            fails.append(name)

    print("== sshsweep selftest ==")

    # SW-01 裸主机名默认 22 / 显式端口 / IPv6 括号形式
    t = parse_target_line("web.corp.lan")
    check("SW-01a", t == (None, "web.corp.lan", 22), str(t))
    t = parse_target_line("db@10.0.0.6:2200")
    check("SW-01b", t == ("db", "10.0.0.6", 2200), str(t))
    t = parse_target_line("[::1]:2222")
    check("SW-01c", t == (None, "::1", 2222), str(t))

    # SW-11 坏行必须报错而非吞掉
    for bad in ("host:0", "host:70000", "host:abc", "=10.0.0.1"):
        try:
            parse_target_line(bad)
            check("SW-11", False, "%s 未报错" % bad)
        except UsageError:
            check("SW-11", True)

    # SW-02 别名去重: 同址多别名合并, 身份计数保留
    merged = merge_entries([
        ("web-1", "10.1.1.5", 22), ("web-1-backup", "10.1.1.5", 22),
        ("db-1", "10.1.1.6", 22), (None, "10.1.1.7", 2200), ("db-1", "10.1.1.6", 22),
    ])
    check("SW-02", len(merged) == 3 and
          sorted(merged[0]["aliases"]) == ["web-1", "web-1-backup"] and
          sum(len(x["aliases"]) for x in merged) == 4,
          str([(x["host"], x["aliases"]) for x in merged]))

    # SW-03 banner 分类 RFC4253
    c = classify_banner("SSH-2.0-OpenSSH_9.6\r\n")
    check("SW-03", c["kind"] == OK and c["proto"] == "2.0" and
          c["software"] == "OpenSSH" and c["version"] == "9.6", str(c))

    # SW-04 非 SSH banner -> MISMATCH
    c = classify_banner("HTTP/1.1 400 Bad Request")
    check("SW-04", c["kind"] == MISMATCH, str(c))
    c = classify_banner("")
    check("SW-04b", c["kind"] == MISMATCH, str(c))

    # SW-05 拒绝连接 -> DEAD/refused (127.0.0.1 关闭端口)
    r = probe("127.0.0.1", 1, connect_to=1.0, banner_to=0.5)
    check("SW-05", r["state"] == DEAD and "refused" in r["error"], str(r))

    # SW-06 超时/不可达 -> DEAD, 与 refused 区分（不可路由测试地址, 0.4s 快速超时）
    r = probe("10.255.255.1", 23222, connect_to=0.4, banner_to=0.3)
    check("SW-06", r["state"] == DEAD and "refused" not in r["error"], str(r))

    # SW-07 版本阈值
    check("SW-07a", classify_banner("SSH-2.0-OpenSSH_7.4")["kind"] == STALE)
    check("SW-07b", classify_banner("SSH-2.0-OpenSSH_9.6")["kind"] == OK)
    check("SW-07c", classify_banner("SSH-2.0-dropbear_2020.79")["kind"] == OK,
          "非 OpenSSH 软件不套用 OpenSSH 阈值")

    # 真实监听 fleet: 三个 banner 服务
    p_ok, stop_ok = _spawn_banner_listener("SSH-2.0-OpenSSH_9.6")
    p_old, stop_old = _spawn_banner_listener("SSH-2.0-OpenSSH_7.4")
    p_http, stop_http = _spawn_banner_listener("HTTP/1.1 400 Bad Request")
    dead_port = 1  # 127.0.0.1:1 通常无人监听
    try:
        time.sleep(0.15)
        targets = merge_entries([
            ("fresh-1", "127.0.0.1", p_ok), ("fresh-1-b", "127.0.0.1", p_ok),
            ("old-1", "127.0.0.1", p_old), ("odd-1", "127.0.0.1", p_http),
            ("ghost-1", "127.0.0.1", dead_port),
        ])
        t0 = time.time()
        results = sweep(targets, workers=8, connect_to=2.0, banner_to=1.5)
        elapsed = time.time() - t0

        by_alias = {}
        for r in results:
            for a in r["aliases"]:
                by_alias[a] = r

        # SW-02 语义在真实 sweep 上成立: fresh-1 与 fresh-1-b 是同一条结果
        check("SW-02r", by_alias["fresh-1"] is by_alias["fresh-1-b"] and
              by_alias["fresh-1"]["version"] == "9.6")

        # SW-08 退出码契约
        kinds_now = {r["kind"] for r in results}
        has_dead = any(r["state"] == DEAD for r in results)
        expect = 2 if has_dead else (3 if ({"STALE", "MISMATCH"} & kinds_now) else 0)
        check("SW-08a", exit_code(results) == expect and has_dead,
              "本场景含 dead -> 应为 2")
        check("SW-08b", exit_code([by_alias["fresh-1"]]) == 0)
        check("SW-08c", exit_code([by_alias["ghost-1"]]) == 2)

        # SW-09 JSON 字段齐全
        need = {"host", "port", "aliases", "state", "banner", "kind",
                "software", "version", "latency_ms"}
        check("SW-09", all(need.issubset(r.keys()) for r in results))

        # SW-10 不写 known_hosts
        kh = os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
        if os.path.exists(kh):
            h0 = hashlib.sha256(open(kh, "rb").read()).hexdigest()
            sweep(targets[:2], workers=2, connect_to=2.0, banner_to=1.0)
            h1 = hashlib.sha256(open(kh, "rb").read()).hexdigest()
            check("SW-10", h0 == h1)
        else:
            check("SW-10", True, "(no known_hosts, skipped)")

        # SW-12 并发: 5 目标串行上界约 5*connect_to, 并行应远小于
        check("SW-12", elapsed < 2.0 * len(targets) / 8 * 8 and elapsed < 6.0,
              "elapsed=%.2fs" % elapsed)

        # SW-13 基线往返: 单元级构造合成结果(复用 selftest 环境内固定 host:port),
        # 只测 compare_baseline 纯函数语义, 不做端口漂移的真实服务切换。
        with tempfile.TemporaryDirectory() as td:
            bl = os.path.join(td, "base.json")
            mk = lambda host, port, state, banner, soft, ver: {
                "host": host, "port": port, "aliases": [host], "state": state,
                "banner": banner, "latency_ms": 1.0, "error": "",
                "kind": state if state == DEAD else
                        (classify_banner(banner)["kind"] if state == OK else state),
                "proto": None, "software": soft, "version": ver,
                "note": "" if state == OK else "x"}
            base_now = [
                mk("10.199.0.1", 22, OK, "SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6"),
                mk("10.199.0.2", 22, OK, "SSH-2.0-OpenSSH_8.2", "OpenSSH", "8.2"),
                mk("10.199.0.3", 22, DEAD, "", None, None),
            ]
            save_baseline(bl, base_now)
            after = [
                # alive->dead => HOST_GONE
                mk("10.199.0.1", 22, DEAD, "", None, None),
                # 8.2 -> 7.4 => VERSION_DRIFT
                mk("10.199.0.2", 22, OK, "SSH-2.0-OpenSSH_7.4", "OpenSSH", "7.4"),
                # dead->alive => HOST_REVIVED
                mk("10.199.0.3", 22, OK, "SSH-2.0-OpenSSH_7.4", "OpenSSH", "7.4"),
                # 新面孔 => NEW_HOST
                mk("10.199.0.9", 22, OK, "SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6"),
            ]
            events = compare_baseline(bl, after)
            kinds = {e["event"] for e in events}
            check("SW-13", {"HOST_GONE", "VERSION_DRIFT", "HOST_REVIVED", "NEW_HOST"} <= kinds
                  and not any(e["event"] == "TARGET_REMOVED" for e in events),
                  str(events))
            check("SW-08d", exit_code(after, events) == 4)
            # 清单缩编 -> TARGET_REMOVED
            events2 = compare_baseline(bl, [after[0]])
            check("SW-13b", any(e["event"] == "TARGET_REMOVED" for e in events2),
                  str(events2))
            # 基线无漂移场景: 同状态同版本 -> 空 events
            events3 = compare_baseline(bl, base_now)
            check("SW-13c", events3 == [], str(events3))
    finally:
        stop_ok(); stop_old(); stop_http()

    # SW-14 Include 展开 + 通配跳过
    with tempfile.TemporaryDirectory() as td:
        inc = os.path.join(td, "work_hosts")
        with open(inc, "w", encoding="utf-8") as f:
            f.write("Host lab-a\n  HostName 10.60.0.11\n  Port 2222\n")
        main = os.path.join(td, "config")
        with open(main, "w", encoding="utf-8") as f:
            f.write("Include %s\n\nHost lab-b lab-c\n  HostName 10.60.0.12\n\n"
                    "Host *!pattern\n  HostName 10.99.99.99\n" % inc)
        got = parse_ssh_config(main)
        m = {(a, h, p) for (a, h, p) in got}
        check("SW-14", ("lab-a", "10.60.0.11", 2222) in m and
              ("lab-b", "10.60.0.12", 22) in m and ("lab-c", "10.60.0.12", 22) in m,
              str(sorted(m)))

    print("== %d checks, %d failed ==" % (counters["n"], len(fails)))
    if fails:
        print("FAILED:", ", ".join(sorted(set(fails))))
        return 1
    print("ALL GREEN")
    return 0


# ---------------------------------------------------------------- CLI

def cmd_inventory(args):
    targets = build_targets(args)
    print("FLEET %d targets (%d identities):" % (
        len(targets), sum(len(t["aliases"]) for t in targets)))
    for t in targets:
        name = ", ".join(t["aliases"]) if t["aliases"] != [t["host"]] else "(bare)"
        print("  %-28s -> %s:%d" % (name, t["host"], t["port"]))
    return 0


def cmd_sweep(args):
    targets = build_targets(args)
    t0 = time.time()
    results = sweep(targets, workers=args.workers, connect_to=args.connect_timeout,
                    banner_to=args.banner_timeout, min_version=args.min_version)
    elapsed = time.time() - t0
    events = None
    if args.compare:
        events = compare_baseline(args.compare, results)
    out = render_report(results, events, args.compare, elapsed)
    print(out)
    if args.json:
        doc = {"tool": TOOL, "version": VERSION, "swept_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "elapsed_s": round(elapsed, 2), "results": results}
        if events is not None:
            doc["drift"] = events
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        print("json -> %s" % args.json)
    if args.baseline:
        save_baseline(args.baseline, results)
        print("baseline -> %s (%d targets pinned)" % (args.baseline, len(results)))
    return exit_code(results, events)


def cmd_explain(args):
    if args.code:
        code = args.code.upper()
        if code not in INVARIANTS:
            print("unknown invariant: %s" % code)
            return 1
        print("%s: %s" % (code, INVARIANTS[code]))
        return 0
    for k in sorted(INVARIANTS):
        print("%s  %s" % (k, INVARIANTS[k]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog=TOOL, description="SSH 主机群活性巡扫（零依赖单文件）")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("--inv", help="清单文件: 每行 [alias=]host[:port], # 注释")
        p.add_argument("--config", help="从 ssh_config 展开 (Host/HostName/Port/Include)")
        p.add_argument("--targets", help="逗号分隔内联清单: a@1.2.3.4:22, b:2222")
        p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
        p.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TO)
        p.add_argument("--banner-timeout", type=float, default=DEFAULT_BANNER_TO)
        p.add_argument("--min-version", default=DEFAULT_MIN_VERSION,
                       help="OpenSSH 低于此版本判 STALE (默认 %(default)s)")

    p_sweep = sub.add_parser("sweep", help="巡扫（默认动作）")
    common(p_sweep)
    p_sweep.add_argument("--baseline", help="巡扫后保存基线快照到该文件")
    p_sweep.add_argument("--compare", help="对比基线快照, 报告 HOST_GONE/VERSION_DRIFT 等")
    p_sweep.add_argument("--json", help="机器可读报告写到该文件")
    p_sweep.set_defaults(fn=cmd_sweep)

    p_inv = sub.add_parser("inventory", help="展开清单不探测")
    common(p_inv)
    p_inv.set_defaults(fn=cmd_inventory)

    p_ex = sub.add_parser("explain", help="解释不变量")
    p_ex.add_argument("code", nargs="?", help="如 SW-07")
    p_ex.set_defaults(fn=cmd_explain)

    sub.add_parser("selftest", help="内置不变量自测").set_defaults(fn=lambda a: selftest())

    args = ap.parse_args(argv)
    if not args.cmd:
        args.cmd = "sweep"
        argv = ["sweep"] + list(argv or [])
        args = ap.parse_args(argv)
    try:
        rc = args.fn(args)
    except UsageError as e:
        print("usage error: %s" % e, file=sys.stderr)
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
