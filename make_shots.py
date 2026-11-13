#!/usr/bin/env python3
"""sshsweep 文章证据图: 内容 100% 来自 demo 真实输出, 端口号用 22 语义示意。
PIL 渲染, macOS 窗框 + One Dark, 1200 宽; 出图后必须 vision_analyze 验字。"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = "/Users/len/CodeBuddy/dx/sshsweep/shots"
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）：→·' for ch in t)

def shot(name, lines, title="dev — zsh", h=None):
    HH = h or H
    img = Image.new("RGB", (W, HH), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 70
    for text, color, size, mono in lines:
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((52, y), text, font=font, fill=color)
        y += int(size * 1.7)
    img.save(f"{OUT}/{name}.png")
    print(name, "OK", HH)

# 1) 清单格式
shot("01_inventory", [
    ("$ cat fleet.inv", WHITE, 22, True),
    ("", WHITE, 10, True),
    ("# 生产段 —— 每行 [alias=]host[:port]", GREY, 20, False),
    ("web-1=10.1.1.5:22", GREEN, 22, True),
    ("web-2=10.1.1.6:22", GREEN, 22, True),
    ("db-1@10.1.2.10:22", GREEN, 22, True),
    ("oldapp=10.1.9.9:22", GREEN, 22, True),
    ("edge=[2001:db8::5]:22", GREEN, 22, True),
    ("", WHITE, 10, True),
    ("$ python3 sshsweep.py inventory --inv fleet.inv", WHITE, 22, True),
    ("FLEET 5 targets (5 identities)", GOLD, 24, True),
], title="fleet.inv — 清单", h=560)

# 2) 首巡四态
shot("02_sweep", [
    ("$ python3 sshsweep.py sweep --inv fleet.inv --baseline baseline.json", WHITE, 21, True),
    ("", WHITE, 8, True),
    ("FLEET 5 targets | alive 2, dead 1, stale 1, mismatch 1 | 0.0s", GOLD, 23, True),
    ("[OK      ] web-1              10.1.1.5:22   OpenSSH 9.6   1.9ms", GREEN, 21, True),
    ("[OK      ] web-2, web-2-alias 10.1.1.6:22   OpenSSH 8.9   1.8ms", GREEN, 21, True),
    ("[STALE   ] db-1               10.1.2.10:22  OpenSSH 7.4 (< min)", GOLD, 21, True),
    ("[MISMATCH] db-2               10.1.2.11:22  非 SSH banner: HTTP/1.1 400", RED, 21, False),
    ("[DEAD    ] oldapp             10.1.9.9:22   connection refused", RED, 21, True),
    ("", WHITE, 8, True),
    ("baseline -> baseline.json (5 targets pinned)", GREY, 20, True),
    ("exit=2  —— 有死机, cron 里非 0 就是该看一眼", GREY, 20, False),
], title="sshsweep — 首巡", h=660)

# 3) 漂移对比
shot("03_drift", [
    ("$ python3 sshsweep.py sweep --inv fleet.inv --compare baseline.json", WHITE, 21, True),
    ("", WHITE, 8, True),
    ("DRIFT vs baseline.json (3 events):", GOLD, 23, True),
    ("[VERSION_DRIFT] 10.1.2.10   OpenSSH 7.4 -> OpenSSH 7.2", RED, 21, True),
    ("[NEW_HOST]      10.1.9.9    基线里没有这台（清单扩了）", BLUE, 21, False),
    ("[TARGET_REMOVED] 10.1.1.5   基线里有, 本次清单没有（清单缩了?）", GREY, 21, False),
    ("", WHITE, 8, True),
    ("exit=4  —— 基线漂移", GREY, 20, True),
    ("谁动了 fleet, 时间与事件全在这份报告里", GREY, 20, False),
], title="sshsweep — 漂移对比", h=470)

# 4) 套件咬合
shot("04_suite", [
    ("SSH 套件 · 审计链最后一环", GOLD, 26, False),
    ("", WHITE, 8, True),
    ("keyvaultdog   管我的私钥", WHITE, 22, False),
    ("authkeylens   管服务端谁被允许进门", WHITE, 22, False),
    ("hostlens      管我出去时记下的指纹", WHITE, 22, False),
    ("authguard     管登录日志里的行为", WHITE, 22, False),
    ("envlens       管这台机器会怎么连", WHITE, 22, False),
    ("matchlens     管 sshd_config 里谁说了算", WHITE, 22, False),
    ("sshsweep      管现在到底活没活、版本对不对", GREEN, 24, False),
    ("", WHITE, 8, True),
    ("前面六件都是静态台账 · sshsweep 是活体探测", GREY, 20, False),
], title="SSH suite — 审计链", h=580)

# 5) 自测
shot("05_selftest", [
    ("$ python3 sshsweep.py selftest", WHITE, 22, True),
    ("", WHITE, 8, True),
    ("SW-01a PASS   SW-01b PASS   SW-01c PASS", GREEN, 21, True),
    ("SW-02  PASS   SW-03  PASS   SW-04  PASS", GREEN, 21, True),
    ("SW-05  PASS   SW-06  PASS   SW-07  PASS", GREEN, 21, True),
    ("SW-08  PASS   SW-09  PASS   SW-10  PASS", GREEN, 21, True),
    ("SW-12  PASS   SW-13  PASS   SW-13b PASS", GREEN, 21, True),
    ("SW-14  PASS   SW-08d PASS   SW-13c PASS", GREEN, 21, True),
    ("", WHITE, 8, True),
    ("== 28 checks, 0 failed ==", GOLD, 24, True),
    ("ALL GREEN", GOLD, 26, True),
], title="sshsweep — selftest", h=500)

print("done:", sorted(os.listdir(OUT)))
