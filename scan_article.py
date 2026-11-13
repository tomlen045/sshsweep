#!/usr/bin/env python3
"""sshsweep 文章自检: 标签配对/;;/87%卡片/显式对齐/敏感信息/事实锚点"""
import re
import sys

HTML = "/Users/len/CodeBuddy/dx/sshsweep/sshsweep-article.html"
txt = open(HTML, encoding="utf-8").read()
errors, warns = [], []

# 1 标签配对
from html.parser import HTMLParser
VOID = {"br", "img", "meta", "hr", "input", "link"}


class P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.bad = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.bad.append(tag)
        else:
            self.stack.pop()


p = P()
p.feed(txt)
if p.bad or p.stack:
    errors.append("标签配对: bad=%s unclosed=%s" % (p.bad, p.stack))
else:
    print("PASS 标签配对")

# 2 双分号
n = txt.count(";;")
if n:
    errors.append("双分号 x%d" % n)
else:
    print("PASS 无双分号")

# 3 卡片 87% + margin auto (section 带背景色的卡片)
cards = re.findall(r'<section[^>]*style="([^"]*)"', txt)
for i, s in enumerate(cards):
    has_bg = ("background" in s) or ("gradient" in s)
    if has_bg:
        if "width:87%" not in s:
            errors.append("卡片%d 缺 width:87%%: %s" % (i, s[:60]))
        margin_part = s.split("margin")[-1] if "margin" in s else ""
        seg = margin_part.split(";")[0]
        if not ("auto" in seg or "margin-left:auto" in s):
            errors.append("卡片%d 缺 margin auto: %s" % (i, s[:60]))
        if "box-sizing:border-box" not in s:
            errors.append("卡片%d 缺 box-sizing" % i)
print("PASS 色卡 87%%+margin auto: %d cards checked" % len(cards))

# 4 显式对齐: 每个 p/section 的 style 都有 text-align
ps = re.findall(r'<p[^>]*style="([^"]*)"', txt)
no_align = [s[:50] for s in ps if "text-align" not in s]
if no_align:
    errors.append("%d 个 p 缺显式 text-align: %s" % (len(no_align), no_align[:3]))
else:
    print("PASS 全部 %d 个 p 显式对齐" % len(ps))

# 5 敏感信息 (含空格变体)
sens = ["172.16", "172.18", "10.92", "Appmobsf", "Aixdr", "br-624580c9bf89",
        "Appmobsf#2026", "31e342", "352c9c"]
flat = txt.replace(" ", "")
for s in sens:
    if s in txt or s in flat:
        errors.append("敏感信息命中: %s" % s)
if not errors or all("敏感" not in e for e in errors):
    print("PASS 敏感信息 0 命中 (含空格变体)")

# 6 事实锚点
anchors = {
    "RFC 4253": "banner 协议出处",
    "OpenSSH_9.6": "示例 banner",
    "SW-01": "不变量编号存在",
    "SW-14": "不变量编号存在",
    "28": "自测检查数",
    "7.8": "默认版本阈值",
    "tomlen045/sshsweep": "GitHub 仓库地址",
    "HOST_GONE": "漂移事件类型",
    "VERSION_DRIFT": "漂移事件类型",
    "TARGET_REMOVED": "漂移事件类型",
}
for a, why in anchors.items():
    if a not in txt:
        errors.append("事实锚点缺失: %s (%s)" % (a, why))
if not any("锚点" in e for e in errors):
    print("PASS 事实锚点 %d/%d" % (len(anchors), len(anchors)))

# 7 图片引用存在
import os
base = os.path.dirname(HTML)
for m in re.findall(r'<img src="([^"]+)"', txt):
    if m.startswith("http://") or m.startswith("https://"):
        continue
    path = os.path.join(base, m)
    if not os.path.exists(path):
        errors.append("图片不存在: %s" % m)
if not any("图片不存在" in e for e in errors):
    print("PASS 图片文件全部存在")

print("-" * 40)
if errors:
    print("FAIL (%d):" % len(errors))
    for e in errors:
        print(" -", e)
    sys.exit(1)
print("SCAN PASS")
