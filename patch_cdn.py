#!/usr/bin/env python3
"""把文章 HTML 里的相对图片路径替换为 gcore SHA 锚定 CDN URL。"""
import json

HTML = "/Users/len/CodeBuddy/dx/sshsweep/sshsweep-article.html"
cdn = json.load(open("/Users/len/CodeBuddy/dx/sshsweep/cdn_check.json"))
t = open(HTML, encoding="utf-8").read()
n = 0
for name, info in cdn.items():
    old = 'src="shots/%s.png"' % name
    if old in t:
        t = t.replace(old, 'src="%s"' % info["url"])
        n += 1
open(HTML, "w", encoding="utf-8").write(t)
print("replaced", n, "img -> CDN")
# 复扫
import subprocess
r = subprocess.run(["python3", "scan_article.py"], capture_output=True, text=True)
print(r.stdout[-600:])
