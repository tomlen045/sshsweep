#!/bin/bash
# QA 渲染 sshsweep-article.html: headless=old + alarm 兜底; 底边按内容真实高度裁切
set -e
cd /Users/len/CodeBuddy/dx/sshsweep
OUT=/tmp/sshsweep_qa
mkdir -p $OUT
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
perl -e 'alarm 60; exec @ARGV' "$CHROME" --headless=old --disable-gpu --no-first-run \
  --user-data-dir=/tmp/sshsweep_qa_profile \
  --window-size=760,3800 --screenshot=$OUT/full.png \
  "file:///Users/len/CodeBuddy/dx/sshsweep/sshsweep-article.html" 2>/dev/null || true
ls -la $OUT/full.png
python3 - <<'EOF'
from PIL import Image
import numpy as np
im = Image.open("/tmp/sshsweep_qa/full.png")
a = np.asarray(im.convert("L"))
rows = np.where((a < 245).any(axis=1))[0]
bottom = int(rows.max()) + 30 if len(rows) else im.height
print("content bottom:", bottom, "canvas:", im.height)
im.crop((0, 0, im.width, min(bottom, im.height))).save("/tmp/sshsweep_qa/page.png")
# 分两段便于 vision 检查
h = im.crop((0, 0, im.width, min(bottom, im.height))).height
page = Image.open("/tmp/sshsweep_qa/page.png")
page.crop((0, 0, page.width, h // 2)).save("/tmp/sshsweep_qa/top.png")
page.crop((0, h // 2, page.width, h)).save("/tmp/sshsweep_qa/bot.png")
print("halves saved", page.width, h)
EOF
