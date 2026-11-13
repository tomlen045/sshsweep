#!/bin/bash
# GitHub push + 远端哈希验证（sshsweep 专用，照 cronproof/sync_github.sh 逻辑）
# 注意：git rev-parse github/main 判 push 成功是错的——那是旧 ref。
# 必须 git ls-remote 对比远端哈希。
set -e
cd /Users/len/CodeBuddy/dx/sshsweep

TOKEN=$(security find-generic-password -s GH_TOKEN -w 2>/dev/null)
[ -n "$TOKEN" ] || { echo "GH_TOKEN missing"; exit 1; }

git remote remove github 2>/dev/null || true
git remote add github "https://tomlen045:$TOKEN@github.com/tomlen045/sshsweep.git"

LOCAL=$(git rev-parse HEAD)
for i in 1 2 3 4 5; do
  GIT_TERMINAL_PROMPT=0 git -c http.version=HTTP/1.1 push -u github main 2>&1 | tail -1
  sleep 15
  REMOTE=$(git ls-remote github refs/heads/main 2>/dev/null | cut -c1-40)
  echo "round $i local=$LOCAL remote=$REMOTE"
  if [ "$REMOTE" = "$LOCAL" ]; then echo SYNCED; exit 0; fi
done
echo NOT_SYNCED
exit 1
