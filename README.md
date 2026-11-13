# sshsweep — SSH 主机群活性巡扫

回答三个问题：**fleet 里现在谁活着、谁死了、谁换了版本。**

零依赖单文件 Python CLI（Python 3.8+ 纯 stdlib）。探测 = 纯 TCP 连接 +
读一条 banner（RFC 4253），不碰 known_hosts、不做密钥交换、不登录、
不在远端留任何痕迹。

sshsweep 是 SSH 套件里管「活体探测」的那一件——审计链的最后一环：

> **keyvaultdog**（管我的私钥）→ **authkeylens**（管服务端谁被允许进门）
> → **hostlens**（管我出去时记下的指纹）→ **authguard**（管登录日志里的行为）
> → **envlens**（管这台机器会怎么连）→ **matchlens**（管 sshd_config 谁说了算）
> → **sshsweep**（管现在到底活没活、版本还对不对）

上面六件全是「静态台账」。台账再全，也回答不了凌晨三点那个问题：
**清单里那 40 台机器，现在到底有几台是真的？**

## 为什么需要它

主机清单烂起来是无声的：

- 交接文档里的 40 台机器，3 年没人验过货——一半早换了 IP，没人知道
- 应用了已下线，清单还挂着——等出事照着清单找机器，越找越乱
- 某台的 sshd 还是 OpenSSH 7.4（2017 年的版本）——三年没升级没人在意
- 端口 2222 后面挂的根本不是 sshd，是某个开发随手起的 HTTP 调试口
- 上周某台的 banner 从 8.9 变成了 7.2——谁降的级？为什么？没人说得清
- 清单里 `web-1`、`web-1-b`、`10.1.1.5` 其实是同一台——数机器永远数不准

`ping` 解决不了上面任何一条：ping 通只说明机器开着机，不说明 sshd 活着；
更不说明那是不是你要的那台 sshd。sshsweep 把验货变成一条命令，
把「谁变了」变成一份基线对比报告。

## 30 秒上手

```bash
# 1. 写清单：每行 [alias=]host[:port]，支持别名双形态 alias= 与 alias@
cat > fleet.inv <<'EOF'
# 生产段
web-1=10.1.1.5:22
web-2=10.1.1.6
db-1@10.1.2.10:22
oldapp=10.1.9.9
# IPv6 用方括号
edge=[2001:db8::5]:22
EOF

# 2. 首巡 + 定基线
python3 sshsweep.py sweep --inv fleet.inv --baseline baseline.json

# 3. 日常巡扫 + 漂移对比
python3 sshsweep.py sweep --inv fleet.inv --compare baseline.json

# 4. 没有清单？从 ssh config 直接展开（Host/HostName/Port/Include 都认）
python3 sshsweep.py sweep --config ~/.ssh/config

# 5. 临时看几台
python3 sshsweep.py sweep --targets "web@10.0.0.5:22, db:2222, [::1]:22"
```

一次巡扫长这样（本机演示舰队输出节选）：

```
FLEET 5 targets (6 identities) | alive 2, dead 1, stale 1, mismatch 1 | 0.0s
----------------------------------------------------------------
[OK      ] web-1                  10.1.1.5:22     OpenSSH 9.6  1.9ms
[OK      ] web-2, web-2-alias     10.1.1.6:22     OpenSSH 8.9  1.8ms
[STALE   ] db-1                   10.1.2.10:22    OpenSSH 7.4 (< min)  1.7ms
[MISMATCH] db-2                   10.1.2.11:22    非 SSH banner: HTTP/1.1 400 Bad Request
[DEAD    ] oldapp                 10.1.9.9:22     connection refused
```

同一地址的多个别名自动合并成一个目标（`web-2, web-2-alias`），
机器数不再虚报；`6 identities` 的身份计数保留全部别名，一个不丢。

## 它怎么判

| 判定 | 条件 | 退出码贡献 |
|---|---|---|
| OK | 完整 `SSH-2.0-软件 版本` banner，版本 ≥ min-version | 0 |
| STALE | OpenSSH 版本低于 `--min-version`（默认 7.8，2017 年） | 3 |
| MISMATCH | 端口活着但 banner 不是 SSH（HTTP/Redis/邮件服务……） | 3 |
| DEAD | 拒绝连接 / 超时 / 不可达，error 字段分开计量 | 2 |

基线对比的漂移事件：`HOST_GONE`（基线活现在死）、`HOST_REVIVED`
（基线死现在活）、`VERSION_DRIFT`（banner 版本变了）、`BANNER_CHANGE`
（整条 banner 变了）、`NEW_HOST`（清单扩了）、`TARGET_REMOVED`
（清单缩了）。

退出码契约：`0` 全健康 / `2` 有死机 / `3` 有陈旧或异类 / `4` 基线漂移 /
`1` 用法错误。丢进 cron，非 0 就是你该看一眼的时刻。

## 不变量体系 SW-01..14（`python3 sshsweep.py selftest` 28 项全绿）

每条不变量可用 `python3 sshsweep.py explain SW-07` 单独解释：

- **SW-01/11** 清单格式：裸主机名默认 22、`host:port`、`[IPv6]:port`；
  端口越界/空别名/坏格式行必须报错退出码 1，绝不静默吞
- **SW-02** 同址多别名合并去重，身份计数不丢
- **SW-03/04** banner 分类遵循 RFC 4253；非 SSH banner 判 MISMATCH 不冒充存活
- **SW-05/06** 拒绝连接与超时/不可达分开计量
- **SW-07** 版本阈值判定（只对 OpenSSH 生效，dropbear 等不误伤）
- **SW-08** 退出码契约全场景锁定
- **SW-09** `--json` 机器可读输出字段齐全
- **SW-10** 探测全程不写 known_hosts（自测拿哈希前后对比锁死）
- **SW-12** 并发巡扫（线程池，16 并发默认）
- **SW-13/13b/13c** 基线往返：save→突变→compare 必须给出预期事件类型；
  清单缩编报 TARGET_REMOVED；无变化报零事件
- **SW-14** ssh_config Include 展开（深度限 3 防环），通配/取反 pattern 跳过不猜

## 设计取舍（一句大实话）

banner 只告诉你「这个端口上跑着什么软件、什么版本」，它不等于
补丁级别——一台 banner 9.6 但三年没打补丁的机器，sshsweep 看不出来。
活性巡扫是「验货」，不是漏洞扫描；两者配合用，别互相替代。

另外默认 `--min-version 7.8` 是个保守线：OpenSSH 7.8 是 2017 年的版本，
低于它大概率意味着这台机器的 SSH 从没维护过。要收紧改参数，别改代码。

## 适合谁

- 接手了交接文档里一堆 IP、不知道哪些还活着的运维
- 定期要给领导交「资产台账」但每次都靠人肉 ping 一遍的团队
- 有严格版本基线要求（等保/ISO 27001）需要留巡扫证据的环境
- 把 sshsweep 丢进 cron、把漂移事件接进现有告警链的自动化玩家

## 不适合谁

- 需要漏洞级细节（CVE/补丁差异）的场景——用专门的漏洞扫描器
- 目标禁 ICMP/TCP 探测的合规网络——先拿授权再跑
- 大规模网段发现（成千上万 IP）——这是验清单的工具，不是扫网段的

## 兄弟工具

[debugkit](https://github.com/tomlen045/debugkit)（调试取证）、
[cronproof](https://github.com/tomlen045/cronproof)（crontab 基线审计）、
[authkeylens](https://github.com/tomlen045/authkeylens)（进门名单审计）、
[porteye](https://github.com/tomlen045/porteye)（端口暴露面）——
sshsweep 补上「清单验货」这块拼图。

## License

MIT
