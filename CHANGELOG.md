# Changelog

## 1.0.0 — 2026-11-13

首发版本。

- `sweep` 并发巡扫：TCP + RFC 4253 banner 读取，OK/STALE/MISMATCH/DEAD 四态判定
- `inventory` 清单展开（--inv 文件 / --config ssh_config 展开 / --targets 内联）
- `--baseline` 定基线，`--compare` 漂移对比：HOST_GONE / HOST_REVIVED /
  VERSION_DRIFT / BANNER_CHANGE / NEW_HOST / TARGET_REMOVED 六类事件
- `--json` 机器可读报告；`explain` 不变量速查；`selftest` 28 项不变量自测
- 同址多别名合并（SW-02），身份计数不丢
- OpenSSH 版本阈值 --min-version（默认 7.8），dropbear 等非 OpenSSH 不误伤
- 退出码契约 0/1/2/3/4（SW-08）
- 探测全程不写 known_hosts、不做密钥交换、不登录（SW-10）

开发中抓到并修掉的真 bug（狗粮记录）：

1. banner 正则不支持 `OpenSSH_9.6p1` 带后缀版本号 → 版本抓不全（自测 SW-03 扩展覆盖）
2. 别名双形态 `alias@host` 只实现了 `alias=host`，帮助文本承诺了却没做到（自测 SW-01b 抓住）
3. 空别名行 `=host` 静默当裸主机名解析，坏格式必须报错（自测 SW-11 抓住）
4. 演示脚本 `listener()` 默认参数共享字典，五个监听互相覆盖 banner——
   症状是第二轮巡扫全体主机「同时降级」，一眼假；改成每次调用独立 state
