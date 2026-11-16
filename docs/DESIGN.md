# 实现设计

Reslark 是独立的 Node.js ESM 项目，不依赖原 res-downloader 的桌面框架、前端或全局状态，也不在 Node 中重新实现代理协议。代码使用 Node 内置模块；Python addon 由 mitmdump 自带解释器加载，仅使用标准库和 mitmproxy 自身 API。

## 数据流

```text
CLI
  ├─ 前台 controller / detached controller
  ├─ 仅回环地址的带 token 控制接口
  └─ mitmdump 子进程
       └─ addon/reslark.py
            ├─ 流式 spool 文件（不修改响应字节）
            ├─ 有界内容前缀扫描
            └─ 带前缀的 JSONL 元数据 → controller

controller
  ├─ 来源关系图、域名/类型/深度规则
  ├─ 未建立关系的候选暂存（有数量与磁盘限额）
  ├─ 原子提交文件与内容去重
  ├─ 并发下载队列、续传检查点
  └─ 公开清单 / 私有请求上下文
```

## 模块职责

| 模块 | 职责 |
| --- | --- |
| cli.js | 严格选项解析、命令、JSON、退出码 |
| session.js | 启停、后台控制、目标程序、停止条件 |
| backend.js | mitmdump 探测、参数、事件接收、进程回收 |
| resources.js / rules.js | 资源身份、选择、关联、保存、去重 |
| download.js / network.js | GET、重定向、认证范围、Range 与重试 |
| store.js / util.js | 私有目录、原子 JSON、JSONL、脱敏 |
| platform.js / recover.js | 证书、平台代理、进程快照、恢复 |
| cdp.js | 可选 Chromium initiator 和缓存补采 |
| media.js / scan.js | 清单关系、文件重写、ffmpeg 合并 |

## 会话和一致性

注册表位于 `~/.reslark/sessions/SESSION.json`，包括仅当前用户可读的 controller token。输出目录使用独占锁，每个新会话必须使用独立目录。JSON 文件以同目录临时文件加 rename 更新；清单串行 append。一个截断的最终 JSONL 行不会阻止读取此前完成的记录。

后台进程只有在 mitmdump ready、控制接口可访问、显式系统设置操作完成后才将状态置为 ready。正常停止先关闭目标程序与捕获，再排空/取消下载、清理暂存、恢复代理和关闭控制接口。控制进程被强制终止时不能保证执行退出钩子，因此保留恢复记录。

`recover` 不会仅凭注册表 PID 杀进程。系统代理恢复检查当前值是否仍由本会话设置；不覆盖其他程序或用户后续改动。平台代理和证书安装需要目标机器验收，自动集成测试不会改动这些设置。

## 资源模型

请求身份保留完整 URL、方法以及认证、Cookie、Accept、语言上下文，避免将不同签名/表示错误合并。资源记录描述逻辑资源最新可用状态；单次响应记录另存 `requests.jsonl`；完整文件以 SHA-256 去重。部分响应单独标记并以 `.partial` 保存。

HTML、CSS、JSON、重定向、播放清单和浏览器 initiator 建立有向关系。关联深度、资源数、候选数、扫描前缀、单响应大小和 spool 总量均有限额。跨域关系可以选择已先到达的候选响应；候选超限会产生遗漏事件。候选 body 被清理后无法补回未再次请求的内容。

关联扫描不是浏览器引擎。不会执行脚本，也不保证完整解析所有 HTML/CSS/平台数据。DASH 模板交给显式授权网络访问的 ffmpeg；平台专有脚本注入、解密、DRM 不包含在通用捕获中。

## 下载与恢复

下载只使用 GET。重定向与跨域资源继承会移除认证头和 Cookie；同源必要上下文保留在私有状态。下载器直接出站或使用显式 upstream，不重新进入自己的捕获代理，避免循环。

检查点以资源 ID 关联，保存验证器和部分文件。仅在验证器可用、表示未压缩且 Range 合法时追加；服务器回退完整响应则重新写入。成功后校验长度、计算哈希，再提交到输出目录。下载失败不会产生 completed 状态。新建目标文件不覆盖用户已有的不同内容。

## 发布边界

npm 只包含 bin、src、addon、文档和许可证，不包含测试环境、测试捕获、CA、原始项目或凭据。没有 postinstall 下载或自动系统修改。mitmdump 与 ffmpeg 独立安装和升级。

v0.1 的主要剩余平台验收：真实应用的 local mode、子进程覆盖、平台 CA 信任、系统代理恢复，以及实际 Chromium 调试连接。已有自动测试不将这些平台能力宣称为已验收。
