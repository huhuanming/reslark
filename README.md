# Reslark

面向 AI agent 的资源捕获、关联追踪与下载 CLI。使用 Node.js 内置模块编写，**没有 npm 运行时依赖**；网络捕获交给 `mitmdump`，媒体合并按需使用 `ffmpeg`。

```text
目标域名 / 程序 → mitmdump + bundled addon → 来源关系 → 文件与 JSON 清单
```

## 安装

需要 Node.js 22.15+。捕获功能需要安装 [mitmproxy](https://docs.mitmproxy.org/stable/overview/installation/) 并让 `mitmdump` 出现在 PATH；官方独立发行版自带 Python 环境，无需额外安装 Python。

从源码立即使用：

```bash
git clone https://github.com/huhuanming/reslark.git
cd reslark
npm ci
node bin/reslark.js doctor --json
```

npm 首次发布完成后可使用：

```bash
npm install -g reslark
# 或者
npx reslark --help
```

本仓库包含 npm 发布配置，但提交到 GitHub 不会自动发布 npm 包。发布说明见 [docs/RELEASING.md](docs/RELEASING.md)。

## 启动捕获

以下例子使用安装后的 `reslark` 命令；源码运行时替换为 `node bin/reslark.js`。

```bash
reslark capture \
  --domain example.com \
  --domain '*.example.com' \
  --related \
  --complete \
  --out ./captures/example \
  --background \
  --json
```

返回 `session_id`、自动分配的 `proxy_url`、CA 路径和能力信息。将目标客户端的 HTTP/HTTPS 代理配置为返回的地址。每个会话需要一个新的输出目录。

- `--related`：追踪 HTML/CSS/JSON/播放列表引用、重定向及来源头，包含跨域 CDN。会解密送到本会话代理的所有非排除流量，再按关系决定保存范围。
- `--complete`：主动以 GET 下载缺失的关联资源，默认不会重放 POST 等请求。普通捕获会直接保存实际经过代理的响应体。
- `--exclude-domain HOST`：硬排除，优先于关联规则。
- `--type image --type video`：只保存指定类型的响应体；仍保留追踪所需元数据。
- 没有域名限制时必须使用 `--all`、指定程序，或通过 `run` 启动程序，避免隐式全局捕获。

HTTPS 客户端必须信任返回的 CA。也可以显式运行：

```bash
reslark cert init --json
reslark cert status --json
reslark cert install
reslark cert uninstall
```

普通启动不会自动修改证书信任。macOS 默认使用登录钥匙串，Windows 默认使用当前用户证书库；`--system` 用于系统范围，Linux 的系统安装仅支持 `update-ca-certificates` 布局并需要相应权限。

## 启动程序或捕获现有程序

```bash
# 向新程序提供代理环境变量和 CA 路径，程序退出后结束会话。
reslark run --out ./captures/curl --json -- curl https://example.com

# 使用 mitmdump local mode，捕获现有程序的出站流量。
reslark capture --pid 12345 --include-children \
  --related --out ./captures/program --background --json

reslark capture --process 'Google Chrome' --include-children \
  --domain example.com --related --out ./captures/browser --background --json
```

`run` 默认适用于遵循代理环境变量的程序。忽略代理设置的应用需要 local mode；其权限、辅助组件和平台限制由 [mitmproxy local capture](https://docs.mitmproxy.org/stable/concepts/modes/#local-capture) 决定。`--include-children` 轮询进程树，可能漏掉极短命或已重新挂接父进程的辅助进程；状态里返回当前匹配到的进程。

需要修改系统代理时显式使用 `--system-proxy`。macOS 同时指定 `--network-service Wi-Fi`；Linux 支持 GNOME gsettings，Windows 支持当前用户 Internet Settings。原设置会持久化；退出时只恢复仍属于本会话的设置，异常退出后使用 `recover`。

## AI 调用流程

```bash
reslark doctor --json
reslark status SESSION --json
reslark events SESSION --after 0 --limit 100
reslark resources SESSION --type video --limit 100 --json
reslark inspect RESOURCE --json
reslark download RESOURCE --json
reslark wait SESSION --until idle --idle 3s --timeout 30s --json
reslark stop SESSION --json
reslark export SESSION --format har --out ./capture.har --json
```

命令返回稳定的 JSON，事件使用 JSONL；错误 JSON 写到 stderr。后台启动只有在捕获后端和带认证的本地控制接口就绪后才返回。支持 `--request-id` 对创建会话去重。

`wait` 的 `idle`、`queue-empty`、`files`、`program-exited`、`stopped` 是独立条件；空队列或短暂静默不代表网站所有资源已被发现。完整协议和 agent 操作建议见 [docs/AI.md](docs/AI.md)。

## 下载和流媒体

```bash
# 直接下载无需 mitmdump；关联补全仍可用于播放列表、JSON 和 CSS。
reslark download --url https://example.com/file.mp4 --out ./captures/file --json

reslark download --url https://example.com/master.m3u8 \
  --related --complete --out ./captures/hls --json

reslark retry SESSION --json
reslark media MANIFEST_RESOURCE --out ./video.mp4 --json
```

大文件流式落盘，失败任务可重试；续传使用 ETag/Last-Modified 和 Content-Range 校验。`206` 部分响应、截断、`304` 无响应体和失败响应不会被当成完整文件。保留不同查询参数与登录上下文，完整对象按内容哈希去重。

HLS 清单、子清单、分片、初始化段和 key URI 可以建立关联并补全。`media` 默认只允许 ffmpeg 读取本地捕获资源；缺少分片时明确失败。模板形式的 DASH 可显式使用 `media RESOURCE --allow-network` 交给 ffmpeg 解析；此模式不向 ffmpeg 传递捕获的 Cookie/Authorization，且不能与域名排除规则组合。直播可通过 `--duration` 限制捕获或媒体录制时长。

## 输出与限额

```text
capture/
  session.json            # 会话状态与统计
  resources.jsonl         # 资源变更日志，按 id 取最后一条
  requests.jsonl          # 每次选中响应的记录
  relations.jsonl         # 来源关系与依据
  events.jsonl            # 带递增 seq 的事件
  downloads.jsonl         # 下载任务变更日志
  files/                  # 文件，按域名组织
  manifests/              # 原始播放清单
  .state/                 # 私有请求上下文、续传检查点、日志与控制状态
```

```bash
reslark capture --domain example.com --related --out ./captures/bounded \
  --duration 2m --max-files 200 --max-bytes 1GiB \
  --max-body-bytes 256MiB --max-spool-bytes 1GiB \
  --max-depth 5 --max-resources 20000 --max-pending 1000 \
  --concurrency 4 --background --json
```

元数据中的常见认证头和签名参数会脱敏，原始请求上下文仅保存在权限受限的私有状态中。**资源响应体本身可能包含敏感内容**，不会做内容脱敏。原始 URL 不会通过删参数“归一化”。

默认状态目录为 `~/.reslark`，可用 `--home` 或 `RESLARK_HOME` 覆盖。可通过 `--mitmdump` / `RESLARK_MITMDUMP` 指定后端，通过 `RESLARK_FFMPEG` 指定 ffmpeg。

## 能力边界

- HTTP/HTTPS/HTTP2 由 mitmdump 处理；普通代理模式不捕获绕过代理的 QUIC 流量。local mode 的 HTTP3 能力依赖后端与平台。
- 可选 `--cdp http://127.0.0.1:9222` 补充 Chromium 当前第一个页面目标的 initiator 和缓存/Service Worker 响应体；不是完整浏览器自动化，补采大小受 `--scan-bytes` 限制。
- WebSocket 保存消息方向、大小和哈希等公开元数据，消息内容只写私有状态。自定义 TCP/UDP 协议不会自动解释为可下载文件。
- 关联是基于可观察证据的有限追踪，不会执行 JavaScript。绝对文本 URL 和 Referer/Origin 关系标记为推断；JSON 内不一定每个 URL 都是资源。
- 证书固定、DRM、微信等平台专有加密不提供通用绕过或解密。
- 本地 HTTP/HTTPS、下载续传、关联补全和 HLS 合并有真实端到端测试。透明进程捕获、证书安装与系统代理恢复需要目标系统权限和设备验收；浏览器补采有协议级测试。

## 开发与验证

```bash
npm ci
npm run check
RESLARK_MITMDUMP=/absolute/path/to/mitmdump npm run test:integration
npm pack --dry-run
```

集成测试使用临时目录和独立 CA，不安装系统证书或更改系统代理。没有 mitmdump / ffmpeg 时，对应集成测试会显式跳过。设计说明见 [docs/DESIGN.md](docs/DESIGN.md)。
