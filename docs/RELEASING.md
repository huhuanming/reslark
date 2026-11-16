# npm 发布

包名和命令均为 `reslark`，源码仓库为 `huhuanming/reslark`。GitHub push 和 CI 不会发布 npm。

## 本地检查

```bash
npm ci
npm run check
RESLARK_MITMDUMP=/absolute/path/to/mitmdump npm run test:integration
npm pack --dry-run
npm pack
npm exec --yes --package ./reslark-0.1.0.tgz -- reslark --version
```

确认 tarball 包含 `addon/reslark.py`，且不包含 `.tools`、`.state`、CA 或捕获结果。

## 首次发布

首次发布需要有权注册 `reslark` 的 npm 账号，并完成 npm 要求的认证/二次验证。仓库创建者身份不等于 npm 账号身份。先检查包名仍可用，再由发布者执行：

```bash
npm login
npm publish --access public
```

此命令会执行 `prepublishOnly` 检查。发布动作不可由 `npm pack` 或 GitHub 提交替代。

## 后续可信发布

仓库提供手动触发的 `publish.yml`，使用 GitHub Actions OIDC，不保存长期 npm token。

1. 首次发布后，在 npm 包设置中添加 GitHub trusted publisher：owner `huhuanming`、repo `reslark`、workflow `publish.yml`、environment `npm`。
2. 在 GitHub 配置 `npm` environment，可按需设置发布审批。
3. 更新版本并提交，创建与 package.json 一致的 `vVERSION` tag，推送 tag。
4. 对该 tag 手动运行 `Publish npm`。工作流验证 tag 与包版本，运行检查后发布 provenance。

```bash
gh workflow run publish.yml --ref v0.1.1
```

首次发布前无法把未创建的 npm 包的 trusted publisher 配置当作已经可用。具体要求以 [npm 官方可信发布文档](https://docs.npmjs.com/trusted-publishers/) 为准。
