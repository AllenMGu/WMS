# 仓库拆分说明

[中文](REPOSITORY_SPLIT.md) | [English](REPOSITORY_SPLIT.en.md)

## 目标结构

| 仓库 | 职责 | 发布单元 |
| --- | --- | --- |
| [`AllenMGu/WMS`](https://github.com/AllenMGu/WMS) | FastAPI 后端、GSP 质量域、数据库迁移、测试、运维与验证资料 | Python API 服务 |
| [`AllenMGu/WMS-frontend`](https://github.com/AllenMGu/WMS-frontend) | 兼容期通用 WMS Web 界面 | 静态站点或反向代理静态目录 |
| [`AllenMGu/WMS-miniprogram`](https://github.com/AllenMGu/WMS-miniprogram) | 微信扫码、库存和单据作业客户端 | 微信小程序版本 |

## 历史与版本关系

- 两个客户端从原仓库对应子目录生成独立基线快照；拆分前的完整提交历史继续由本仓库保留。
- 拆分源基线为后端 `main` 提交 `6139b3e53eb6e80e52a3922afee1bc5d8bcfdc21`；Web 前端导入基线为 `62d9e0372245b511c3e57791adaa3d44dc175f83`，微信小程序导入基线为 `0c6238df229ff1b4254e774e9c14ae6f5bd655bb`。
- 客户端后续独立发版，不再通过复制目录回写后端仓库。
- API 契约变化必须在后端 Pull Request 中标明受影响的客户端，并分别提交客户端适配。

## 部署边界

Web 前端默认调用同源 `/api`。如果前端与后端使用不同 Origin，必须同时：

1. 在前端 `config.js` 设置完整后端地址，例如 `https://wms-api.example.com/api`；
2. 在后端 `ALLOWED_ORIGINS` 中登记前端完整 Origin；
3. 验证登录、令牌过期、导入导出、扫码和浏览器预检请求。

微信小程序在 `app.js` 设置 `apiBaseUrl`，并在微信公众平台登记合法 HTTPS 请求域名。

## 变更控制

生产变更应分别记录三个仓库的不可变提交 SHA。涉及同一业务发布时，发布记录至少包含：

- 后端提交 SHA 与数据库迁移版本；
- Web 前端提交 SHA；
- 小程序提交 SHA 与微信版本号；
- API 契约兼容性和回滚组合；
- 对应测试、审批和部署证据引用。

九州通正式适配器仍属于后端外部集成域，是当前明确排除的后续工作；取得正式接口规范和测试环境后再实施。
