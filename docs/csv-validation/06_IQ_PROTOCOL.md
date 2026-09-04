# CSV-06 安装确认方案（IQ）

## 1. 目的与进入条件

确认批准的软件、数据库、配置、网络、身份、时间、日志、备份和安全控制正确安装。执行前必须批准 VP/URS/RA/FS/DS、冻结基线、校验备份并准备回退。

详细执行行见 `records/iq_test_cases.csv`。每一步必须记录原始命令、完整输出、执行时间、执行人和证据 SHA-256；不得仅填写“正常”。

## 2. 环境标识

| 项目 | 实际值 | 证据 |
|---|---|---|
| 环境用途（TEST/UAT/PROD） |  |  |
| 主机名/IP |  |  |
| OS/内核/补丁 |  |  |
| CPU/内存/磁盘/文件系统 |  |  |
| PostgreSQL 版本/实例/数据库 |  |  |
| Python/依赖锁定 |  |  |
| 后端 commit |  |  |
| 前端 commit/build |  |  |
| Alembic revision |  |  |
| 反向代理/证书 |  |  |
| NTP 源/时区 |  |  |

## 3. 关键执行命令基线

以下为最小命令示例；执行人应按批准部署路径调整并保留输出。

```bash
git rev-parse HEAD
python --version
python -m pip freeze
psql --version
alembic current
alembic heads
alembic check
curl -fsS http://127.0.0.1:<port>/health/ready
timedatectl status
systemctl status <wms-service>
systemctl status <backup-timer>
```

禁止在证据中直接输出 `DATABASE_URL`、`SECRET_KEY`、LDAP 密码、Token 或私钥。配置证据仅显示键名、脱敏值、来源和版本引用。

## 4. 数据库升级路径

### 4.1 空库

创建独立空测试库，执行 `alembic upgrade head`，确认达到 `20260902_29`，随后执行 `alembic check`。保存迁移日志、表/约束/索引清单和失败返回码。

### 4.2 历史库

从批准的迁移前备份恢复到隔离测试库，确认原 revision 和源文件 SHA-256，再升级至 head。至少核对：用户、仓库、商品、合作方、批次库存、采购/销售/退货/质量记录、审计事件数量；抽样比较关键字段；验证活动 NC 不重复。

### 4.3 PR #32 结构专项

确认 `ix_gsp_purchase_return_items_nonconforming_record_id` 存在且不是 UNIQUE；确认取消/驳回人员字段的 4 个外键存在；确认模型与迁移无漂移。不得修改已经执行的 revision 以消除漂移。

## 5. 安全与服务安装

- 服务使用非特权专用账号，应用目录和配置权限按最小权限设置；
- 数据库账号仅拥有应用所需权限；迁移账号按 SOP 单独使用；
- TLS 证书、反向代理、CORS、上传大小、超时和安全头按批准值配置；
- 日志目录、轮转、容量、保留和访问权限已配置；
- 生产 `AUTO_CREATE_SCHEMA=false`，秘密来自批准来源；
- `/health/ready` 在数据库断开或 revision 不符时返回失败；
- 自动启动和受控重启不会绕过迁移或丢失数据。

## 6. IQ 接受标准

所有 Critical 行通过；High 行通过或有质量批准的临时控制和偏差；无敏感信息泄漏；空库与历史库升级路径均成功；服务、健康、时间、日志和备份准备满足批准基线。IQ 完成前不得开始依赖该控制的 OQ。

## 7. IQ 结论

| 结论项 | 内容 |
|---|---|
| 执行批次 |  |
| 通过/失败/阻塞 |  |
| 偏差 |  |
| 是否允许进入 OQ |  |
| 执行人/日期 |  |
| 独立复核人/日期 |  |
| 质量批准/日期 |  |
