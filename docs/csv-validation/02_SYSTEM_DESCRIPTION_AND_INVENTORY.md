# CSV-02 系统说明与受控清单

## 1. 预定用途

本系统用于药品批发场景中的质量主数据、采购收货验收、批号库存、销售出库、运输签收、销后退回、不合格品处置、购进退出、召回、养护、盘点、质量体系和相关电子记录管理。系统通过阻断规则、职责分离、电子签名和审计追踪，支持企业执行经批准的 GSP 流程。

系统本身不自动证明企业合规；企业必须配置实际经营范围、角色、文件、阈值、设备、接口和 SOP，并完成本文件体系规定的验证和放行。

## 2. 技术架构

| 层级 | 组件 | 受控内容 | 验证关注点 |
|---|---|---|---|
| 客户端 | 独立 SPA 前端 | 菜单、分页、排序、岗位按钮、错误提示 | 浏览器兼容、越权不能仅靠隐藏按钮 |
| API | FastAPI `0.18.1` | `/api/gsp` 及子路由、兼容 WMS 路由 | 请求校验、状态机、权限、事务 |
| 业务层 | `app/gsp/` | 质量规则、服务、状态转换 | 正/负向、边界、并发、失败回滚 |
| 数据层 | SQLAlchemy/PostgreSQL | 72 个 `gsp_` 表、约束、索引、行锁 | 完整性、唯一性、并发和不可删除性 |
| 迁移 | Alembic | 30 个 revision 文件，head `20260902_29` | 空库和旧库升级、check、不可变迁移 |
| 身份 | 本地账号/LDAP | 认证、再认证、岗位与仓库授权 | 唯一账号、TLS、停用、锁定、职责分离 |
| 审计/签名 | 哈希链记录 | before/after、原因、签署含义、请求摘要 | 追加性、篡改发现、时间、可归属性 |
| 运维 | systemd、反向代理、备份脚本 | 服务、日志、备份、恢复、秘密版本 | 可用性、保留、告警、恢复能力 |

## 3. 后端模块清单

| 模块 | 路由前缀 | 主要功能 | 实现路径 |
|---|---|---|---|
| GSP 核心 | `/api/gsp` | 角色、合作方、产品、批次、质量锁定、追溯、审计 | `app/gsp/router.py` |
| 采购收货 | `/api/gsp` | 采购订单、收货、抽样、验收 | `app/gsp/procurement_receiving/` |
| 不合格品 | `/api/gsp` | 不合格登记、驳回、销毁、购进退出 | `app/gsp/quality_disposition/` |
| 质量体系 | `/api/gsp/quality-system` | 评审、风险、事件、CAPA、培训、受控文件、设备 | `app/gsp/quality_system/` |
| 销售发运 | `/api/gsp` | 销售审批、FEFO、拣货、复核、发运 | `app/gsp/sales_shipping/` |
| 退货召回 | `/api/gsp` | 销退隔离检验、召回、召回演练 | `app/gsp/returns_recalls/` |
| 药品养护 | `/api/gsp/maintenance` | 养护计划、检查、异常、近效期 | `app/gsp/maintenance/` |
| 批号盘点 | `/api/gsp/stocktaking` | 盲盘、差异复核、批准调整 | `app/gsp/stocktaking/` |
| 运维合规 | `/api/gsp/operations` | 秘密轮换、备份证据、恢复演练 | `app/gsp/operations/` |
| 运输签收 | `/api/gsp/transport` | 承运资质、运输任务、异常、签收 | `app/gsp/transport/` |
| 环境监测 | `/api/gsp/environment` | 设备、分配、读数、告警、哈希链 | `app/gsp/environment/` |
| 电子签名 | `/api/gsp/electronic-signatures` | 再认证、挑战、令牌、签名链 | `app/gsp/electronic_signature/` |
| 集成出站箱 | `/api/gsp/integration` | 幂等消息、重试、死信 | `app/gsp/integration_router.py`、`outbox.py` |
| 历史归档 | `/api/gsp/legacy-archive` | 迁移批次、摘要、核对、只读查询/导出 | `app/gsp/legacy_archive/` |

## 4. 健康和生产门禁

- `/health`：进程响应和版本；
- `/health/live`：存活探针；
- `/health/ready`：数据库连通、实际/预期 schema revision、LDAP 传输模式和安全警告；
- 生产模式禁止 SQLite、弱 JWT、自动建表、缺少秘密来源/版本引用；
- LDAP SSL 与 StartTLS 互斥；普通 389 必须显式风险开关；加密模式必须验证证书。

## 5. 角色清单

系统定义 18 个 GSP 岗位：`AUDITOR`、`DISPATCHER`、`ENVIRONMENT_MONITOR`、`INSPECTOR`、`MAINTENANCE`、`OUTBOUND_REVIEWER`、`PICKER`、`PROCUREMENT`、`QUALITY_MANAGER`、`QUALITY_REVIEWER`、`RECEIVER`、`RETURNS_RECEIVER`、`SALES`、`STOCKTAKE`、`SYSTEM_ADMIN`、`TRANSPORT_COORDINATOR`、`WAREHOUSE_CUSTODIAN`、`WAREHOUSE_MANAGER`。

实际授权必须同时考虑岗位冲突、有效期、复核日期、仓库范围、用户启用状态和业务记录上的自批限制，详见 CSV-11 和权限矩阵。

## 6. 关键数据域

| 数据域 | 系统事实来源 | 关键完整性要求 |
|---|---|---|
| 合作方/品种授权 | GSP 主数据 | 独立核验、批准、有效期、暂停后实时阻断 |
| 批次库存 | `gsp_batch_stock` | 批号、有效期、数量、预留、状态、并发版本 |
| 业务单据 | 各 GSP 业务表 | 唯一编号、状态机、人员和时间、取消不删历史 |
| 质量锁定 | `gsp_quality_holds` | 活动锁与批次状态一致，解除前重新校验 |
| 审计事件 | GSP 审计表 | before/after、原因、来源 IP、前向哈希链 |
| 电子签名 | 签名挑战和签名记录 | 身份快照、含义、对象、请求摘要、单次令牌 |
| 温湿度读数 | 环境读数表 | 来源幂等键、原始载荷摘要、前向哈希链 |
| 历史归档 | legacy archive | 源包摘要、记录数量、独立核对、只读 |
| 备份证据 | operations 表 | 文件哈希、位置、时间、结果、独立复核 |

## 7. 软件清单与自动化覆盖

当前基线有 72 个 `test_` 自动化测试函数，覆盖认证、权限、配置、采购收货、销售发运、退货召回、不合格品、供应商品种授权、质量体系、养护、盘点、运输、环境监测、电子签名、审计、出站箱、历史归档和运维治理。正式执行时必须保存测试收集列表与结果，不能只记录“测试通过”。

## 8. 外部依赖和数据流

| 外部对象 | 当前状态 | 输入/输出 | 控制 |
|---|---|---|---|
| LDAP/AD | 可配置 | 账号认证、身份属性 | TLS/风险批准、唯一账号、停用同步 |
| PostgreSQL | 已使用 | 全部受控记录 | 事务、约束、迁移、备份恢复 |
| 前端仓库 | 独立 | API 请求、展示和导出 | SHA 冻结、CORS、岗位 UI 验证 |
| 九州通 | 暂缓 | 订单/库存/状态消息 | 出站箱预留；正式协议未验证 |
| 温湿度网关 | 暂缓 | 设备读数和告警 | 内部逻辑可测；真实网关未验证 |
| 药品追溯平台 | 暂缓 | 追溯码采集/核销/报送 | 数据字段和阻断；正式对接未验证 |
