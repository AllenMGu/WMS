# CSV-05 功能与设计规格（FS/DS）

## 1. 设计原则

- GSP 质量域拥有药品质量属性、批准、质量锁定和批号库存规则；旧 WMS 接口不得绕过。
- 所有受控状态转换在后端校验，前端按钮隐藏仅作为可用性控制。
- 关键业务使用数据库事务、外键、唯一/检查约束和行锁；失败必须整体回滚。
- 取消和驳回保留单据及明细；审计和签名记录只追加。
- 外部集成使用出站箱，不把外部响应直接作为库存事实来源。

## 2. 状态机规格

| 对象 | 允许状态主链 | 关键禁止项 |
|---|---|---|
| 采购单 | `DRAFT→SUBMITTED→APPROVED→PARTIALLY_RECEIVED/RECEIVED→COMPLETED` | 草稿不能质量驳回；非质量人员不能批准/驳回 |
| 销售单 | `DRAFT→SUBMITTED→APPROVED→ALLOCATED→PICKED→PREPARED→REVIEWED→SHIPPED` | 不得跳步；库存不足不得部分预留 |
| 销后退回 | `PENDING_INSPECTION→PARTIALLY_INSPECTED→COMPLETED` | 待检数量不能成为可用库存 |
| 不合格品 | `PENDING_APPROVAL→APPROVED→DISPOSITIONED` 或 `REJECTED` | 登记人不得审批/驳回 |
| 购进退出 | `DRAFT→SUBMITTED→APPROVED→SHIPPED` 或 `CANCELLED/REJECTED` | 同一 NC 不得同时存在多个活动单；取消不删明细 |
| 召回 | `DRAFT→ACTIVE→CLOSED` | 未通知目标或非独立复核不得关闭 |
| 召回演练 | `DRAFT→ACTIVE→COMPLETED` | 不得建立真实锁定或发送真实通知 |
| 质量锁定 | `ACTIVE→RELEASED` | 最后锁定解除前必须重新核验放行条件 |
| 养护计划 | `DRAFT→SUBMITTED→APPROVED→IN_PROGRESS→COMPLETED` | 异常未处置不得完成 |
| 盘点 | `DRAFT→SUBMITTED→COUNTING→COUNTED→ADJUSTMENT_APPROVED→COMPLETED` | 基线已变化不得执行差异调整 |
| 运输 | `PREPARED→IN_TRANSIT→DELIVERED→CLOSED`；异常可到 `EXCEPTION` | 质量异常未决定、签收未复核不得关闭 |
| 秘密轮换 | `SUBMITTED→APPROVED→PENDING_VERIFICATION→VERIFIED/FAILED` | 申请/批准/实施/验证职责不得冲突 |
| 恢复演练 | `SUBMITTED→APPROVED→EXECUTED→VERIFIED` | 只允许使用独立复核为可接受的备份 |

## 3. 资格与实时阻断

采购创建、批准、收货和验收分别调用资格规则，确认供应商、合作方文件、供应商—品种授权和药品档案处于批准且有效状态。销售、分配、复核和发运分别核验购货方资质、批次放行、质量锁定、追溯要求和剩余有效期。检查必须在最终事务内重复进行，避免先检查后变更的竞态。

## 4. 批号库存与并发

| 控制 | 设计 |
|---|---|
| 正式入库来源 | 验收合格、销退检验合格、批准盘点调整 |
| 正式出库来源 | 发运、退供发运、监督销毁、批准盘点调整 |
| 预留 | 销售分配增加 `reserved_quantity`；取消或失败释放 |
| FEFO | 仅选择批准、未过期、未锁定且满足剩余效期的库存，按有效期排序 |
| 并发 | 对库存/NC 行加锁；使用 `lock_version` 或基线值检测变化 |
| 守恒 | 业务前后数量、预留、合格/拒收、退回/销毁数量必须可核对 |

## 5. 审计设计

审计事件至少保存：事件 ID、前一事件哈希、事件哈希、动作、实体类型/ID、执行用户、原因、before/after JSON、来源 IP、服务器时间。追加时采用数据库级链锁；验证功能应重算每个事件并返回首个断点。业务事务回滚时对应审计也必须回滚，避免孤立审计。

## 6. 电子签名设计

1. 用户针对确定的动作、对象、签名含义和请求正文重新输入本地/LDAP 凭据。
2. 系统生成 5 分钟有效、仅返回一次的挑战令牌，并保存请求摘要。
3. 受监管接口在同一事务中验证签署人、动作、对象、含义、摘要、到期和未使用状态。
4. 操作成功时消费令牌并创建签名链记录；业务失败时一并回滚。
5. 支持的签名含义必须含实际业务需要的 `APPROVAL`、`REJECTION` 等批准词汇。

## 7. 安全和配置设计

生产环境 `APP_ENV=production`、`AUTO_CREATE_SCHEMA=false`，使用 PostgreSQL；JWT、数据库和 LDAP 凭据从外部秘密来源注入并记录版本引用。禁止向日志打印口令、Token、连接串和请求头签名令牌。LDAP 模式为 LDAPS、StartTLS 或显式批准的普通 389，三者配置一致且互斥。

## 8. 数据库迁移设计

- Alembic 是受控环境唯一结构变更机制；head 为 `20260902_29`。
- 验证空库从 base 升级至 head，历史备份从其实际 revision 升级至 head。
- 每条路径执行 `alembic current` 和 `alembic check`。
- 校验 PR #32 的非唯一 `gsp_purchase_return_items.nonconforming_record_id` 索引和 4 个用户外键。
- 对升级前后表/约束/索引、关键记录数量、重复活动 NC 和审计链进行核对。

## 9. 实现追踪

| 控制 | 实现路径 | 现有自动化测试 |
|---|---|---|
| 岗位/冲突/停用 | `app/gsp/access_control.py` | `test_access_control.py` |
| 采购收货验收 | `app/gsp/procurement_receiving/` | `test_procurement_receiving.py`、`test_p0_merge_po.py` |
| 销售发运 | `app/gsp/sales_shipping/` | `test_sales_shipping.py` |
| 不合格/退供 | `app/gsp/quality_disposition/` | `test_quality_disposition.py`、`test_p0_merge_disposition.py` |
| 退货召回 | `app/gsp/returns_recalls/` | `test_returns_recalls.py` |
| 养护/效期 | `app/gsp/maintenance/`、`rules.py` | `test_maintenance.py`、`test_expiry_controls.py` |
| 盘点 | `app/gsp/stocktaking/` | `test_stocktaking.py` |
| 运输 | `app/gsp/transport/` | `test_transport.py` |
| 环境 | `app/gsp/environment/` | `test_environment_monitoring.py` |
| 电子签名 | `app/gsp/electronic_signature/` | `test_electronic_signatures.py` |
| 质量体系 | `app/gsp/quality_system/` | `test_quality_system.py`、`test_quality_system_access.py` |
| 备份恢复/秘密 | `app/gsp/operations/`、`scripts/` | `test_operations_governance.py` |
| 历史归档 | `app/gsp/legacy_archive/` | `test_legacy_archive.py` |
| 出站箱 | `app/gsp/outbox.py` | `test_outbox_governance.py` |

## 10. 已知设计边界

前端、生产部署配置和外部适配器位于本仓库之外；本规格仅以接口契约描述其要求。真实温湿度采集、九州通和药品追溯平台不得因为内部数据模型存在而被宣称已验证。
