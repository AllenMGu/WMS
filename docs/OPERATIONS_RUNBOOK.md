# 秘密、备份与恢复运维控制手册

[中文](OPERATIONS_RUNBOOK.md) | [English](OPERATIONS_RUNBOOK.en.md)

本文说明自 v0.9.0 起后端提供的运维合规控制。示例路径和时间不是企业 SOP；上线前必须由 IT、质量和
信息安全共同批准目标环境配置、保留期限、RTO/RPO、复核周期和告警升级路径。

## 1. 秘密管理

生产进程仍通过环境变量接收运行时值，但这些值必须由外部秘密管理服务、容器 Secret 或受控文件注入，
不得写入仓库、镜像、systemd Unit 或工单正文。生产启动至少配置：

```text
APP_ENV=production
SECRETS_PROVIDER=azure-key-vault
SECRET_KEY_VERSION_REF=kv://wms-gsp/jwt/version-id
DATABASE_CREDENTIAL_VERSION_REF=kv://wms-gsp/postgres/version-id
LDAP_CREDENTIAL_VERSION_REF=kv://wms-gsp/ldap/version-id
```

`*_VERSION_REF` 是非秘密版本标识，不能填入密码、令牌或连接串。LDAP 未使用绑定服务账号时可不设置
LDAP 版本引用。

LDAP 认证传输必须从以下互斥模式中选择一种：

| 模式 | 配置 | 说明 |
|---|---|---|
| LDAPS | `LDAP_USE_SSL=true` | 推荐方式，通常使用 636 端口并验证证书 |
| StartTLS | `LDAP_START_TLS=true` | 在 389 端口建立连接后、发送凭据前升级为 TLS |
| 普通 389 | `LDAP_ALLOW_PLAINTEXT_AUTH=true` | 仅限风险批准且网络隔离的受信环境，默认关闭 |

普通 389 启用后，就绪检查会返回 `LDAP_PLAINTEXT_AUTH_ENABLED` 警告。变更单必须记录风险接受、网络
隔离、访问控制和补偿措施。三个开关不得同时启用，绑定密码仍只能由外部秘密源注入。

轮换流程：

1. `SYSTEM_ADMIN` 提交版本引用、变更单和下次轮换日期。
2. `QUALITY_MANAGER` 或 `QUALITY_REVIEWER` 独立审批风险、回退和窗口。
3. 与审批人不同的 `SYSTEM_ADMIN` 在外部秘密管理服务中实施，只登记审计证据引用。
4. `AUDITOR` 或独立 `QUALITY_REVIEWER` 验证登录、会话、数据库/LDAP 连接与回退。
5. 失败时保持 `FAILED` 证据并按偏差流程处理；禁止覆盖原记录。

## 2. 每日备份

参考 systemd 文件位于 `deploy/systemd/`。部署时复制到 `/etc/systemd/system/`，并把脚本部署到
`/opt/wms-gsp/scripts/`。`/etc/wms-gsp/backup.env` 权限应为 `0600`，示例键如下：

```text
DATABASE_URL=<由秘密管理服务注入，不进入工单证据>
BACKUP_DIR=/var/backups/wms-gsp
OFFSITE_BACKUP_DIR=/mnt/wms-gsp-offsite
BACKUP_ALERT_DIR=/var/lib/wms-gsp/alerts
RETENTION_DAYS=90
```

`OFFSITE_BACKUP_DIR` 必须是不同故障域的挂载或同步落点，不能只是同一磁盘的另一个目录。脚本会：

- 使用 `pg_dump --format=custom` 生成备份；
- 使用 `pg_restore --list` 验证归档可读；
- 生成 SHA-256 并复制到异地目录后再次校验；
- 输出符合备份证据 API 的 JSON；
- 失败时在告警目录写入 `FAILED` JSON 标记。

脚本默认检查主备目录是否位于不同文件系统；`ALLOW_SAME_FILESYSTEM_FOR_TESTS=true` 只供临时测试，
生产配置不得启用。

必须由 Zabbix 或企业监控检查 systemd Unit 失败和告警目录新增文件，并将告警号写入
`alert_evidence_ref`。脚本不会自行删除备份；清理策略应由批准的不可变/保留锁策略执行，避免脚本错误
删除唯一可恢复副本。

启用后至少核对：

```bash
systemctl daemon-reload
systemctl enable --now wms-gsp-backup.timer
systemctl list-timers wms-gsp-backup.timer
systemctl start wms-gsp-backup.service
journalctl -u wms-gsp-backup.service
```

成功或失败 JSON 默认由备份任务直接登记到数据库；`REGISTER_BACKUP_EVIDENCE=false`
仅用于隔离恢复测试。自动登记失败时保留告警 JSON，管理员可补录到
`/api/gsp/operations/backups`，再由独立 `AUDITOR` 或
`QUALITY_REVIEWER` 复核。

## 3. 温湿度离线自动扫描

离线扫描只读取 WMS 自有监测分配和读数，不调用外部监测平台。部署
`wms-gsp-environment-scan.service` 与 `wms-gsp-environment-scan.timer` 后，每分钟检查一次
有效点位，并为超过批准离线阈值的点位生成唯一的未关闭告警。

运行前必须至少存在一个仍在复核期和有效期内的 `ENVIRONMENT_MONITOR` 岗位；定时任务使用该岗位
作为系统执行责任人写入审计追踪。无有效岗位时任务失败并写入 systemd 日志，不会绕过岗位控制。

```bash
systemctl daemon-reload
systemctl enable --now wms-gsp-environment-scan.timer
systemctl list-timers wms-gsp-environment-scan.timer
systemctl start wms-gsp-environment-scan.service
journalctl -u wms-gsp-environment-scan.service
```

必须由 Zabbix 或企业监控检查 Unit 失败，并按偏差流程处理连续扫描失败。

## 4. 近效期自动控制

先由质量岗位通过 `/api/gsp/compliance/settings/{setting_key}` 电子签名批准
`MAINTENANCE_SELECTION_DAYS`、`NEAR_EXPIRY_WARNING_DAYS` 和 `STOP_SALE_DAYS`。启用
`wms-gsp-expiry-scan.timer` 后每日扫描一次；达到停销阈值的批次会自动创建质量锁定并置为 `HOLD`。
任务需要有效的 `MAINTENANCE` 或 `QUALITY_MANAGER` 岗位。告警关闭必须保存处置证据并电子签名，且不会
自动解除质量锁定。

## 5. 数据库就绪与审计校验

生产服务启动前执行 `scripts/check_schema_revision.py`，`/health/ready` 同时检查数据库连接和 Alembic
版本。迁移必须在受控发布步骤中单独执行，API 服务不自动迁移。部署并启用
`wms-gsp-audit-verify.timer`，由有效 `AUDITOR` 或 `QUALITY_REVIEWER` 岗位生成每日验证证据。

## 6. 隔离恢复演练

恢复脚本拒绝非空目标库，并要求显式设置 `ALLOW_NON_PRODUCTION_RESTORE=true`。目标库必须是隔离的
一次性演练数据库；不得指向生产、灾备待机或包含现有数据的库。

```bash
BACKUP_FILE=/var/backups/wms-gsp/wms-gsp-YYYYMMDDTHHMMSSZ.dump \
CHECKSUM_FILE=/var/backups/wms-gsp/wms-gsp-YYYYMMDDTHHMMSSZ.dump.sha256 \
RESTORE_DATABASE_URL=<隔离空库连接串> \
RESTORE_TARGET_REF=drill://postgres/quarterly-YYYYQn \
RESTORE_EVIDENCE_DIR=/var/lib/wms-gsp/restore-evidence \
ALLOW_NON_PRODUCTION_RESTORE=true \
PYTHON_BIN=/opt/wms-gsp/.venv/bin/python \
/opt/wms-gsp/scripts/restore-drill-postgres.sh
```

脚本在恢复前校验 SHA-256 和归档目录，恢复后只读核对用户数、药品批次数、审计事件数及审计哈希链。
业务负责人还应按批准清单抽查采购、收货、库存、销售、召回和权限记录。API 中登记实际 RTO/RPO、
证据路径和 PASS/FAIL，并由申请人/执行人之外的人员验证。

## 7. 仍需目标环境完成的验收

- 外部秘密管理连接、服务身份和首次受控轮换；
- 真实异地或离线介质、不可变/保留锁和容量监控；
- systemd 定时器连续成功证据以及失败告警到达/升级测试；
- 实际温湿度网关、告警渠道和断网补传/时钟同步验证；
- 九州通正式适配器、联调、对账与失败重放验证；
- 首次完整恢复演练、关键业务抽查、RTO/RPO 结论和质量批准；
- SOP、权限矩阵、培训、变更记录和后续 CSV 文件包。
