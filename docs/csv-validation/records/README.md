# 执行台账说明

本目录中的 CSV 是执行记录模板，编码为 UTF-8。首次执行前应由质量部门批准列结构和用例内容。

## 填写规则

- `result` 仅允许：`NOT_RUN`、`PASS`、`FAIL`、`BLOCKED`、`N/A`、`VOID`。
- `N/A` 必须填写批准的理由；`VOID` 必须关联偏差或更正记录。
- `actual_result` 写实际观察值，禁止只写“正常”“同预期”。
- `evidence_refs` 使用 CSV-00 的证据编号；多个编号用 `|` 分隔。
- 时间采用带时区 ISO 8601，例如 `2026-09-04T15:30:00+08:00`。
- 执行人和复核人必须不同；电子签名或审批引用不得用姓名文本替代。
- 不得删除失败行；复测新增一行到 `test_execution_log.csv` 并关联原执行和偏差。

## 文件

| 文件 | 用途 |
|---|---|
| `risk_assessment.csv` | 初始/残余风险、控制和验证引用 |
| `requirements_traceability_matrix.csv` | URS→风险→设计→测试→证据追踪 |
| `iq_test_cases.csv` | 安装确认详细步骤和记录字段 |
| `oq_test_cases.csv` | 运行确认正向、负向、边界、并发和恢复测试 |
| `pq_test_cases.csv` | 端到端业务场景和实际用户确认 |
| `role_permission_matrix.csv` | 岗位—能力—职责分离基线 |
| `data_migration_reconciliation.csv` | 数据迁移数量、字段、哈希和异常核对 |
| `evidence_index.csv` | 原始证据元数据和 SHA-256 |
| `test_execution_log.csv` | 每次执行/复测的独立记录 |
| `deviation_log.csv` | 偏差、根因、CAPA、复测和关闭 |
| `approval_log.csv` | 文件/方案/执行/VSR/放行审批 |
