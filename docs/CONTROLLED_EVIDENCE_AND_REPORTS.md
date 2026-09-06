# 受控附件与业务报表（P0/P1）说明

> 覆盖 2026-09 上线的“真实受控附件存储/业务绑定”与“业务报表/受控打印”两组能力。
> 代码位于 `app/gsp/attachments/` 与 `app/gsp/reports/`。

## 1. 受控附件（GSP 受控文件）

历史问题：资质/授权/注册/承运文件只保存客户端填写的 `file_ref` + SHA-256 + 大小，后端无真实文件，
引用与哈希可任意伪造（2026-09-05 代码审核 P0）。

### 能力

- **服务端上传与哈希**：`POST /api/gsp/files`（multipart）流式落盘并计算 SHA-256；
- **不可变内容寻址存储**：`<ATTACHMENT_DIR>/<sha256[:2]>/<sha256>`，相同内容去重，对象不可覆盖；
- **文件类型服务端识别**：PDF/JPEG/PNG/WebP/OLE2(.doc/.xls 按流名区分，经 olefile 校验)/
  OOXML(docx/xlsx 由 zipfile+Content_Types XML 真读)/ZIP/CSV/TXT；声明与内容不符即 422；
- **引用令牌**：`gspf:<32hex>`；业务记录绑定前必须解析到 ACTIVE 对象且 purpose 匹配（或 OTHER），
  服务端 sha/大小覆盖客户端值；
- **策略 `ATTACHMENT_POLICY`**：`warn`（默认，兼容旧引用）| `enforce`（非令牌引用 422）；
  每次读取校验，值非法即拒绝/阻止启动（fail closed）；
- **下载前完整性校验**：返回字节前重算 size+SHA，篡改→410；
- **停用（唯一生命周期）**：质量经理可停任意；上传人仅可停**未被任何业务记录引用**的自身文件
  （引用检查与停用同一事务并加行锁 `FOR UPDATE`）；停用幂等，不删除字节；
- **审计**：FILE_UPLOADED/DOWNLOADED/VERIFIED/INTEGRITY_LOST/DISABLED 全部入哈希链。

### 绑定范围（均存服务端真值）

| 业务记录 | 字段 |
|---|---|
| 合作方资质文件 | `file_ref/file_sha256/file_size_bytes` |
| 供应商-品种授权（单条 + bulk-import） | `authorization_ref/_sha256/_size_bytes` |
| 品种质量档案（注册文件） | `registration_document_ref/_sha256/_size_bytes` |
| 承运商文件 | `file_ref/file_sha256/file_size_bytes`（迁移 `20260905_31` 加列） |

### 端点

- `POST /api/gsp/files`（上传，返回 ref/sha256/size/content_type）
- `GET  /api/gsp/files/{object_key}`、`GET /{object_key}/content`、`POST /{object_key}/verify`、
  `POST /{object_key}/disable`
- 前端（WMS-frontend）`uploadControlledFile()/bindControlledFileInput()`：选文件→上传→自动填引用；
  弹窗关闭（footer/×/遮罩）走 guarded close，未绑定对象自动停用。

### 配置

```dotenv
ATTACHMENT_DIR=./attachment-store        # 生产建议显式绝对路径并纳入备份
ATTACHMENT_MAX_BYTES=52428800
ATTACHMENT_POLICY=warn                    # 生产闭环后建议 enforce
```

## 2. 业务报表与受控打印

通用报表框架：每张报表显式声明输出列与允许岗位（不做 ORM 全列内省，防敏感列/新列泄漏），
正式/开发预览两级交付。

### 首批报表

- 正式：`electronic_signature_ledger`（电子签名台账）、`audit_event_ledger`（审计事件台账）
  —— 均限 AUDITOR/质量角色；
- 开发预览（`production_ready=false`，待补充业务可读关联字段的下一批次）：
  `batch_stock_ledger` / `environment_alarm_ledger` / `quality_hold_ledger`。

### 端点

- `GET /api/gsp/reports`：仅返回当前用户可见报表（含 production_ready/roles/模板版本）
- `GET /api/gsp/reports/{key}?limit=&offset=`：allow-list 过滤（未知条件 422），分页
  `offset/limit/total/has_more`
- `POST /api/gsp/reports/{key}/print`：
  - 正式报表→受控打印；预览报表需显式 `preview=true`（否则 409）
  - `cover_all=true` 单条 SELECT（MAX_ROWS+1）全量（超上限 422）
  - 先生成 `copy_no`（`RPT-`/`PREVIEW-`）再渲染：HTML 内嵌编号/模板版本/过滤/范围；
    预览件含每页水印“开发预览—非受控”与条件化页脚
- `GET /api/gsp/reports/prints/list`：SQL 层可见性过滤后再分页（items/total/has_more）
- `GET /api/gsp/reports/prints/{id}`、`POST /api/gsp/reports/prints/{id}/verify`：取回/校验

### 快照与哈希

打印记录持久化到 `gsp_controlled_print_records`：snapshot 含完整 HTML、规范化行、
过滤/范围/版本/编号/是否截断/cover_all/preview/as-of 边界与 `generated_at`；
`content_hash = sha256(canonical 全量受控字段)`，verify 同时比对外层字段
（document_type/template_version/copy_no/purpose/printed_by）——任何受控字段被改即校验失败。

### 审计

正式打印 `REPORT_PRINTED`、开发预览 `REPORT_PREVIEW_PRINTED`，均写实体/原因/哈希。

## 3. 前端

WMS-frontend：NAV“系统与合规 → 业务报表”报表中心页（目录→分页查询→受控打印/生成开发预览件→
打印/校验→打印记录台账）；资质/授权/注册/承运四表单均支持受控上传（common.js 助手 + guarded close）。

## 4. 测试与证据

- 后端：`tests/test_controlled_files*.py`、`test_reports*.py`（角色矩阵、分页、未知过滤 422、
  预览/正式区分、快照不可变与逐字段篡改、PG 集成）——全套 123 passed（+1 PG-skip），CI 双 job 绿；
- 前端：`scripts/behavior-controlled-upload.test.mjs`（9 场景）、`scripts/behavior-reports.test.mjs`
  （结构回归）随 `validate.mjs` 执行；
- 部署证据：服务器 `/opt/wms-evidence/deploy-*-20260905/`（execution_summary + 截图 + sha256 清单）。
