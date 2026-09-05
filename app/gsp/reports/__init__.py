"""Business reports with controlled printing (P1).

Each report explicitly declares its output columns (label order) and the GSP
roles allowed to view it; no raw ORM introspection reaches the output, so new
schema columns can never silently leak into a controlled template.  Queries
are paginated (fixed id-desc order, offset, total, has_more).  Prints persist
the full rendered HTML and the normalised rows inside the record snapshot so a
previously issued print can be reproduced and its hash re-verified even after
source data changes.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from app.gsp.electronic_signature.models import GspElectronicSignature
from app.gsp.environment.models import GspEnvironmentAlarm
from app.gsp.models import (
    GspAuditEvent,
    GspBatchStock,
    GspQualityHold,
)
from app.gsp.procurement_receiving.models import GspControlledPrintRecord

PRINT_TEMPLATE_VERSION = "reports-v1"

# GSP roles allowed to view sensitive ledgers; empty tuple => any GSP role.
_ROLES_QUALITY = ("AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER", "SYSTEM_ADMIN")


class ReportDefinition:
    def __init__(
        self,
        key: str,
        title: str,
        desc: str,
        entity,
        columns: dict[str, str],
        filters: tuple[str, ...] = (),
        roles: tuple[str, ...] = (),
        template_version: str = "v1",
    ):
        self.key = key
        self.title = title
        self.desc = desc
        self.entity = entity
        #: ordered dict attribute -> human label (explicit, versioned output)
        self.columns = columns
        self.filters = filters
        self.roles = roles
        self.template_version = template_version

    def allowed_for(self, roles: set[str]) -> bool:
        if not self.roles:
            return bool(roles)
        return bool(self.roles and roles.intersection(self.roles))


REPORTS: list[ReportDefinition] = [
    ReportDefinition(
        "batch_stock_ledger", "批号库存台账", "批号-仓位数量/预留/质量状态",
        GspBatchStock,
        {
            "id": "ID", "batch_id": "批号ID", "warehouse_id": "仓库ID",
            "location_id": "库位ID", "quantity": "数量", "reserved_quantity": "预留",
            "stock_status": "质量状态", "updated_at": "更新时间",
        },
        filters=("stock_status",),
    ),
    ReportDefinition(
        "electronic_signature_ledger", "电子签名台账", "电子签名记录（敏感，限质量/AUDITOR）",
        GspElectronicSignature,
        {
            "id": "ID", "signature_ref": "签名引用", "signer_username": "操作人",
            "signer_full_name": "姓名", "meaning": "签名含义", "action": "动作",
            "entity_type": "对象类型", "entity_id": "对象ID", "reason": "原因",
        },
        filters=("meaning", "action"),
        roles=_ROLES_QUALITY,
    ),
    ReportDefinition(
        "environment_alarm_ledger", "温湿度超限告警台账", "温湿度告警（类型/级别/状态过滤）",
        GspEnvironmentAlarm,
        {
            "id": "ID", "alarm_no": "告警编号", "assignment_id": "监测点ID",
            "reading_id": "读数ID", "alarm_type": "类型", "severity": "级别",
            "status": "状态", "observed_value": "观测值",
        },
        filters=("alarm_type", "severity", "status"),
    ),
    ReportDefinition(
        "quality_hold_ledger", "质量锁定台账", "批号质量锁定记录",
        GspQualityHold,
        {"id": "ID", "batch_id": "批号ID", "reason_code": "原因码"},
    ),
    ReportDefinition(
        "audit_event_ledger", "审计事件台账", "哈希链审计事件（敏感，限质量/AUDITOR）",
        GspAuditEvent,
        {
            "id": "ID", "actor_user_id": "操作人ID", "action": "动作",
            "entity_type": "对象类型", "entity_id": "对象ID", "reason": "原因",
            "occurred_at": "时间",
        },
        filters=("action",),
        roles=_ROLES_QUALITY,
    ),
]

_REPORT_MAP = {r.key: r for r in REPORTS}
MAX_ROWS = 10000  # absolute cap when a print is requested to cover all matches


def report_catalog() -> list[dict]:
    return [
        {
            "key": r.key,
            "title": r.title,
            "desc": r.desc,
            "columns": list(r.columns.values()),
            "template_version": r.template_version,
            "roles": list(r.roles) or None,
        }
        for r in REPORTS
    ]


def _jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


class ReportError(ValueError):
    pass


def _page_query(db: Session, report: ReportDefinition, filters: dict[str, str], limit: int, offset: int):
    query = db.query(report.entity)
    for name, value in filters.items():
        if name not in report.filters:
            raise ReportError(
                f"不支持的过滤条件：{name}（{report.key} 仅支持 {', '.join(report.filters) or '无'}）"
            )
        query = query.filter(getattr(report.entity, name) == value)
    total = query.count()
    rows = query.order_by(report.entity.id.desc()).offset(offset).limit(limit).all()
    return total, rows


def run_report(
    db: Session,
    key: str,
    filters: dict | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    report = _REPORT_MAP.get(key)
    if report is None:
        raise KeyError(key)
    filters = {str(k): str(v).strip() for k, v in (filters or {}).items() if v not in (None, "")}
    total, rows = _page_query(db, report, filters, limit=limit, offset=offset)
    data = [{attr: _jsonable(getattr(row, attr)) for attr in report.columns} for row in rows]
    count = len(data)
    return {
        "key": key,
        "title": report.title,
        "columns": list(report.columns.values()),
        "row_keys": list(report.columns.keys()),
        "count": count,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + count < total,
        "rows": data,
        "filters": filters,
    }


def render_printable_html(result: dict, generated_by: str, reason: str, truncated: bool) -> str:
    columns = result["columns"]
    row_keys = result.get("row_keys", columns)
    header = "".join(f"<th>{_esc_html(c)}</th>" for c in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc_html(d.get(k))}</td>" for k in row_keys) + "</tr>"
        for d in result["rows"]
    )
    if not result["rows"]:
        body = f'<tr><td colspan="{max(len(columns), 1)}">暂无数据</td></tr>'
    note = (
        f"<p class='warn'>⚠ 本打印仅含第 {result['offset'] + 1}–{result['offset'] + len(result['rows'])} "
        f"行（共 {result['total']} 行），存在未包含记录。</p>"
        if truncated
        else ""
    )
    now = datetime.now().isoformat(timespec="seconds")
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{_esc_html(result['title'])}</title>
<style>
body{{font-family:"Microsoft YaHei",Arial,sans-serif;margin:24px;color:#111}}
h1{{font-size:20px}} h2{{font-size:13px;font-weight:normal;color:#444}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th,td{{border:1px solid #999;padding:4px 6px;text-align:left}}
th{{background:#eef2f7}} .warn{{color:#b00}} .foot{{margin-top:12px;font-size:11px;color:#555}}
</style></head><body>
<h1>{_esc_html(result['title'])}</h1>
<h2>生成时间 {_esc_html(now)} · 打印人 {_esc_html(generated_by)} · 原因 {_esc_html(reason)}</h2>
<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>
{note}
<div class="foot">受控打印（REPORT:{_esc_html(result['key'])}）共 {result['total']} 行，本页 {len(result['rows'])} 行；本内容哈希见打印记录。</div>
</body></html>"""


def _esc_html(value) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def record_print(
    db: Session,
    *,
    key: str,
    content_html: str,
    result: dict,
    printed_by: int,
    purpose: str,
    cover_all: bool,
) -> GspControlledPrintRecord:
    content_hash = hashlib.sha256(content_html.encode("utf-8")).hexdigest()
    record = GspControlledPrintRecord(
        document_type=f"REPORT:{key}",
        entity_id=0,
        template_version=PRINT_TEMPLATE_VERSION,
        copy_no=f"RPT-{key[:8].upper()}-{uuid.uuid4().hex[:12].upper()}",
        purpose=purpose,
        status="GENERATED",
        snapshot_data={
            "report_key": key,
            "title": result["title"],
            "columns": result["columns"],
            "filters": result["filters"],
            "offset": result["offset"],
            "limit": result["limit"],
            "count": result["count"],
            "total": result["total"],
            "truncated": result["has_more"] and not cover_all,
            "cover_all": cover_all,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "rows": result["rows"],
            "html": content_html,
        },
        content_hash=content_hash,
        printed_by=printed_by,
    )
    db.add(record)
    db.flush()
    return record


def verify_record_content(record: GspControlledPrintRecord) -> bool:
    """Recompute the hash from the persisted artifact and compare."""
    if not record.snapshot_data:
        return False
    html = record.snapshot_data.get("html") or ""
    return hashlib.sha256(html.encode("utf-8")).hexdigest() == (record.content_hash or "")


def run_full_print_rows(db: Session, key: str, filters: dict | None) -> dict:
    """All matching rows (paged internally, hard capped) for a full print."""
    filters = {str(k): str(v).strip() for k, v in (filters or {}).items() if v not in (None, "")}
    report = _REPORT_MAP.get(key)
    if report is None:
        raise KeyError(key)
    page_size = 500
    merged = []
    offset = 0
    total = None
    while True:
        page_total, rows = _page_query(db, report, filters, limit=page_size, offset=offset)
        if total is None:
            total = page_total
        merged.extend(rows)
        offset += len(rows)
        if not rows or offset >= total or len(merged) >= MAX_ROWS:
            break
    cover_all = len(merged) < MAX_ROWS
    data = [{attr: _jsonable(getattr(row, attr)) for attr in report.columns} for row in merged]
    return {
        "key": key,
        "title": report.title,
        "columns": list(report.columns.values()),
        "row_keys": list(report.columns.keys()),
        "count": len(data),
        "total": total or len(data),
        "offset": 0,
        "limit": len(data),
        "has_more": not cover_all,
        "rows": data,
        "filters": filters,
    }
