"""Business reports with controlled printing (P1).

Report definitions are declarative: each report binds to one core table plus
optional allow-listed filters.  Rows are rendered generically from the actual
ORM columns (introspection), so schema additions cannot break a report.  Every
print is captured into ``gsp_controlled_print_records`` (immutable snapshot +
content hash + auditor) and written to the audit chain.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import inspect
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


class ReportDefinition:
    def __init__(self, key: str, title: str, desc: str, entity, filters: tuple[str, ...] = ()):
        self.key = key
        self.title = title
        self.desc = desc
        self.entity = entity
        self.filters = filters  # allow-listed filter column names


REPORTS: list[ReportDefinition] = [
    ReportDefinition(
        "batch_stock_ledger",
        "批号库存台账",
        "批号-仓位数量/预留/质量状态（可按质量状态过滤）",
        GspBatchStock,
        ("stock_status",),
    ),
    ReportDefinition(
        "electronic_signature_ledger",
        "电子签名台账",
        "电子签名记录（含义/动作/对象可过滤）",
        GspElectronicSignature,
        ("meaning", "action"),
    ),
    ReportDefinition(
        "environment_alarm_ledger",
        "温湿度超限告警台账",
        "温湿度监测告警（类型/级别/状态可过滤）",
        GspEnvironmentAlarm,
        ("alarm_type", "severity", "status"),
    ),
    ReportDefinition(
        "quality_hold_ledger",
        "质量锁定台账",
        "批号质量锁定记录",
        GspQualityHold,
        (),
    ),
    ReportDefinition(
        "audit_event_ledger",
        "审计事件台账",
        "哈希链审计事件（动作可过滤）",
        GspAuditEvent,
        ("action",),
    ),
]

_REPORT_MAP = {r.key: r for r in REPORTS}


def report_catalog() -> list[dict]:
    out = []
    for r in REPORTS:
        columns = [col.key for col in inspect(r.entity).columns if not col.key.startswith("_")]
        out.append({"key": r.key, "title": r.title, "desc": r.desc, "columns": columns})
    return out


def _jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def run_report(db: Session, key: str, filters: dict | None = None, limit: int = 200) -> dict:
    report = _REPORT_MAP.get(key)
    if report is None:
        raise KeyError(key)
    query = db.query(report.entity)
    filters = {str(k): str(v).strip() for k, v in (filters or {}).items() if v not in (None, "")}
    for name, value in filters.items():
        if name in report.filters:
            query = query.filter(getattr(report.entity, name) == value)
    rows = query.order_by(report.entity.id.desc()).limit(min(max(limit, 1), 1000)).all()
    columns = [col.key for col in inspect(report.entity).columns if not col.key.startswith("_")]
    data = [
        {col: _jsonable(getattr(row, col)) for col in columns}
        for row in rows
    ]
    return {"key": key, "title": report.title, "count": len(data), "rows": data, "filters": filters}


def render_printable_html(key: str, result: dict, generated_by: str, reason: str) -> str:
    """Self-contained printable HTML (no external assets) for a report."""
    rows = result["rows"]
    columns = list(rows[0].keys()) if rows else report_catalog_columns(key)
    def esc(v):
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def tr(d):
        return "<tr>" + "".join(f"<td>{esc(d.get(c, ''))}</td>" for c in columns) + "</tr>"

    head = "".join(f"<th>{esc(c)}</th>" for c in columns)
    body = "".join(tr(d) for d in rows) or '<tr><td colspan="%d">暂无数据</td></tr>' % max(len(columns), 1)
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{esc(result['title'])}</title>
<style>
body{{font-family:"Microsoft YaHei",Arial,sans-serif;margin:24px;color:#111}}
h1{{font-size:20px}} h2{{font-size:13px;font-weight:normal;color:#444}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th,td{{border:1px solid #999;padding:4px 6px;text-align:left}}
th{{background:#eef2f7}} .foot{{margin-top:12px;font-size:11px;color:#555}}
@media print{{.no-print{{display:none}}}}
</style></head><body>
<h1>{esc(result['title'])}</h1>
<h2>生成时间 {esc(datetime.now().isoformat(timespec='seconds'))} · 打印人 {esc(generated_by)} · 原因 {esc(reason)}</h2>
<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>
<div class="foot">受控打印（REPORT:{esc(result['key'])}）共 {len(rows)} 行；本页内容哈希见打印记录。</div>
</body></html>"""


def report_catalog_columns(key: str) -> list[str]:
    report = _REPORT_MAP[key]
    return [col.key for col in inspect(report.entity).columns if not col.key.startswith("_")]


def record_print(
    db: Session,
    *,
    key: str,
    content_html: str,
    result: dict,
    printed_by: int,
    purpose: str,
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
            "title": result.get("title"),
            "count": result.get("count"),
            "filters": result.get("filters"),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        content_hash=content_hash,
        printed_by=printed_by,
    )
    db.add(record)
    db.flush()
    return record
