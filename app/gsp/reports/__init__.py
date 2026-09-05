"""Business reports with controlled printing (P1, reviewed).

Design notes (per review):
* explicit, versioned output columns and per-report GSP role ACL;
* queries paginated (fixed id-desc, offset/total/has_more);
* ``cover_all`` reads by keyset (id cursor under the scanned max id) so a
  concurrent insert/delete cannot shift offsets; hard cap raises instead of
  silently truncating;
* the controlled number, report template version, filters and range/totals are
  generated *before* hashing and rendered into the printable HTML;
* the stored hash covers the complete normalised snapshot (html + rows +
  filters/range/version metadata), so tampering with any controlled field is
  detected by ``verify_record_content``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.gsp.electronic_signature.models import GspElectronicSignature
from app.gsp.environment.models import GspEnvironmentAlarm
from app.gsp.models import (
    GspAuditEvent,
    GspBatchStock,
    GspQualityHold,
)
from app.gsp.procurement_receiving.models import GspControlledPrintRecord

MAX_ROWS = 10000

_ROLES_QUALITY = ("AUDITOR", "QUALITY_MANAGER", "QUALITY_REVIEWER", "SYSTEM_ADMIN")


class ReportDefinition:
    def __init__(self, key, title, desc, entity, columns, filters=(), roles=(), template_version="v1", production_ready=True):
        self.key = key
        self.title = title
        self.desc = desc
        self.entity = entity
        self.columns = columns  # ordered attr -> label
        self.filters = tuple(filters)
        self.roles = tuple(roles)
        self.template_version = template_version
        self.production_ready = production_ready

    def allowed_for(self, roles):
        if not self.roles:
            return bool(roles)
        return bool(self.roles and roles.intersection(self.roles))


REPORTS: list[ReportDefinition] = [
    ReportDefinition(
        "batch_stock_ledger", "批号库存台账（开发预览）", "批号库存量/预留/质量状态；可读字段（物料/批号/仓库名）随下批报表补充",
        GspBatchStock,
        {"id": "ID", "batch_id": "批号ID", "warehouse_id": "仓库ID", "location_id": "库位ID",
         "quantity": "数量", "reserved_quantity": "预留", "stock_status": "质量状态", "updated_at": "更新时间"},
        filters=("stock_status",),
        production_ready=False,
    ),
    ReportDefinition(
        "electronic_signature_ledger", "电子签名台账", "电子签名记录（敏感，限质量/AUDITOR）",
        GspElectronicSignature,
        {"id": "ID", "signature_ref": "签名引用", "signer_username": "操作人", "signer_full_name": "姓名",
         "meaning": "签名含义", "action": "动作", "entity_type": "对象类型", "entity_id": "对象ID", "reason": "原因"},
        filters=("meaning", "action"),
        roles=_ROLES_QUALITY,
    ),
    ReportDefinition(
        "environment_alarm_ledger", "温湿度超限告警台账（开发预览）", "告警记录；监测点/设备可读字段随下批补充",
        GspEnvironmentAlarm,
        {"id": "ID", "alarm_no": "告警编号", "assignment_id": "监测点ID", "reading_id": "读数ID",
         "alarm_type": "类型", "severity": "级别", "status": "状态", "observed_value": "观测值"},
        filters=("alarm_type", "severity", "status"),
        production_ready=False,
    ),
    ReportDefinition(
        "quality_hold_ledger", "质量锁定台账（开发预览）", "批号质量锁定记录；可读字段随下批补充",
        GspQualityHold,
        {"id": "ID", "batch_id": "批号ID", "reason_code": "原因码"},
        production_ready=False,
    ),
    ReportDefinition(
        "audit_event_ledger", "审计事件台账", "哈希链审计事件（敏感，限质量/AUDITOR）",
        GspAuditEvent,
        {"id": "ID", "actor_user_id": "操作人ID", "action": "动作", "entity_type": "对象类型",
         "entity_id": "对象ID", "reason": "原因", "occurred_at": "时间"},
        filters=("action",),
        roles=_ROLES_QUALITY,
    ),
]

_REPORT_MAP = {r.key: r for r in REPORTS}


def report_catalog(visible_keys: set[str] | None = None) -> list[dict]:
    out = []
    for r in REPORTS:
        if visible_keys is not None and r.key not in visible_keys:
            continue
        out.append({
            "key": r.key, "title": r.title, "desc": r.desc,
            "columns": list(r.columns.values()),
            "template_version": r.template_version,
            "roles": list(r.roles) or None,
            "production_ready": r.production_ready,
        })
    return out


def visible_report_keys(user_roles: set[str]) -> set[str]:
    return {r.key for r in REPORTS if r.allowed_for(user_roles)}


def _jsonable(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


class ReportError(ValueError):
    pass


def _apply_filters(query, report: ReportDefinition, filters: dict[str, str]):
    for name, value in filters.items():
        if name not in report.filters:
            raise ReportError(f"不支持的过滤条件：{name}（{report.key} 仅支持 {', '.join(report.filters) or '无'}）")
        query = query.filter(getattr(report.entity, name) == value)
    return query


def run_report(db: Session, key: str, filters=None, limit: int = 200, offset: int = 0) -> dict:
    report = _REPORT_MAP.get(key)
    if report is None:
        raise KeyError(key)
    filters = {str(k): str(v).strip() for k, v in (filters or {}).items() if v not in (None, "")}
    query = _apply_filters(db.query(report.entity), report, filters)
    total = query.count()
    rows = query.order_by(report.entity.id.desc()).offset(offset).limit(limit).all()
    return _build_result(report, rows, total, offset, limit, filters)


def _build_result(report, rows, total, offset, limit, filters) -> dict:
    data = [{attr: _jsonable(getattr(row, attr)) for attr in report.columns} for row in rows]
    return {
        "key": report.key, "title": report.title,
        "columns": list(report.columns.values()), "row_keys": list(report.columns.keys()),
        "template_version": report.template_version,
        "count": len(data), "total": total, "offset": offset, "limit": limit,
        "has_more": offset + len(data) < total, "rows": data, "filters": filters,
    }


def run_full_print_rows(db: Session, key: str, filters=None) -> dict:
    """Keyset scan over the as-of max id (consistent within this transaction)."""
    report = _REPORT_MAP.get(key)
    if report is None:
        raise KeyError(key)
    filters = {str(k): str(v).strip() for k, v in (filters or {}).items() if v not in (None, "")}
    base = _apply_filters(db.query(report.entity), report, filters)
    total = base.count()
    max_id = db.query(func.max(report.entity.id)).scalar() or 0
    if total > MAX_ROWS:
        raise ReportError(f"匹配记录 {total} 行超过全量打印上限 {MAX_ROWS}，请使用分页或收紧筛选条件")
    page_size = 500
    cursor = max_id
    collected: list = []
    while True:
        rows = (
            base.filter(report.entity.id <= cursor)
            .order_by(report.entity.id.desc())
            .limit(page_size)
            .all()
        )
        if not rows:
            break
        collected.extend(rows)
        cursor = min(row.id for row in rows) - 1
        if len(collected) >= total or cursor < 0:
            break
    collected = collected[:total]
    result = _build_result(report, collected, total, 0, len(collected), filters)
    result["as_of_max_id"] = max_id
    return result


def _snapshot_canonical(snapshot: dict) -> str:
    """Canonical JSON over every controlled field (excluding the hash itself)."""
    ordered = {
        "report_key": snapshot.get("report_key"),
        "title": snapshot.get("title"),
        "template_version": snapshot.get("template_version"),
        "copy_no": snapshot.get("copy_no"),
        "columns": snapshot.get("columns"),
        "filters": snapshot.get("filters"),
        "offset": snapshot.get("offset"),
        "limit": snapshot.get("limit"),
        "count": snapshot.get("count"),
        "total": snapshot.get("total"),
        "truncated": snapshot.get("truncated"),
        "cover_all": snapshot.get("cover_all"),
        "as_of_max_id": snapshot.get("as_of_max_id"),
        "rows": snapshot.get("rows"),
        "html": snapshot.get("html"),
    }
    return json.dumps(ordered, ensure_ascii=False, sort_keys=True)


def render_printable_html(result: dict, meta: dict) -> str:
    """Render with controlled number/version/filters/range embedded first."""
    def esc(v):
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    columns = result["columns"]
    row_keys = result.get("row_keys", columns)
    header = "".join(f"<th>{esc(c)}</th>" for c in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(d.get(k))}</td>" for k in row_keys) + "</tr>"
        for d in result["rows"]
    )
    if not result["rows"]:
        body = f'<tr><td colspan="{max(len(columns), 1)}">暂无数据</td></tr>'
    truncated = bool(meta["truncated"])
    note = (
        f"<p class='warn'>⚠ 本打印含第 {result['offset'] + 1}–{result['offset'] + result['count']} 行"
        f"（共 {result['total']} 行，已截断：未包含全部匹配记录）。</p>"
        if truncated
        else ""
    )
    filters_txt = json.dumps(meta.get("filters") or {}, ensure_ascii=False) or "无"
    now = datetime.now().isoformat(timespec="seconds")
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{esc(result['title'])}</title>
<style>
body{{font-family:"Microsoft YaHei",Arial,sans-serif;margin:24px;color:#111}}
h1{{font-size:20px}} h2{{font-size:13px;font-weight:normal;color:#444}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th,td{{border:1px solid #999;padding:4px 6px;text-align:left}}
th{{background:#eef2f7}} .warn{{color:#b00}} .foot{{margin-top:12px;font-size:11px;color:#555}}
.meta{{font-size:11px;color:#333;border:1px dashed #888;padding:6px;margin:8px 0}}
</style></head><body>
<h1>{esc(result['title'])}</h1>
<div class="meta">
受控编号：{esc(meta['copy_no'])} · 模板版本：{esc(meta['template_version'])}<br>
生成时间 {esc(now)} · 打印人 {esc(meta['generated_by'])} · 原因 {esc(meta['reason'])}<br>
过滤条件：{esc(filters_txt)} · 范围：第 {result['offset'] + 1}–{result['offset'] + result['count']} 行 / 共 {result['total']} 行
{(' · 已截断' if truncated else '')}{(' · as-of max id=' + str(result.get('as_of_max_id', '')) if result.get('as_of_max_id') else '')}
</div>
<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>
{note}
<div class="foot">本打印件为受控打印记录（REPORT:{esc(result['key'])}）；内容哈希见受控打印台账。</div>
</body></html>"""


def record_print(
    db: Session,
    *,
    key: str,
    content_html: str,
    result: dict,
    printed_by: int,
    purpose: str,
    cover_all: bool,
    copy_no: str,
    template_version: str,
    truncated: bool,
    as_of_max_id: int | None = None,
) -> GspControlledPrintRecord:
    snapshot = {
        "report_key": key,
        "title": result["title"],
        "template_version": template_version,
        "copy_no": copy_no,
        "columns": result["columns"],
        "filters": result["filters"],
        "offset": result["offset"],
        "limit": result["limit"],
        "count": result["count"],
        "total": result["total"],
        "truncated": bool(truncated),
        "cover_all": bool(cover_all),
        "as_of_max_id": as_of_max_id if as_of_max_id is not None else result.get("as_of_max_id"),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "rows": result["rows"],
        "html": content_html,
    }
    canonical = _snapshot_canonical(snapshot)
    content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    record = GspControlledPrintRecord(
        document_type=f"REPORT:{key}",
        entity_id=0,
        template_version=template_version,
        copy_no=copy_no,
        purpose=purpose,
        status="GENERATED",
        snapshot_data=snapshot,
        content_hash=content_hash,
        printed_by=printed_by,
    )
    db.add(record)
    db.flush()
    return record


def verify_record_content(record: GspControlledPrintRecord) -> bool:
    if not record.snapshot_data:
        return False
    return hashlib.sha256(_snapshot_canonical(record.snapshot_data).encode()).hexdigest() == (record.content_hash or "")
