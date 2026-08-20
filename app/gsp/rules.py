"""Pure GSP release/qualification rules.

Keeping these rules free of FastAPI and SQLAlchemy makes them reviewable by the
quality department and straightforward to cover with validation evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable, Optional


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    blocking: bool = True


@dataclass(frozen=True)
class QualificationResult:
    qualified: bool
    findings: tuple[Finding, ...]


def evaluate_partner(
    *,
    status: str,
    license_valid_to: date,
    quality_agreement_valid_to: Optional[date],
    document_expiries: Iterable[date] = (),
    on_date: Optional[date] = None,
) -> QualificationResult:
    today = on_date or date.today()
    findings: list[Finding] = []
    if status != "APPROVED":
        findings.append(Finding("PARTNER_NOT_APPROVED", "供货方/购货方尚未通过质量审批"))
    if license_valid_to < today:
        findings.append(Finding("LICENSE_EXPIRED", "经营或生产许可证已过期"))
    if quality_agreement_valid_to is not None and quality_agreement_valid_to < today:
        findings.append(Finding("QUALITY_AGREEMENT_EXPIRED", "质量保证协议已过期"))
    if any(expiry < today for expiry in document_expiries):
        findings.append(Finding("PARTNER_DOCUMENT_EXPIRED", "合作方必备资质文件存在过期项"))
    return QualificationResult(not any(item.blocking for item in findings), tuple(findings))


def evaluate_product(
    *,
    status: str,
    registration_valid_to: Optional[date],
    on_date: Optional[date] = None,
) -> QualificationResult:
    today = on_date or date.today()
    findings: list[Finding] = []
    if status != "APPROVED":
        findings.append(Finding("PRODUCT_NOT_APPROVED", "经营品种尚未通过质量审批"))
    if registration_valid_to is not None and registration_valid_to < today:
        findings.append(Finding("REGISTRATION_EXPIRED", "药品注册批准文件已过期"))
    return QualificationResult(not findings, tuple(findings))


def evaluate_batch(
    *,
    status: str,
    expiry_date: date,
    has_active_hold: bool,
    traceability_required: bool,
    traceability_code: Optional[str],
    minimum_remaining_days: int = 0,
    on_date: Optional[date] = None,
) -> QualificationResult:
    today = on_date or date.today()
    findings: list[Finding] = []
    if status != "RELEASED":
        findings.append(Finding("BATCH_NOT_RELEASED", "批次尚未验收放行"))
    if expiry_date < today:
        findings.append(Finding("BATCH_EXPIRED", "批次已超过有效期"))
    elif expiry_date < today + timedelta(days=minimum_remaining_days):
        findings.append(Finding("INSUFFICIENT_SHELF_LIFE", "批次剩余有效期不足"))
    if has_active_hold:
        findings.append(Finding("QUALITY_HOLD", "批次处于质量锁定状态"))
    if traceability_required and not traceability_code:
        findings.append(Finding("TRACEABILITY_CODE_MISSING", "缺少法规要求的药品追溯信息"))
    return QualificationResult(not findings, tuple(findings))


def select_fefo(batches: Iterable[tuple[int, date, float]], requested_quantity: float):
    """Allocate released stock by first-expire-first-out without mutating inventory."""
    if requested_quantity <= 0:
        raise ValueError("requested_quantity must be positive")
    remaining = requested_quantity
    allocation: list[tuple[int, float]] = []
    for batch_id, expiry_date, available in sorted(batches, key=lambda item: item[1]):
        if available <= 0:
            continue
        quantity = min(available, remaining)
        allocation.append((batch_id, quantity))
        remaining -= quantity
        if remaining <= 0:
            return allocation
    raise ValueError("insufficient eligible batch stock")
