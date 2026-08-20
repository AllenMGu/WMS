from datetime import date

import pytest

from app.gsp.rules import evaluate_batch, evaluate_partner, evaluate_product, select_fefo


def test_expired_partner_is_blocked_even_when_approved():
    result = evaluate_partner(
        status="APPROVED",
        license_valid_to=date(2026, 1, 1),
        quality_agreement_valid_to=date(2027, 1, 1),
        on_date=date(2026, 8, 20),
    )
    assert result.qualified is False
    assert {item.code for item in result.findings} == {"LICENSE_EXPIRED"}


def test_unapproved_product_is_blocked():
    result = evaluate_product(
        status="PENDING",
        registration_valid_to=date(2027, 1, 1),
        on_date=date(2026, 8, 20),
    )
    assert result.qualified is False
    assert result.findings[0].code == "PRODUCT_NOT_APPROVED"


def test_product_requires_registration_archive_and_nmpa_verification():
    result = evaluate_product(
        status="APPROVED",
        registration_valid_to=date(2027, 1, 1),
        on_date=date(2026, 8, 20),
    )
    assert {item.code for item in result.findings} == {
        "REGISTRATION_DOCUMENT_MISSING",
        "NMPA_VERIFICATION_MISSING",
    }


def test_quality_hold_blocks_released_batch():
    result = evaluate_batch(
        status="RELEASED",
        expiry_date=date(2027, 8, 20),
        has_active_hold=True,
        traceability_required=True,
        traceability_code="TRACE-001",
        on_date=date(2026, 8, 20),
    )
    assert result.qualified is False
    assert {item.code for item in result.findings} == {"QUALITY_HOLD"}


def test_traceability_code_is_mandatory_when_configured():
    result = evaluate_batch(
        status="RELEASED",
        expiry_date=date(2027, 8, 20),
        has_active_hold=False,
        traceability_required=True,
        traceability_code=None,
        on_date=date(2026, 8, 20),
    )
    assert result.qualified is False
    assert result.findings[0].code == "TRACEABILITY_CODE_MISSING"


def test_fefo_allocates_earliest_expiring_batches_first():
    allocation = select_fefo(
        [
            (2, date(2027, 6, 1), 10),
            (1, date(2027, 1, 1), 5),
        ],
        requested_quantity=8,
    )
    assert allocation == [(1, 5), (2, 3)]


def test_fefo_rejects_shortage():
    with pytest.raises(ValueError, match="insufficient"):
        select_fefo([(1, date(2027, 1, 1), 2)], requested_quantity=3)
