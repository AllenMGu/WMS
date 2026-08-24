from app.core.database import SessionLocal
from app.gsp.outbox import enqueue_integration_message, mark_outbox_failed


def test_outbox_enqueue_is_idempotent_and_failure_becomes_dead_letter():
    import main  # noqa: F401

    db = SessionLocal()
    try:
        kwargs = {
            "destination": "TEST_ADAPTER",
            "message_type": "TEST_EVENT",
            "aggregate_type": "TestAggregate",
            "aggregate_id": "42",
            "payload": {"batch": "B-001", "quantity": 3},
        }
        first = enqueue_integration_message(db, **kwargs)
        second = enqueue_integration_message(db, **kwargs)
        assert first is second
        db.flush()
        third = enqueue_integration_message(db, **kwargs)
        assert third.id == first.id

        mark_outbox_failed(db, first, "remote timeout", max_attempts=1)
        assert first.status == "DEAD"
        assert first.dead_lettered_at is not None
        assert first.last_error == "remote timeout"
    finally:
        db.rollback()
        db.close()
