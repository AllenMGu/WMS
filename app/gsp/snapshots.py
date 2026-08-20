"""JSON-safe snapshots for regulated records and audit evidence."""

from fastapi.encoders import jsonable_encoder


def model_snapshot(model) -> dict:
    return jsonable_encoder(
        {column.name: getattr(model, column.name) for column in model.__table__.columns}
    )
