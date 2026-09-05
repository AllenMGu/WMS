"""Application composition root.

Legacy WMS routes are preserved while the GSP bounded context evolves behind
its own router and database tables.
"""

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import EXPECTED_SCHEMA_REVISION, Base, SessionLocal, engine
from app.gsp import models as gsp_models  # noqa: F401 - registers tables
from app.gsp.attachments import models as attachments_models  # noqa: F401
from app.gsp.attachments.router import router as attachments_router
from app.gsp.electronic_signature import models as electronic_signature_models  # noqa: F401
from app.gsp.electronic_signature.router import router as electronic_signature_router
from app.gsp.environment import models as environment_models  # noqa: F401
from app.gsp.environment.router import router as environment_router
from app.gsp.integration_router import router as integration_router
from app.gsp.legacy_archive import models as legacy_archive_models  # noqa: F401
from app.gsp.legacy_archive.router import router as legacy_archive_router
from app.gsp.maintenance.router import router as maintenance_router
from app.gsp.operations import models as operations_models  # noqa: F401 - registers tables
from app.gsp.operations.router import router as operations_router
from app.gsp.procurement_receiving.router import router as procurement_receiving_router
from app.gsp.quality_disposition.router import router as quality_disposition_router
from app.gsp.quality_system import models as quality_system_models  # noqa: F401
from app.gsp.quality_system.router import router as quality_system_router
from app.gsp.returns_recalls.router import router as returns_recalls_router
from app.gsp.router import router as gsp_router
from app.gsp.sales_shipping.router import router as sales_shipping_router
from app.gsp.stocktaking.router import router as stocktaking_router
from app.gsp.transport import models as transport_models  # noqa: F401 - registers tables
from app.gsp.transport.router import router as transport_router
from app.legacy import app

app.title = "药品GSP仓储与质量管理系统 API"
app.version = "0.18.1"
app.description = (
    "WMS兼容接口与独立GSP质量域。GSP接口默认位于 /api/gsp；对接九州通等外部平台时通过集成出站箱解耦。"
)
app.include_router(gsp_router, prefix="/api")
app.include_router(attachments_router, prefix="/api")
app.include_router(procurement_receiving_router, prefix="/api")
app.include_router(quality_disposition_router, prefix="/api")
app.include_router(quality_system_router, prefix="/api")
app.include_router(sales_shipping_router, prefix="/api")
app.include_router(returns_recalls_router, prefix="/api")
app.include_router(maintenance_router, prefix="/api")
app.include_router(stocktaking_router, prefix="/api")
app.include_router(operations_router, prefix="/api")
app.include_router(transport_router, prefix="/api")
app.include_router(environment_router, prefix="/api")
app.include_router(electronic_signature_router, prefix="/api")
app.include_router(integration_router, prefix="/api")
app.include_router(legacy_archive_router, prefix="/api")

if settings.auto_create_schema:
    # Existing deployments keep their current start-up behavior.  Controlled
    # environments should set AUTO_CREATE_SCHEMA=false and run reviewed migrations.
    Base.metadata.create_all(bind=engine)


@app.get("/health", tags=["系统"])
async def health():
    return {"status": "ok", "service": "wms-gsp", "version": app.version}


@app.get("/health/live", tags=["系统"])
async def liveness():
    return {"status": "alive", "service": "wms-gsp"}


@app.get("/health/ready", tags=["系统"])
async def readiness():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        if settings.environment == "production" and revision != EXPECTED_SCHEMA_REVISION:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "database": "connected",
                    "schema_revision": revision,
                    "expected_schema_revision": EXPECTED_SCHEMA_REVISION,
                },
            )
        return {
            "status": "ready",
            "database": "connected",
            "schema_revision": revision,
            "expected_schema_revision": EXPECTED_SCHEMA_REVISION,
            "ldap_transport_mode": settings.ldap_transport_mode(),
            "security_warnings": (
                ["LDAP_PLAINTEXT_AUTH_ENABLED"]
                if settings.ldap_admin_dn and settings.ldap_transport_mode() == "PLAINTEXT"
                else []
            ),
        }
    except HTTPException:
        raise
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "database": "failed"})
    finally:
        db.close()
