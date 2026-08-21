"""Application composition root.

Legacy WMS routes are preserved while the GSP bounded context evolves behind
its own router and database tables.
"""

from app.core.config import settings
from app.core.database import Base, engine
from app.gsp import models as gsp_models  # noqa: F401 - registers tables
from app.gsp.environment import models as environment_models  # noqa: F401
from app.gsp.environment.router import router as environment_router
from app.gsp.maintenance.router import router as maintenance_router
from app.gsp.operations import models as operations_models  # noqa: F401 - registers tables
from app.gsp.operations.router import router as operations_router
from app.gsp.procurement_receiving.router import router as procurement_receiving_router
from app.gsp.quality_disposition.router import router as quality_disposition_router
from app.gsp.returns_recalls.router import router as returns_recalls_router
from app.gsp.router import router as gsp_router
from app.gsp.sales_shipping.router import router as sales_shipping_router
from app.gsp.stocktaking.router import router as stocktaking_router
from app.gsp.transport import models as transport_models  # noqa: F401 - registers tables
from app.gsp.transport.router import router as transport_router
from app.legacy import app

app.title = "药品GSP仓储与质量管理系统 API"
app.version = "0.11.0"
app.description = (
    "WMS兼容接口与独立GSP质量域。GSP接口默认位于 /api/gsp；对接九州通等外部平台时通过集成出站箱解耦。"
)
app.include_router(gsp_router, prefix="/api")
app.include_router(procurement_receiving_router, prefix="/api")
app.include_router(quality_disposition_router, prefix="/api")
app.include_router(sales_shipping_router, prefix="/api")
app.include_router(returns_recalls_router, prefix="/api")
app.include_router(maintenance_router, prefix="/api")
app.include_router(stocktaking_router, prefix="/api")
app.include_router(operations_router, prefix="/api")
app.include_router(transport_router, prefix="/api")
app.include_router(environment_router, prefix="/api")

if settings.auto_create_schema:
    # Existing deployments keep their current start-up behavior.  Controlled
    # environments should set AUTO_CREATE_SCHEMA=false and run reviewed migrations.
    Base.metadata.create_all(bind=engine)


@app.get("/health", tags=["系统"])
async def health():
    return {"status": "ok", "service": "wms-gsp", "version": app.version}
