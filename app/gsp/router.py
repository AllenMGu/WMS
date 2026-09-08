"""GSP 核心路由聚合器。

各领域端点已下沉到 compliance_router / partners_router / catalog_router /
trace_audit_router，本模块仅负责以 /gsp 前缀聚合它们，URL 路径保持不变。
"""
from __future__ import annotations

from fastapi import APIRouter

from app.gsp.catalog_router import router as catalog_router
from app.gsp.compliance_router import router as compliance_router
from app.gsp.partners_router import router as partners_router
from app.gsp.trace_audit_router import router as trace_audit_router

router = APIRouter(prefix="/gsp", tags=["GSP合规"])
router.include_router(compliance_router)
router.include_router(partners_router)
router.include_router(catalog_router)
router.include_router(trace_audit_router)
