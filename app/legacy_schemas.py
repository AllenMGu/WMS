"""Legacy WMS Pydantic schemas（自 app/legacy.py 提取）。"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.legacy_models import InventoryType, UserRole


# ------------------- Pydantic模型 -------------------
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    warehouse_ids: List[int] = Field(default_factory=list)  # 改为列表
    role: UserRole = UserRole.OPERATOR

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    current_warehouse_id: Optional[int] = None
    role: UserRole
    is_ldap_user: bool
    is_active: bool

    model_config = ConfigDict(from_attributes=True)

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    access_change_reason: Optional[str] = Field(None, min_length=3, max_length=500)

class WarehouseCreate(BaseModel):
    code: str
    name: str
    address: Optional[str] = ""

class WarehouseResponse(BaseModel):
    id: int
    code: str
    name: str
    address: str
    is_active: Optional[bool] = True

    model_config = ConfigDict(from_attributes=True)

class WarehouseUpdate(BaseModel):
    code: Optional[str] = None
    name: Optional[str] = None
    address: Optional[str] = None
    is_active: Optional[bool] = None

class LocationCreate(BaseModel):
    warehouse_id: int
    location_code: str
    name: str

class LocationResponse(BaseModel):
    id: int
    warehouse_id: int
    location_code: str
    name: str
    is_active: bool
    create_time: datetime

    model_config = ConfigDict(from_attributes=True)

class LocationUpdate(BaseModel):
    warehouse_id: Optional[int] = None
    location_code: Optional[str] = None
    name: Optional[str] = None
    is_active: Optional[bool] = None

class GoodsCreate(BaseModel):
    barcode: str
    name: str
    spec: Optional[str] = ""
    unit: Optional[str] = "个"
    price: Optional[float] = 0.0

class GoodsResponse(BaseModel):
    id: int
    barcode: str
    name: str
    spec: str
    unit: str
    price: float
    create_time: datetime

    model_config = ConfigDict(from_attributes=True)

class GoodsUpdate(BaseModel):
    barcode: Optional[str] = None
    name: Optional[str] = None
    spec: Optional[str] = None
    unit: Optional[str] = None
    price: Optional[float] = None

class InventoryCreate(BaseModel):
    goods_barcode: str  # 扫码传入条码
    location_code: str  # 扫码传入库位编码
    type: InventoryType
    quantity: float
    remark: Optional[str] = ""

class CheckCreate(BaseModel):
    goods_barcode: str
    location_code: str
    check_quantity: float

class StockResponse(BaseModel):
    id: int
    warehouse_name: str
    goods_name: str
    goods_barcode: str
    location_code: str
    location_name: str
    quantity: float
    update_time: datetime

# 入库单相关模型
class InboundOrderItemCreate(BaseModel):
    goods_barcode: str  # 货物条码
    location_code: str  # 库位编码
    quantity: float
    unit_price: Optional[float] = None
    remark: Optional[str] = ""

class InboundOrderItemResponse(BaseModel):
    id: int
    goods_id: int
    goods_barcode: str
    goods_name: str
    location_id: int
    location_code: str
    quantity: float
    unit_price: float
    total_price: float
    remark: str

    model_config = ConfigDict(from_attributes=True)

class InboundOrderHeaderCreate(BaseModel):
    supplier: Optional[str] = ""
    remark: Optional[str] = ""

class InboundOrderHeaderResponse(BaseModel):
    id: int
    order_no: str
    warehouse_id: int
    warehouse_name: str
    supplier: str
    operator_id: int
    operator_name: str
    total_amount: float
    remark: str
    status: str
    create_time: datetime
    submit_time: Optional[datetime] = None
    complete_time: Optional[datetime] = None
    item_count: int = 0

    model_config = ConfigDict(from_attributes=True)

class InboundOrderDetailResponse(InboundOrderHeaderResponse):
    items: List[InboundOrderItemResponse] = []

# 出库单相关模型
class OutboundOrderItemCreate(BaseModel):
    goods_barcode: str
    location_code: str
    quantity: float
    unit_price: Optional[float] = None
    remark: Optional[str] = ""

class OutboundOrderItemResponse(BaseModel):
    id: int
    goods_id: int
    goods_barcode: str
    goods_name: str
    location_id: int
    location_code: str
    quantity: float
    unit_price: float
    total_price: float
    remark: str

    model_config = ConfigDict(from_attributes=True)

class OutboundOrderHeaderCreate(BaseModel):
    customer: Optional[str] = ""
    remark: Optional[str] = ""

class OutboundOrderHeaderResponse(BaseModel):
    id: int
    order_no: str
    warehouse_id: int
    warehouse_name: str
    customer: str
    operator_id: int
    operator_name: str
    total_amount: float
    remark: str
    status: str
    create_time: datetime
    submit_time: Optional[datetime] = None
    complete_time: Optional[datetime] = None
    item_count: int = 0

    model_config = ConfigDict(from_attributes=True)

class OutboundOrderDetailResponse(OutboundOrderHeaderResponse):
    items: List[OutboundOrderItemResponse] = []
__all__ = [
    "UserCreate",
    "UserResponse",
    "UserUpdate",
    "WarehouseCreate",
    "WarehouseResponse",
    "WarehouseUpdate",
    "LocationCreate",
    "LocationResponse",
    "LocationUpdate",
    "GoodsCreate",
    "GoodsResponse",
    "GoodsUpdate",
    "InventoryCreate",
    "CheckCreate",
    "StockResponse",
    "InboundOrderItemCreate",
    "InboundOrderItemResponse",
    "InboundOrderHeaderCreate",
    "InboundOrderHeaderResponse",
    "InboundOrderDetailResponse",
    "OutboundOrderItemCreate",
    "OutboundOrderItemResponse",
    "OutboundOrderHeaderCreate",
    "OutboundOrderHeaderResponse",
    "OutboundOrderDetailResponse",
]
