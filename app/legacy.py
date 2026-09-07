import enum
import io
import logging
import secrets
import ssl
from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlparse

import ldap3
import pandas as pd
from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from ldap3.utils.conv import escape_filter_chars
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, relationship

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.time import utc_now
from app.gsp.snapshots import model_snapshot

# ------------------- 配置项 -------------------
SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

# LDAP配置（需根据实际环境修改）
LDAP_SERVER = settings.ldap_server
LDAP_BASE_DN = settings.ldap_base_dn
LDAP_ADMIN_DN = settings.ldap_admin_dn
LDAP_ADMIN_PASSWORD = settings.ldap_admin_password
LDAP_USER_SEARCH_FILTER = settings.ldap_user_search_filter
LDAP_USE_SSL = settings.ldap_use_ssl
LDAP_START_TLS = settings.ldap_start_tls
LDAP_TLS_VALIDATE = settings.ldap_tls_validate
LDAP_CA_CERT_FILE = settings.ldap_ca_cert_file
LDAP_ALLOW_PLAINTEXT_AUTH = settings.ldap_allow_plaintext_auth

router = APIRouter()

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# ------------------- 枚举定义 -------------------
class UserRole(str, enum.Enum):
    ADMIN = "admin"       # 仓库管理员，可管理所有数据
    OPERATOR = "operator" # 操作员，仅可做出入库和盘点

class InventoryType(str, enum.Enum):
    IN = "入库"
    OUT = "出库"

# ------------------- 数据库模型 -------------------
# 0. 配置表
class Config(Base):
    __tablename__ = "config"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, comment="配置项名称")
    value = Column(String(500), comment="配置项值")
    description = Column(String(500), comment="配置项描述")
    create_time = Column(DateTime, default=datetime.now)
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now)

# 1. 仓库表
class Warehouse(Base):
    __tablename__ = "warehouses"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, comment="仓库编码")
    name = Column(String(100), comment="仓库名称")
    address = Column(String(200), comment="仓库地址")
    is_active = Column(Boolean, default=True, comment="是否启用")
    create_time = Column(DateTime, default=datetime.now)

# 添加用户-仓库关联表（多对多）
class UserWarehouse(Base):
    __tablename__ = "user_warehouses"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), comment="用户ID")
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    is_default = Column(Boolean, default=False, comment="是否默认仓库")
    create_time = Column(DateTime, default=datetime.now)

# 2. 用户表
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, comment="用户名")
    hashed_password = Column(String(100), comment="加密密码")
    full_name = Column(String(100), comment="真实姓名")
    role = Column(Enum(UserRole), default=UserRole.OPERATOR, comment="角色")
    is_active = Column(Boolean, default=True, comment="是否启用")
    is_ldap_user = Column(Boolean, default=False, comment="是否是LDAP用户")
    create_time = Column(DateTime, default=datetime.now)
    current_warehouse_id = Column(Integer, nullable=True, comment="当前选择的仓库ID")

    # 多对多关联
    warehouses = relationship("Warehouse", secondary="user_warehouses",
                            backref="users", lazy="dynamic")


class LoginSecurityState(Base):
    """Durable login throttling shared by all API processes."""

    __tablename__ = "login_security_states"
    id = Column(Integer, primary_key=True)
    scope_type = Column(String(20), nullable=False)
    scope_key = Column(String(200), nullable=False)
    failed_count = Column(Integer, nullable=False, default=0)
    window_started_at = Column(DateTime, nullable=True)
    last_failed_at = Column(DateTime, nullable=True)
    locked_until = Column(DateTime, nullable=True)
    __table_args__ = (
        UniqueConstraint("scope_type", "scope_key", name="uq_login_security_scope"),
    )

# 3. 库位表（关联仓库）
class Location(Base):
    __tablename__ = "locations"
    id = Column(Integer, primary_key=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="所属仓库ID")
    location_code = Column(String(50), unique=True, index=True, comment="库位编码")
    name = Column(String(100), comment="库位名称")
    is_active = Column(Boolean, default=True, comment="是否启用")
    create_time = Column(DateTime, default=datetime.now)

    # 关联关系
    warehouse = relationship("Warehouse")

# 4. 货物表（全局货物，多仓库共享）
class Goods(Base):
    __tablename__ = "goods"
    id = Column(Integer, primary_key=True, index=True)
    barcode = Column(String(100), unique=True, index=True, comment="货物条码")
    name = Column(String(100), comment="货物名称")
    spec = Column(String(100), comment="规格型号")
    unit = Column(String(20), comment="单位")
    price = Column(Float, comment="单价")
    create_time = Column(DateTime, default=datetime.now)

# 5. 库存表（关联仓库+库位+货物）
class Stock(Base):
    __tablename__ = "stock"
    id = Column(Integer, primary_key=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    quantity = Column(Float, default=0, comment="库存数量")
    update_time = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    # 复合唯一索引，防止相同仓库、货物、库位的重复记录
    __table_args__ = (
        UniqueConstraint('warehouse_id', 'goods_id', 'location_id', name='_warehouse_goods_location_uc'),
        CheckConstraint("quantity >= 0", name="ck_stock_quantity_non_negative"),
    )

    # 关联关系
    warehouse = relationship("Warehouse")
    goods = relationship("Goods")
    location = relationship("Location")

# 6. 出入库记录表
class InventoryRecord(Base):
    __tablename__ = "inventory_records"
    id = Column(Integer, primary_key=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    type = Column(Enum(InventoryType), comment="类型：入库/出库")
    quantity = Column(Float, comment="数量")
    operator_id = Column(Integer, ForeignKey("users.id"), comment="操作员ID")
    remark = Column(String(500), comment="备注")
    create_time = Column(DateTime, default=datetime.now)

    # 关联关系
    warehouse = relationship("Warehouse")
    goods = relationship("Goods")
    location = relationship("Location")
    operator = relationship("User")

# 7. 盘点单表头
class CheckOrderHeader(Base):
    __tablename__ = "check_order_header"
    id = Column(Integer, primary_key=True, index=True)
    order_no = Column(String(50), unique=True, index=True, comment="盘点单号")
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    operator_id = Column(Integer, ForeignKey("users.id"), comment="操作员ID")
    remark = Column(String(500), comment="备注")
    status = Column(String(20), default="DRAFT", comment="状态: DRAFT-草稿, IN_PROGRESS-盘点中, COMPLETED-已完成")
    create_time = Column(DateTime, default=datetime.now)
    start_time = Column(DateTime, comment="开始时间")
    complete_time = Column(DateTime, comment="完成时间")

    # 关联关系
    warehouse = relationship("Warehouse")
    operator = relationship("User")
    items = relationship("CheckOrderItem", back_populates="header", cascade="all, delete-orphan")

# 8. 盘点单明细
class CheckOrderItem(Base):
    __tablename__ = "check_order_item"
    id = Column(Integer, primary_key=True, index=True)
    header_id = Column(Integer, ForeignKey("check_order_header.id"), comment="单据头ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    check_quantity = Column(Float, comment="盘点数量")
    actual_quantity = Column(Float, comment="系统库存数量")
    diff_quantity = Column(Float, comment="差异数量")
    create_time = Column(DateTime, default=datetime.now)

    # 关联关系
    header = relationship("CheckOrderHeader", back_populates="items")
    goods = relationship("Goods")
    location = relationship("Location")

# 9. 盘点记录表（保留历史记录）
class CheckRecord(Base):
    __tablename__ = "check_records"
    id = Column(Integer, primary_key=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    check_quantity = Column(Float, comment="盘点数量")
    actual_quantity = Column(Float, comment="实际库存数量")
    operator_id = Column(Integer, ForeignKey("users.id"), comment="操作员ID")
    check_time = Column(DateTime, default=datetime.now)

    # 关联关系
    warehouse = relationship("Warehouse")
    goods = relationship("Goods")
    location = relationship("Location")
    operator = relationship("User")

# 8. 入库单表头
class InboundOrderHeader(Base):
    __tablename__ = "inbound_order_header"
    id = Column(Integer, primary_key=True, index=True)
    order_no = Column(String(50), unique=True, index=True, comment="入库单号")
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    supplier = Column(String(200), comment="供应商")
    operator_id = Column(Integer, ForeignKey("users.id"), comment="操作员ID")
    total_amount = Column(Float, default=0, comment="总金额")
    remark = Column(String(500), comment="备注")
    status = Column(String(20), default="DRAFT", comment="状态")
    create_time = Column(DateTime, default=datetime.now)
    submit_time = Column(DateTime, comment="提交时间")
    complete_time = Column(DateTime, comment="完成时间")

    # 关联关系
    warehouse = relationship("Warehouse")
    operator = relationship("User")
    items = relationship("InboundOrderItem", back_populates="header", cascade="all, delete-orphan")

# 9. 入库单明细
class InboundOrderItem(Base):
    __tablename__ = "inbound_order_item"
    id = Column(Integer, primary_key=True, index=True)
    header_id = Column(Integer, ForeignKey("inbound_order_header.id"), comment="单据头ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    quantity = Column(Float, comment="数量")
    unit_price = Column(Float, comment="单价")
    total_price = Column(Float, comment="总价")
    remark = Column(String(500), comment="备注")
    create_time = Column(DateTime, default=datetime.now)

    # 关联关系
    header = relationship("InboundOrderHeader", back_populates="items")
    goods = relationship("Goods")
    location = relationship("Location")

# 10. 出库单表头
class OutboundOrderHeader(Base):
    __tablename__ = "outbound_order_header"
    id = Column(Integer, primary_key=True, index=True)
    order_no = Column(String(50), unique=True, index=True, comment="出库单号")
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), comment="仓库ID")
    customer = Column(String(200), comment="客户")
    operator_id = Column(Integer, ForeignKey("users.id"), comment="操作员ID")
    total_amount = Column(Float, default=0, comment="总金额")
    remark = Column(String(500), comment="备注")
    status = Column(String(20), default="DRAFT", comment="状态")
    create_time = Column(DateTime, default=datetime.now)
    submit_time = Column(DateTime, comment="提交时间")
    complete_time = Column(DateTime, comment="完成时间")

    # 关联关系
    warehouse = relationship("Warehouse")
    operator = relationship("User")
    items = relationship("OutboundOrderItem", back_populates="header", cascade="all, delete-orphan")

# 11. 出库单明细
class OutboundOrderItem(Base):
    __tablename__ = "outbound_order_item"
    id = Column(Integer, primary_key=True, index=True)
    header_id = Column(Integer, ForeignKey("outbound_order_header.id"), comment="单据头ID")
    goods_id = Column(Integer, ForeignKey("goods.id"), comment="货物ID")
    location_id = Column(Integer, ForeignKey("locations.id"), comment="库位ID")
    quantity = Column(Float, comment="数量")
    unit_price = Column(Float, comment="单价")
    total_price = Column(Float, comment="总价")
    remark = Column(String(500), comment="备注")
    create_time = Column(DateTime, default=datetime.now)

    # 关联关系
    header = relationship("OutboundOrderHeader", back_populates="items")
    goods = relationship("Goods")
    location = relationship("Location")

# ------------------- FastAPI应用初始化 -------------------
# 非 development 环境（staging/production/...）默认关闭交互式文档与 OpenAPI
# schema 暴露，避免泄露全部接口结构；开发环境保留便于调试。
_public_docs = settings.environment == "development"
app = FastAPI(
    title="多仓库管理系统API",
    docs_url="/docs" if _public_docs else None,
    redoc_url="/redoc" if _public_docs else None,
    openapi_url="/openapi.json" if _public_docs else None,
)

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- 工具函数 -------------------
# 密码验证
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# 密码加密
def get_password_hash(password: str):
    return pwd_context.hash(password)

# LDAP认证
def _ldap_server_definition():
    parsed = urlparse(LDAP_SERVER if "://" in LDAP_SERVER else f"ldap://{LDAP_SERVER}")
    use_ssl = LDAP_USE_SSL or parsed.scheme.lower() == "ldaps"
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED if LDAP_TLS_VALIDATE else ssl.CERT_NONE,
        ca_certs_file=LDAP_CA_CERT_FILE or None,
    )
    return ldap3.Server(
        parsed.hostname or LDAP_SERVER,
        port=parsed.port or (636 if use_ssl else 389),
        use_ssl=use_ssl,
        tls=tls,
        get_info=ldap3.NONE,
    ), use_ssl


def _ldap_connection(user: str, password: str):
    server, use_ssl = _ldap_server_definition()
    conn = ldap3.Connection(server, user=user, password=password)
    if LDAP_START_TLS and not use_ssl:
        conn.open()
        if conn.closed or not conn.start_tls():
            raise RuntimeError("LDAP StartTLS negotiation failed")
    elif not use_ssl and not LDAP_ALLOW_PLAINTEXT_AUTH:
        raise RuntimeError("LDAP plaintext authentication is not explicitly enabled")
    if not conn.bind():
        raise RuntimeError("LDAP bind failed")
    return conn


def ldap_authenticate(username: str, password: str):
    """通过LDAP安全连接验证用户身份。"""
    try:
        conn = _ldap_connection(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)

        # 搜索用户
        search_filter = LDAP_USER_SEARCH_FILTER.format(escape_filter_chars(username))
        conn.search(LDAP_BASE_DN, search_filter, attributes=['cn', 'mail', 'givenName', 'sn', 'sAMAccountName', 'uid'])

        if len(conn.entries) == 1:
            user_dn = conn.entries[0].entry_dn
            # 尝试使用用户凭证绑定
            user_conn = _ldap_connection(user_dn, password)
            if user_conn.bound:
                # 获取用户信息
                user_info = {
                    'username': username,
                    'full_name': conn.entries[0].cn.value if hasattr(conn.entries[0], 'cn') else username,
                    'email': conn.entries[0].mail.value if hasattr(conn.entries[0], 'mail') else '',
                    'first_name': conn.entries[0].givenName.value if hasattr(conn.entries[0], 'givenName') else '',
                    'last_name': conn.entries[0].sn.value if hasattr(conn.entries[0], 'sn') else ''
                }
                return True, user_info
        elif len(conn.entries) > 1:
            logging.warning("LDAP search returned multiple entries")

        return False, None
    except Exception:
        logging.exception("LDAP authentication failed")
        return False, None

# 创建JWT Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 获取当前用户
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def ensure_admin(current_user: User, detail: str = "无权限操作") -> User:
    """命令式管理员闸门：非 ADMIN 角色直接抛出 403。

    供绕过 FastAPI 依赖注入的直接调用（运维脚本、单元测试）复用同一判定，
    保证 HTTP 入口与非 HTTP 入口的权限语义完全一致。
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail=detail)
    return current_user


def require_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """管理员依赖：非 ADMIN 角色一律 403（默认提示文案）。"""
    return ensure_admin(current_user)


def require_admin(detail: str = "无权限操作"):
    """管理员依赖工厂：保留端点原有的 403 提示文案。"""

    def dependency(current_user: User = Depends(get_current_user)) -> User:
        return ensure_admin(current_user, detail)

    return dependency


def format_outbound_order_response(order):
    return {
        "id": order.id,
        "order_no": order.order_no,
        "warehouse_id": order.warehouse_id,
        "warehouse_name": order.warehouse.name,
        "customer": order.customer,
        "operator_id": order.operator_id,
        "operator_name": order.operator.full_name,
        "total_amount": order.total_amount,
        "remark": order.remark,
        "status": order.status,
        "create_time": order.create_time,
        "submit_time": order.submit_time,
        "complete_time": order.complete_time,
        "item_count": len(order.items)
    }

def format_outbound_order_item_response(item):
    return {
        "id": item.id,
        "goods_id": item.goods_id,
        "goods_barcode": item.goods.barcode,
        "goods_name": item.goods.name,
        "location_id": item.location_id,
        "location_code": item.location.location_code,
        "quantity": item.quantity,
        "unit_price": item.unit_price,
        "total_price": item.total_price,
        "remark": item.remark
    }

def recalculate_outbound_order_total(order_id, db):
    """重新计算出库单总金额"""
    order = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id).first()
    if order:
        total_amount = 0
        for item in order.items:
            total_amount += item.total_price
        order.total_amount = total_amount
        db.commit()
        db.refresh(order)


def format_inbound_order_response(order):
    """入库单表头序列化：goods/warehouse 等字段经关联读取（模型无冗余列）。"""
    return {
        "id": order.id,
        "order_no": order.order_no,
        "warehouse_id": order.warehouse_id,
        "warehouse_name": order.warehouse.name,
        "supplier": order.supplier,
        "operator_id": order.operator_id,
        "operator_name": order.operator.full_name,
        "total_amount": order.total_amount,
        "remark": order.remark,
        "status": order.status,
        "create_time": order.create_time,
        "submit_time": order.submit_time,
        "complete_time": order.complete_time,
        "item_count": len(order.items)
    }


def format_inbound_order_item_response(item):
    """入库单明细序列化：goods_barcode/name、location_code 经关联读取。"""
    return {
        "id": item.id,
        "header_id": item.header_id,
        "goods_id": item.goods_id,
        "goods_barcode": item.goods.barcode,
        "goods_name": item.goods.name,
        "location_id": item.location_id,
        "location_code": item.location.location_code,
        "quantity": item.quantity,
        "unit_price": item.unit_price,
        "total_price": item.total_price,
        "remark": item.remark
    }

def recalculate_inbound_order_total(order_id, db):
    """重新计算入库单总金额"""
    order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()
    if order:
        total_amount = 0
        for item in order.items:
            total_amount += item.total_price
        order.total_amount = total_amount
        db.commit()
        db.refresh(order)

# 生成单据编号
def generate_order_no(prefix: str, db: Session) -> str:
    """生成单据编号"""
    today = datetime.now().strftime("%Y%m%d")
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
            {"scope": f"wms-order-number:{prefix}:{today}"},
        )
    # 查找今天已有多少单
    if prefix == "IN":
        count = db.query(InboundOrderHeader).filter(
            InboundOrderHeader.order_no.like(f"{prefix}{today}%")
        ).count()
    else:
        count = db.query(OutboundOrderHeader).filter(
            OutboundOrderHeader.order_no.like(f"{prefix}{today}%")
        ).count()
    return f"{prefix}{today}{str(count + 1).zfill(3)}"

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

# ------------------- 认证接口 -------------------
def _login_scopes(username: str, source_ip: str) -> tuple[tuple[str, str], ...]:
    return (("USERNAME", username.strip().lower()), ("SOURCE_IP", source_ip))


def _login_security_rows(db: Session, username: str, source_ip: str, *, lock: bool):
    rows = []
    for scope_type, scope_key in _login_scopes(username, source_ip):
        if lock and db.get_bind().dialect.name == "postgresql":
            db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:scope))"),
                {"scope": f"wms-gsp-login:{scope_type}:{scope_key}"},
            )
        query = db.query(LoginSecurityState).filter(
            LoginSecurityState.scope_type == scope_type,
            LoginSecurityState.scope_key == scope_key,
        )
        row = query.with_for_update().first() if lock else query.first()
        if row is None and lock:
            row = LoginSecurityState(scope_type=scope_type, scope_key=scope_key)
            db.add(row)
            db.flush()
        rows.append(row)
    return rows


def _enforce_login_throttle(db: Session, username: str, source_ip: str) -> None:
    now = utc_now()
    for row in _login_security_rows(db, username, source_ip, lock=False):
        if row and row.locked_until and row.locked_until > now:
            raise HTTPException(status_code=429, detail="登录尝试过多，请稍后重试")


def _record_login_failure(db: Session, username: str, source_ip: str) -> None:
    now = utc_now()
    window = timedelta(minutes=settings.login_failure_window_minutes)
    for row in _login_security_rows(db, username, source_ip, lock=True):
        if row.window_started_at is None or now - row.window_started_at > window:
            row.failed_count = 0
            row.window_started_at = now
        row.failed_count += 1
        row.last_failed_at = now
        if row.failed_count >= settings.login_failure_limit:
            row.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
    db.commit()


def _record_login_success(db: Session, username: str, source_ip: str) -> None:
    for row in _login_security_rows(db, username, source_ip, lock=True):
        row.failed_count = 0
        row.window_started_at = None
        row.last_failed_at = None
        row.locked_until = None
    db.commit()


def _authentication_failed(db: Session, username: str, source_ip: str) -> None:
    _record_login_failure(db, username, source_ip)
    raise HTTPException(status_code=401, detail="用户名或密码错误")


@router.post("/token", summary="用户登录获取Token")
def login_for_access_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    source_ip = request.client.host if request.client else "UNKNOWN"
    _enforce_login_throttle(db, username, source_ip)
    # 首先尝试本地数据库认证
    user = db.query(User).filter(User.username == username).first()
    if user:
        # 检查用户是否被禁用
        if not user.is_active:
            _authentication_failed(db, username, source_ip)

        if user.is_ldap_user:
            # LDAP用户，直接使用LDAP认证
            ldap_success, ldap_user_info = ldap_authenticate(username, password)
            if not ldap_success:
                _authentication_failed(db, username, source_ip)
            # LDAP口令只交给目录服务验证，不在本系统留存可复用的派生值。
        else:
            # 本地用户，使用本地数据库认证
            if not verify_password(password, user.hashed_password):
                _authentication_failed(db, username, source_ip)
    else:
        # 本地数据库中未找到用户，尝试LDAP认证
        ldap_success, ldap_user_info = ldap_authenticate(username, password)
        if ldap_success:
            # LDAP认证成功，自动创建本地用户
            hashed_password = get_password_hash(secrets.token_urlsafe(48))
            user = User(
                username=username,
                hashed_password=hashed_password,
                full_name=ldap_user_info.get('full_name', username),
                role=UserRole.OPERATOR,  # 默认角色为操作员
                is_ldap_user=True  # 标识为LDAP用户
            )
            db.add(user)
            db.flush()

            # GSP最小权限：新目录用户必须由管理员审批并明确分配仓库/岗位。
            db.commit()
            db.refresh(user)
        else:
            _authentication_failed(db, username, source_ip)

    _record_login_success(db, username, source_ip)

    # 获取用户所有可管理仓库
    warehouses = []
    for uw in db.query(UserWarehouse).filter(UserWarehouse.user_id == user.id).all():
        warehouse = db.query(Warehouse).filter(Warehouse.id == uw.warehouse_id).first()
        if warehouse:
            warehouses.append({
                "id": warehouse.id,
                "code": warehouse.code,
                "name": warehouse.name,
                "is_default": uw.is_default
            })

    # 获取当前仓库名称
    current_warehouse_name = None
    if user.current_warehouse_id:
        warehouse = db.query(Warehouse).filter(Warehouse.id == user.current_warehouse_id).first()
        current_warehouse_name = warehouse.name if warehouse else None

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role.value},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        # 服务端权威过期时刻(与 JWT exp 一致)；前端应以此为会话失效依据，不得自行伪造更长时效。
        "expiry": (datetime.utcnow() + access_token_expires).isoformat() + "Z",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "current_warehouse_id": user.current_warehouse_id,
            "current_warehouse_name": current_warehouse_name,
            "warehouses": warehouses
        }
    }

# 新增用户（仅管理员可操作）
@router.post("/users/", response_model=UserResponse, summary="新增用户")
def create_user(
    user: UserCreate,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="用户名已存在")

    try:
        new_user = User(
            username=user.username,
            hashed_password=get_password_hash(user.password),
            full_name=user.full_name,
            role=user.role,
        )
        db.add(new_user)
        db.flush()

        if user.role == UserRole.ADMIN:
            assigned_warehouses = (
                db.query(Warehouse)
                .filter(Warehouse.is_active.is_(True))
                .order_by(Warehouse.id)
                .all()
            )
        else:
            assigned_warehouses = []
            seen_warehouse_ids = set()
            for warehouse_id in user.warehouse_ids:
                if warehouse_id in seen_warehouse_ids:
                    continue
                seen_warehouse_ids.add(warehouse_id)
                warehouse = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
                if not warehouse:
                    raise HTTPException(status_code=400, detail=f"仓库ID {warehouse_id} 不存在")
                if warehouse.is_active is False:
                    raise HTTPException(status_code=400, detail=f"仓库ID {warehouse_id} 已停用")
                assigned_warehouses.append(warehouse)

        for index, warehouse in enumerate(assigned_warehouses):
            is_default = index == 0
            db.add(
                UserWarehouse(
                    user_id=new_user.id,
                    warehouse_id=warehouse.id,
                    is_default=is_default,
                )
            )
        if assigned_warehouses:
            new_user.current_warehouse_id = assigned_warehouses[0].id

        db.flush()
        assigned_ids = [warehouse.id for warehouse in assigned_warehouses]
        write_legacy_audit(
            db,
            actor_id=current_user.id,
            action="USER_CREATED",
            entity_type="User",
            entity_id=str(new_user.id),
            reason=reason,
            before_data=None,
            after_data={
                "id": new_user.id,
                "username": new_user.username,
                "full_name": new_user.full_name,
                "role": new_user.role.value if hasattr(new_user.role, "value") else new_user.role,
                "is_ldap_user": new_user.is_ldap_user,
                "warehouse_ids": assigned_ids,
                "current_warehouse_id": new_user.current_warehouse_id,
            },
            request=request,
        )
        for index, warehouse in enumerate(assigned_warehouses):
            write_legacy_audit(
                db,
                actor_id=current_user.id,
                action="USER_WAREHOUSE_ASSIGNED",
                entity_type="UserWarehouse",
                entity_id=f"{new_user.id}:{warehouse.id}",
                reason=reason,
                before_data=None,
                after_data={
                    "user_id": new_user.id,
                    "warehouse_id": warehouse.id,
                    "warehouse_code": warehouse.code,
                    "warehouse_name": warehouse.name,
                    "is_default": index == 0,
                    "assignment_source": "USER_CREATION",
                },
                request=request,
            )

        db.commit()
        db.refresh(new_user)
        return new_user
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logging.exception("local user creation failed")
        raise HTTPException(status_code=500, detail="创建用户失败")

# 用户切换仓库接口
@router.post("/users/{user_id}/switch-warehouse", summary="切换当前仓库")
def switch_user_warehouse(
    user_id: int,
    warehouse_id: Optional[int] = Query(None),
    request: Optional[dict] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 获取仓库ID，可以通过查询参数或请求体获取
    if not warehouse_id:
        if request and "warehouse_id" in request:
            warehouse_id = request.get("warehouse_id")
        else:
            raise HTTPException(status_code=400, detail="缺少仓库ID参数")

    # 确保warehouse_id是整数
    try:
        warehouse_id = int(warehouse_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="仓库ID必须是整数")
    # 权限检查：只能切换自己的仓库或管理员操作
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")

    # 检查用户是否有权限访问该仓库
    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == user_id,
        UserWarehouse.warehouse_id == warehouse_id
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=403, detail="用户无权访问该仓库")

    # 更新用户当前仓库
    user = db.query(User).filter(User.id == user_id).first()
    user.current_warehouse_id = warehouse_id
    db.commit()

    warehouse = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
    return {
        "message": "仓库切换成功",
        "current_warehouse_id": warehouse_id,
        "current_warehouse_name": warehouse.name if warehouse else None
    }

# 获取用户可管理的仓库列表
@router.get("/users/{user_id}/warehouses", summary="获取用户可管理的仓库")
def get_user_warehouses(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限查看")

    user = db.query(User).filter(User.id == user_id).first()

    # 如果是管理员，返回所有仓库
    if user.role == UserRole.ADMIN:
        all_warehouses = db.query(Warehouse).filter(Warehouse.is_active is True).all()
        warehouses = []
        for warehouse in all_warehouses:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == user_id,
                UserWarehouse.warehouse_id == warehouse.id
            ).first()
            warehouses.append({
                "id": warehouse.id,
                "code": warehouse.code,
                "name": warehouse.name,
                "is_default": user_warehouse.is_default if user_warehouse else False,
                "is_current": user.current_warehouse_id == warehouse.id
            })
    else:
        # 普通用户，返回分配的仓库
        warehouses = []
        for uw in db.query(UserWarehouse).filter(UserWarehouse.user_id == user_id).all():
            warehouse = db.query(Warehouse).filter(Warehouse.id == uw.warehouse_id).first()
            if warehouse:
                warehouses.append({
                    "id": warehouse.id,
                    "code": warehouse.code,
                    "name": warehouse.name,
                    "is_default": uw.is_default,
                    "is_current": user.current_warehouse_id == warehouse.id
                })

    return warehouses

# 获取LDAP配置
@router.get("/ldap/config", summary="获取当前LDAP配置")
def get_ldap_config(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")

    return {
        "ldap_server": settings.ldap_server,
        "ldap_base_dn": settings.ldap_base_dn,
        "ldap_admin_dn": settings.ldap_admin_dn,
        "ldap_user_search_filter": settings.ldap_user_search_filter,
        "ldap_use_ssl": settings.ldap_use_ssl,
        "ldap_start_tls": settings.ldap_start_tls,
        "ldap_tls_validate": settings.ldap_tls_validate,
        "ldap_allow_plaintext_auth": settings.ldap_allow_plaintext_auth,
        "ldap_transport_mode": settings.ldap_transport_mode(),
        "managed_externally": True,
    }

# 更新LDAP配置
@router.put("/ldap/config", summary="更新LDAP配置")
def update_ldap_config(
    config_data: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    raise HTTPException(
        status_code=409,
        detail="LDAP配置由外部秘密管理和部署配置控制，请通过受控变更流程更新并重启服务",
    )

# LDAP用户导入
@router.post("/ldap/import-users", summary="导入LDAP用户")
def import_ldap_users(
    ldap_config: dict = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    if ldap_config:
        raise HTTPException(status_code=422, detail="LDAP连接与凭据只能由受控运行环境配置")

    try:
        conn = _ldap_connection(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)

        # 搜索符合条件的用户
        search_filter = LDAP_USER_SEARCH_FILTER  # 使用传入的用户搜索过滤器
        conn.search(LDAP_BASE_DN, search_filter, attributes=['cn', 'mail', 'givenName', 'sn', 'sAMAccountName', 'uid'])

        imported_count = 0
        skipped_count = 0

        for entry in conn.entries:
            # 尝试获取用户名（优先级：sAMAccountName > uid > cn > 邮箱前缀）
            username = None
            if hasattr(entry, 'sAMAccountName'):
                username = entry.sAMAccountName.value
            elif hasattr(entry, 'uid'):
                username = entry.uid.value
            elif hasattr(entry, 'cn'):
                username = entry.cn.value
            elif hasattr(entry, 'mail'):
                username = entry.mail.value.split('@')[0]

            if not username:
                skipped_count += 1
                continue

            # 检查用户是否已存在
            existing_user = db.query(User).filter(User.username == username).first()
            if existing_user:
                skipped_count += 1
                continue

            # 获取用户姓名（优先级：cn > givenName + sn > 用户名）
            full_name = username
            if hasattr(entry, 'cn'):
                full_name = entry.cn.value
            elif hasattr(entry, 'givenName') and hasattr(entry, 'sn'):
                full_name = f"{entry.givenName.value} {entry.sn.value}"
            elif hasattr(entry, 'givenName'):
                full_name = entry.givenName.value
            elif hasattr(entry, 'sn'):
                full_name = entry.sn.value

            # LDAP口令不在本系统保存；随机占位值不可用于目录认证。
            hashed_password = get_password_hash(secrets.token_urlsafe(48))

            # 创建本地用户
            new_user = User(
                username=username,
                hashed_password=hashed_password,
                full_name=full_name,
                role=UserRole.OPERATOR,  # 默认角色为操作员
                is_ldap_user=True  # 标识为LDAP用户
            )
            db.add(new_user)
            db.flush()

            # 最小权限：导入只建立无仓库、无GSP岗位账号，访问权限须独立审批。

            imported_count += 1

        db.commit()

        return {
            "imported": imported_count,
            "skipped": skipped_count,
            "message": f"成功导入 {imported_count} 个用户，跳过 {skipped_count} 个用户"
        }

    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        logging.exception("LDAP user import failed")
        raise HTTPException(status_code=502, detail="LDAP用户导入失败")

# 获取所有用户
@router.get("/users/", summary="获取所有用户")
def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 权限校验：仅管理员可查看所有用户
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限查看用户列表")

    users = db.query(User).all()

    # 返回简化用户信息
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
            "is_ldap_user": user.is_ldap_user
        })
    return result

# 修改用户（仅管理员可操作）
@router.put("/users/{user_id}", summary="修改用户信息")
def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if user_update.full_name is not None:
        user.full_name = user_update.full_name
    if user_update.role is not None:
        user.role = user_update.role
    if user_update.is_active is False:
        if not user_update.access_change_reason:
            raise HTTPException(status_code=400, detail="停用用户必须填写原因")
        from app.gsp.access_control import deactivate_user_access

        deactivate_user_access(
            db,
            user=user,
            actor_id=current_user.id,
            reason=user_update.access_change_reason,
            source_ip=request.client.host if request.client else None,
        )
    elif user_update.is_active is True:
        raise HTTPException(status_code=400, detail="停用账号须通过重新审批后启用，不允许直接恢复")
    if user_update.password:
        user.hashed_password = get_password_hash(user_update.password)

    db.commit()
    return {"message": "用户更新成功"}

# 为用户分配/取消分配仓库
@router.post("/users/{user_id}/assign-warehouse", summary="为用户分配仓库")
def assign_warehouse_to_user(
    user_id: int,
    warehouse_id: int,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    is_default: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    reason = normalize_legacy_audit_reason(reason)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    warehouse = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
    if not warehouse:
        raise HTTPException(status_code=404, detail="仓库不存在")
    if warehouse.is_active is False:
        raise HTTPException(status_code=400, detail="不能分配已停用仓库")

    existing = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == user_id,
        UserWarehouse.warehouse_id == warehouse_id,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="已分配该仓库给用户")

    previous_current_warehouse_id = user.current_warehouse_id
    previous_default_ids = []
    if is_default:
        previous_defaults = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == user_id,
            UserWarehouse.is_default.is_(True),
        ).all()
        previous_default_ids = [assignment.warehouse_id for assignment in previous_defaults]
        for assignment in previous_defaults:
            assignment.is_default = False

    db.add(
        UserWarehouse(
            user_id=user_id,
            warehouse_id=warehouse_id,
            is_default=is_default,
        )
    )
    if is_default or not user.current_warehouse_id:
        user.current_warehouse_id = warehouse_id

    db.flush()
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="USER_WAREHOUSE_ASSIGNED",
        entity_type="UserWarehouse",
        entity_id=f"{user_id}:{warehouse_id}",
        reason=reason,
        before_data={
            "current_warehouse_id": previous_current_warehouse_id,
            "previous_default_warehouse_ids": previous_default_ids,
        },
        after_data={
            "user_id": user_id,
            "warehouse_id": warehouse_id,
            "warehouse_code": warehouse.code,
            "warehouse_name": warehouse.name,
            "is_default": is_default,
            "current_warehouse_id": user.current_warehouse_id,
        },
        request=request,
    )
    db.commit()
    return {"message": "仓库分配成功"}

@router.delete("/users/{user_id}", summary="删除用户")
def delete_user(
    user_id: int,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="仅管理员可操作")

    # 查找用户
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    # 受控系统保留历史操作人引用，同时撤销全部岗位和仓库访问。
    from app.gsp.access_control import deactivate_user_access

    deactivate_user_access(
        db,
        user=user,
        actor_id=current_user.id,
        reason=reason,
        source_ip=request.client.host if request.client else None,
    )
    db.commit()

    return {"message": "用户已停用，历史记录已保留"}

@router.delete("/users/{user_id}/unassign-warehouse", summary="取消用户仓库分配")
def unassign_warehouse_from_user(
    user_id: int,
    warehouse_id: int,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    reason = normalize_legacy_audit_reason(reason)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user.role == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="管理员自动拥有全部仓库，不能单独解除")

    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == user_id,
        UserWarehouse.warehouse_id == warehouse_id,
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=404, detail="未找到分配记录")

    warehouse = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
    previous_current_warehouse_id = user.current_warehouse_id
    before = {
        "user_id": user_id,
        "warehouse_id": warehouse_id,
        "warehouse_code": warehouse.code if warehouse else None,
        "warehouse_name": warehouse.name if warehouse else None,
        "is_default": user_warehouse.is_default,
        "current_warehouse_id": previous_current_warehouse_id,
    }
    db.delete(user_warehouse)
    db.flush()

    if previous_current_warehouse_id == warehouse_id:
        replacement = (
            db.query(UserWarehouse)
            .filter(UserWarehouse.user_id == user_id)
            .order_by(UserWarehouse.is_default.desc(), UserWarehouse.id)
            .first()
        )
        user.current_warehouse_id = replacement.warehouse_id if replacement else None

    remaining_warehouse_ids = [
        assignment.warehouse_id
        for assignment in db.query(UserWarehouse)
        .filter(UserWarehouse.user_id == user_id)
        .order_by(UserWarehouse.id)
        .all()
    ]
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="USER_WAREHOUSE_UNASSIGNED",
        entity_type="UserWarehouse",
        entity_id=f"{user_id}:{warehouse_id}",
        reason=reason,
        before_data=before,
        after_data={
            "user_id": user_id,
            "removed_warehouse_id": warehouse_id,
            "current_warehouse_id": user.current_warehouse_id,
            "remaining_warehouse_ids": remaining_warehouse_ids,
        },
        request=request,
    )
    db.commit()
    return {"message": "取消分配成功"}

# ------------------- 仓库管理接口 -------------------
@router.post("/warehouses/", response_model=WarehouseResponse, summary="新增仓库")
def create_warehouse(
    warehouse: WarehouseCreate,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    db_warehouse = db.query(Warehouse).filter(Warehouse.code == warehouse.code).first()
    if db_warehouse:
        raise HTTPException(status_code=400, detail="仓库编码已存在")

    new_warehouse = Warehouse(**warehouse.dict())
    db.add(new_warehouse)
    db.flush()

    assigned_admins = []
    admin_users = db.query(User).filter(User.role == UserRole.ADMIN).order_by(User.id).all()
    for admin in admin_users:
        is_default = admin.current_warehouse_id is None
        db.add(
            UserWarehouse(
                user_id=admin.id,
                warehouse_id=new_warehouse.id,
                is_default=is_default,
            )
        )
        if is_default:
            admin.current_warehouse_id = new_warehouse.id
        assigned_admins.append((admin, is_default))

    db.flush()
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="WAREHOUSE_CREATED",
        entity_type="Warehouse",
        entity_id=str(new_warehouse.id),
        reason=reason,
        before_data=None,
        after_data={
            **model_snapshot(new_warehouse),
            "auto_assigned_admin_user_ids": [admin.id for admin, _ in assigned_admins],
        },
        request=request,
    )
    for admin, is_default in assigned_admins:
        write_legacy_audit(
            db,
            actor_id=current_user.id,
            action="USER_WAREHOUSE_ASSIGNED",
            entity_type="UserWarehouse",
            entity_id=f"{admin.id}:{new_warehouse.id}",
            reason=reason,
            before_data=None,
            after_data={
                "user_id": admin.id,
                "warehouse_id": new_warehouse.id,
                "warehouse_code": new_warehouse.code,
                "warehouse_name": new_warehouse.name,
                "is_default": is_default,
                "assignment_source": "WAREHOUSE_CREATION",
            },
            request=request,
        )

    db.commit()
    db.refresh(new_warehouse)
    return new_warehouse

@router.get("/warehouses/", response_model=List[WarehouseResponse], summary="获取所有仓库")
def get_warehouses(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        if current_user.role == UserRole.ADMIN:
            # 管理员可以看到所有仓库，包括禁用的
            warehouses = db.query(Warehouse).all()
            print(f"管理员 {current_user.username} 查询到 {len(warehouses)} 个仓库")
            return warehouses
        else:
            # 非管理员只返回自己有权限的启用的仓库
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            print(f"用户 {current_user.username} 有权限的仓库ID: {user_warehouse_ids}")

            if user_warehouse_ids:
                warehouses = db.query(Warehouse).filter(
                    Warehouse.id.in_(user_warehouse_ids),
                    Warehouse.is_active is True
                ).all()
                print(f"用户 {current_user.username} 查询到 {len(warehouses)} 个启用的仓库")
                return warehouses
            else:
                print(f"用户 {current_user.username} 没有分配任何仓库")
                return []
    except Exception as e:
        print(f"获取仓库列表出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"获取仓库列表失败: {str(e)}")

@router.get("/warehouses/{id}", response_model=WarehouseResponse, summary="获取仓库详情")
def get_warehouse(id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # 获取仓库信息
    db_warehouse = db.query(Warehouse).filter(Warehouse.id == id).first()

    if not db_warehouse:
        raise HTTPException(status_code=404, detail="仓库未找到")

    # 检查用户权限
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == id
        ).first()

        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限访问此仓库")

    return db_warehouse

@router.put("/warehouses/{id}", response_model=WarehouseResponse, summary="修改仓库信息")
def update_warehouse(
    id: int,
    warehouse: WarehouseUpdate,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    db_warehouse = db.query(Warehouse).filter(Warehouse.id == id).first()
    if not db_warehouse:
        raise HTTPException(status_code=404, detail="仓库未找到")

    before = model_snapshot(db_warehouse)
    for key, value in warehouse.dict(exclude_unset=True).items():
        setattr(db_warehouse, key, value)

    after = model_snapshot(db_warehouse)
    if before == after:
        raise HTTPException(status_code=400, detail="未提供有效变更")

    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="WAREHOUSE_UPDATED",
        entity_type="Warehouse",
        entity_id=str(id),
        reason=reason,
        before_data=before,
        after_data=after,
        request=request,
    )
    db.commit()
    db.refresh(db_warehouse)
    return db_warehouse

# ------------------- 库位管理接口 -------------------
@router.post("/locations/", response_model=LocationResponse, summary="新增库位")
def create_location(
    location: LocationCreate,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    warehouse = db.query(Warehouse).filter(Warehouse.id == location.warehouse_id).first()
    if not warehouse:
        raise HTTPException(status_code=404, detail="仓库不存在")
    if warehouse.is_active is False:
        raise HTTPException(status_code=400, detail="不能在已停用仓库中新建库位")

    db_location = db.query(Location).filter(Location.location_code == location.location_code).first()
    if db_location:
        raise HTTPException(status_code=400, detail="库位编码已存在")

    new_location = Location(**location.dict())
    db.add(new_location)
    db.flush()
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="LOCATION_CREATED",
        entity_type="Location",
        entity_id=str(new_location.id),
        reason=reason,
        before_data=None,
        after_data=model_snapshot(new_location),
        request=request,
    )
    db.commit()
    db.refresh(new_location)
    return new_location

@router.get("/locations/", response_model=List[LocationResponse], summary="获取库位列表")
def get_locations(
    warehouse_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # 如果是管理员，返回所有库位，包括禁用的
        if current_user.role == UserRole.ADMIN:
            if warehouse_id:
                locations = db.query(Location).filter(Location.warehouse_id == warehouse_id).all()
            else:
                locations = db.query(Location).all()
        else:
            # 非管理员，获取用户可管理的所有仓库ID，只返回启用的库位
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                query = db.query(Location).filter(
                    Location.is_active is True,
                    Location.warehouse_id.in_(user_warehouse_ids)
                )
                if warehouse_id and warehouse_id in user_warehouse_ids:
                    query = query.filter(Location.warehouse_id == warehouse_id)
                locations = query.all()
            else:
                # 用户没有分配任何仓库，返回空列表
                locations = []

        # 确保返回正确的字段
        result = []
        for loc in locations:
            result.append({
                "id": loc.id,
                "warehouse_id": loc.warehouse_id,
                "location_code": loc.location_code,
                "name": loc.name,
                "is_active": loc.is_active,
                "create_time": loc.create_time
            })
        return result
    except Exception as e:
        # 记录错误日志
        print(f"获取库位列表出错: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"获取库位列表失败: {str(e)}"
        )

@router.put("/locations/{id}", response_model=LocationResponse, summary="修改库位信息")
def update_location(
    id: int,
    location: LocationUpdate,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_location = db.query(Location).filter(Location.id == id).first()
    if not db_location:
        raise HTTPException(status_code=404, detail="库位未找到")
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    target_warehouse_id = (
        location.warehouse_id
        if location.warehouse_id is not None
        else db_location.warehouse_id
    )
    warehouse = db.query(Warehouse).filter(Warehouse.id == target_warehouse_id).first()
    if not warehouse:
        raise HTTPException(status_code=404, detail="仓库不存在")
    if warehouse.is_active is False:
        raise HTTPException(status_code=400, detail="不能将库位设置到已停用仓库")

    before = model_snapshot(db_location)
    for key, value in location.dict(exclude_unset=True).items():
        setattr(db_location, key, value)
    after = model_snapshot(db_location)
    if before == after:
        raise HTTPException(status_code=400, detail="未提供有效变更")

    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="LOCATION_UPDATED",
        entity_type="Location",
        entity_id=str(id),
        reason=reason,
        before_data=before,
        after_data=after,
        request=request,
    )
    db.commit()
    db.refresh(db_location)
    return db_location

@router.delete("/locations/{id}", summary="删除库位")
def delete_location(
    id: int,
    request: Request,
    reason: str = Query(..., min_length=3, max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    reason = normalize_legacy_audit_reason(reason)

    db_location = db.query(Location).filter(Location.id == id).first()
    if not db_location:
        raise HTTPException(status_code=404, detail="库位未找到")

    before = model_snapshot(db_location)
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="LOCATION_DELETED",
        entity_type="Location",
        entity_id=str(id),
        reason=reason,
        before_data=before,
        after_data=None,
        request=request,
    )
    db.delete(db_location)
    db.commit()
    return {"message": "删除成功"}

# ------------------- 货物管理接口 -------------------
@router.post("/goods/", response_model=GoodsResponse, summary="新增货物")
def create_goods(
    goods: GoodsCreate,
    current_user: User = Depends(require_admin_user),
    db: Session = Depends(get_db)
):
    db_goods = db.query(Goods).filter(Goods.barcode == goods.barcode).first()
    if db_goods:
        raise HTTPException(status_code=400, detail="货物条码已存在")

    new_goods = Goods(**goods.dict())
    db.add(new_goods)
    db.commit()
    db.refresh(new_goods)
    return new_goods

@router.get("/goods/", response_model=List[GoodsResponse], summary="获取所有货物（支持搜索）")
def get_goods(
    keyword: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取货物列表，支持通过货物名称、条码或规格搜索"""
    query = db.query(Goods)

    if keyword:
        query = query.filter(
            Goods.name.contains(keyword) |
            Goods.barcode.contains(keyword) |
            Goods.spec.contains(keyword)
        )

    return query.all()

@router.get("/goods/export", summary="导出货物数据")
def export_goods(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """导出货物数据为Excel文件"""
    try:
        # 获取所有货物数据
        goods_list = db.query(Goods).all()

        # 转换为DataFrame
        data = []
        for goods in goods_list:
            data.append({
                "条码": goods.barcode,
                "货物名称": goods.name,
                "规格型号": goods.spec,
                "单位": goods.unit,
                "单价": goods.price,
                "创建时间": goods.create_time.strftime("%Y-%m-%d %H:%M:%S")
            })

        df = pd.DataFrame(data)

        # 写入Excel文件
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='货物数据')

        output.seek(0)

        # 返回响应
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=goods_export.xlsx"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导出失败：{str(e)}")

@router.get("/goods/{id}", response_model=GoodsResponse, summary="获取单个货物详情")
def get_goods_detail(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_goods = db.query(Goods).filter(Goods.id == id).first()
    if not db_goods:
        raise HTTPException(status_code=404, detail="货物未找到")
    return db_goods

@router.put("/goods/{id}", response_model=GoodsResponse, summary="修改货物信息")
def update_goods(
    id: int,
    goods: GoodsUpdate,
    current_user: User = Depends(require_admin_user),
    db: Session = Depends(get_db)
):
    db_goods = db.query(Goods).filter(Goods.id == id).first()
    if not db_goods:
        raise HTTPException(status_code=404, detail="货物未找到")

    for key, value in goods.dict(exclude_unset=True).items():
        setattr(db_goods, key, value)

    db.commit()
    db.refresh(db_goods)
    return db_goods

@router.delete("/goods/{id}", summary="删除货物")
def delete_goods(
    id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")

    db_goods = db.query(Goods).filter(Goods.id == id).first()
    if not db_goods:
        raise HTTPException(status_code=404, detail="货物未找到")

    db.delete(db_goods)
    db.commit()
    return {"message": "删除成功"}

@router.post("/goods/import", summary="导入货物数据")
def import_goods(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """从Excel文件导入货物数据"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")

    try:
        # 读取Excel文件（同步 def：FastAPI 在线程池执行整个处理流程，
        # pandas 解析与逐行 DB 查询/提交不会阻塞事件循环）
        contents = file.file.read()
        df = pd.read_excel(io.BytesIO(contents))

        # 检查必要的列
        required_columns = ["条码", "货物名称", "规格型号", "单位", "单价"]
        for col in required_columns:
            if col not in df.columns:
                raise HTTPException(status_code=400, detail=f"缺少必要列：{col}")

        # 导入数据
        success_count = 0
        error_count = 0
        errors = []

        for index, row in df.iterrows():
            try:
                # 检查条码是否已存在
                existing_goods = db.query(Goods).filter(Goods.barcode == str(row["条码"])).first()
                if existing_goods:
                    error_count += 1
                    errors.append(f"第{index+1}行：条码{row['条码']}已存在")
                    continue

                # 创建新货物
                new_goods = Goods(
                    barcode=str(row["条码"]),
                    name=str(row["货物名称"]),
                    spec=str(row["规格型号"]) if pd.notna(row["规格型号"]) else "",
                    unit=str(row["单位"]) if pd.notna(row["单位"]) else "个",
                    price=float(row["单价"]) if pd.notna(row["单价"]) else 0.0
                )

                db.add(new_goods)
                success_count += 1
            except Exception as e:
                error_count += 1
                errors.append(f"第{index+1}行：{str(e)}")

        db.commit()

        return {
            "success_count": success_count,
            "error_count": error_count,
            "errors": errors
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"导入失败：{str(e)}")

# ------------------- 扫码出入库接口 -------------------
def ensure_not_gsp_managed_goods(db: Session, goods_ids) -> None:
    """Prevent legacy quantity paths from bypassing batch and quality controls."""
    from app.gsp.models import GspDrugProfile

    managed_goods = (
        db.query(GspDrugProfile.goods_id)
        .filter(GspDrugProfile.goods_id.in_(set(goods_ids)))
        .first()
    )
    if managed_goods:
        raise HTTPException(
            status_code=409,
            detail="GSP药品禁止使用旧版无批号出入库接口，请使用 /api/gsp 受控流程",
        )


def gsp_managed_goods_query(db: Session):
    """Return the controlled goods ID query used to close legacy read/report paths."""
    from app.gsp.models import GspDrugProfile

    return db.query(GspDrugProfile.goods_id)


def legacy_order_contains_gsp_goods(db: Session, item_model, header_id: int) -> bool:
    return (
        db.query(item_model.id)
        .filter(
            item_model.header_id == header_id,
            item_model.goods_id.in_(gsp_managed_goods_query(db)),
        )
        .first()
        is not None
    )


def write_legacy_audit(
    db: Session,
    *,
    actor_id: int,
    action: str,
    entity_type: str,
    entity_id: str,
    reason: str,
    before_data: dict | None,
    after_data: dict | None,
    request: Request,
) -> None:
    from app.gsp.audit import write_audit_event

    write_audit_event(
        db,
        actor_user_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        reason=reason,
        before_data=before_data,
        after_data=after_data,
        source_ip=request.client.host if request.client else None,
    )


def normalize_legacy_audit_reason(reason: str) -> str:
    normalized = (reason or "").strip()
    if len(normalized) < 3:
        raise HTTPException(status_code=422, detail="变更原因不能少于3个字")
    return normalized


@router.post("/inventory/scan", summary="扫码出入库")
def scan_inventory(
    inventory: InventoryCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. 查询货物
    goods = db.query(Goods).filter(Goods.barcode == inventory.goods_barcode).first()
    if not goods:
        raise HTTPException(status_code=404, detail="货物不存在")
    ensure_not_gsp_managed_goods(db, [goods.id])

    # 2. 查询库位并校验所属仓库
    location = db.query(Location).filter(Location.location_code == inventory.location_code).first()
    if not location:
        raise HTTPException(status_code=404, detail="库位不存在")

    # 检查用户是否有权限操作这个仓库
    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == current_user.id,
        UserWarehouse.warehouse_id == location.warehouse_id
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=403, detail="无权限操作其他仓库库位")

    # 3. 处理出入库逻辑
    warehouse_id = location.warehouse_id
    stock = db.query(Stock).filter(
        Stock.warehouse_id == warehouse_id,
        Stock.goods_id == goods.id,
        Stock.location_id == location.id
    ).with_for_update().first()
    quantity_before = stock.quantity if stock else 0

    if inventory.type == InventoryType.IN:
        # 入库
        if not stock:
            # 并发首笔入库可能同时创建同一 (warehouse, goods, location) 行，
            # 依靠唯一约束 _warehouse_goods_location_uc 兜底：冲突则回滚后
            # 重新以行锁读取既有行再累加，避免并发丢单与 IntegrityError 泄漏。
            stock = Stock(
                warehouse_id=warehouse_id,
                goods_id=goods.id,
                location_id=location.id,
                quantity=inventory.quantity
            )
            db.add(stock)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                stock = db.query(Stock).filter(
                    Stock.warehouse_id == warehouse_id,
                    Stock.goods_id == goods.id,
                    Stock.location_id == location.id
                ).with_for_update().first()
                if stock is None:
                    raise
                # 冲突重取后，真实 before 是并发事务已提交的库存量，而非首次查询的 0，
                # 否则 GxP 审计会记录错误的 before_data（如 0 -> 8 而非 5 -> 8）。
                quantity_before = stock.quantity
                stock.quantity += inventory.quantity
        else:
            stock.quantity += inventory.quantity

        # 创建入库单与明细：与库存变更、日志、审计同属一个事务，
        # 任一写入失败则整体回滚（GxP：不允许"库存已变但审计缺失"）。
        order_no = generate_order_no("IN", db)
        new_order = InboundOrderHeader(
            order_no=order_no,
            warehouse_id=warehouse_id,
            supplier="扫码入库",
            operator_id=current_user.id,
            remark=inventory.remark,
            status="COMPLETED"  # 直接设置为已完成
        )
        db.add(new_order)
        db.flush()  # 先取 order.id 供明细外键使用（不提交事务）

        # 添加明细项
        unit_price = goods.price
        total_price = unit_price * inventory.quantity
        new_item = InboundOrderItem(
            header_id=new_order.id,
            goods_id=goods.id,
            location_id=location.id,
            quantity=inventory.quantity,
            unit_price=unit_price,
            total_price=total_price,
            remark=inventory.remark
        )
        new_order.total_amount = total_price
        db.add(new_item)
    else:
        # 出库（余额校验与扣减在行锁内，同一事务，见上方 with_for_update）
        if not stock or stock.quantity < inventory.quantity:
            raise HTTPException(status_code=400, detail="库存不足")
        stock.quantity -= inventory.quantity

        # 创建出库单与明细：与库存变更、日志、审计同属一个事务
        order_no = generate_order_no("OUT", db)
        new_order = OutboundOrderHeader(
            order_no=order_no,
            warehouse_id=warehouse_id,
            customer="扫码出库",
            operator_id=current_user.id,
            remark=inventory.remark,
            status="COMPLETED"  # 直接设置为已完成
        )
        db.add(new_order)
        db.flush()  # 先取 order.id 供明细外键使用（不提交事务）

        # 添加明细项
        unit_price = goods.price
        total_price = unit_price * inventory.quantity
        new_item = OutboundOrderItem(
            header_id=new_order.id,
            goods_id=goods.id,
            location_id=location.id,
            quantity=inventory.quantity,
            unit_price=unit_price,
            total_price=total_price,
            remark=inventory.remark
        )
        new_order.total_amount = total_price
        db.add(new_item)

    # 4. 记录出入库日志（同事务）
    record = InventoryRecord(
        warehouse_id=warehouse_id,
        goods_id=goods.id,
        location_id=location.id,
        type=inventory.type,
        quantity=inventory.quantity,
        operator_id=current_user.id,
        remark=inventory.remark
    )
    db.add(record)
    db.flush()  # 获取 record.id 供审计引用（不提交事务）
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="LEGACY_INVENTORY_SCANNED",
        entity_type="InventoryRecord",
        entity_id=str(record.id),
        reason=inventory.remark or "旧版扫码库存操作",
        before_data={"quantity": quantity_before},
        after_data={"quantity": stock.quantity, "type": inventory.type.value},
        request=request,
    )
    # 5. 单次提交：库存 + 单据头 + 明细 + 日志 + 审计 原子生效
    db.commit()
    db.refresh(new_order)
    db.refresh(new_item)

    return {
        "message": f"{inventory.type}成功",
        "goods_name": goods.name,
        "location_name": location.name,
        "current_stock": stock.quantity
    }

# ------------------- 库存查询接口（带仓库+库位） -------------------
@router.get("/stock/", response_model=List[StockResponse], summary="库存查询（带仓库库位）")
def get_stock(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = (
        db.query(Stock)
        .join(Warehouse, Stock.warehouse_id == Warehouse.id)
        .join(Goods, Stock.goods_id == Goods.id)
        .join(Location, Stock.location_id == Location.id)
    )
    query = query.filter(Stock.goods_id.notin_(gsp_managed_goods_query(db)))

    if current_user.role != UserRole.ADMIN:
        # 获取用户有权限的仓库
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(Stock.warehouse_id.in_(user_warehouse_ids))
        else:
            query = query.filter(Stock.warehouse_id == -1)  # 返回空结果

    stocks = query.all()

    # 对相同仓库、货物、库位的库存进行聚合
    stock_map = {}
    for stock in stocks:
        key = (stock.warehouse_id, stock.goods_id, stock.location_id)
        if key not in stock_map:
            stock_map[key] = {
                "id": stock.id,
                "warehouse_name": stock.warehouse.name,
                "goods_name": stock.goods.name,
                "goods_barcode": stock.goods.barcode,
                "location_code": stock.location.location_code,
                "location_name": stock.location.name,
                "quantity": 0,
                "update_time": stock.update_time
            }
        stock_map[key]["quantity"] += stock.quantity
        # 保留最新的更新时间
        if stock.update_time > stock_map[key]["update_time"]:
            stock_map[key]["update_time"] = stock.update_time

    return list(stock_map.values())

# ------------------- 扫码盘点接口 -------------------
@router.post("/check/scan", summary="扫码盘点")
def scan_check(
    check: CheckCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询货物和库位
    goods = db.query(Goods).filter(Goods.barcode == check.goods_barcode).first()
    location = db.query(Location).filter(Location.location_code == check.location_code).first()

    if not goods or not location:
        raise HTTPException(status_code=404, detail="货物或库位不存在")
    ensure_not_gsp_managed_goods(db, [goods.id])

    # 权限校验
    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == current_user.id,
        UserWarehouse.warehouse_id == location.warehouse_id
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=403, detail="无权限操作其他仓库库位")

    # 查询实际库存
    warehouse_id = location.warehouse_id
    stock = db.query(Stock).filter(
        Stock.warehouse_id == warehouse_id,
        Stock.goods_id == goods.id,
        Stock.location_id == location.id
    ).first()

    actual_quantity = stock.quantity if stock else 0.0

    # 记录盘点
    record = CheckRecord(
        warehouse_id=warehouse_id,
        goods_id=goods.id,
        location_id=location.id,
        check_quantity=check.check_quantity,
        actual_quantity=actual_quantity,
        operator_id=current_user.id
    )
    db.add(record)
    db.flush()
    write_legacy_audit(
        db,
        actor_id=current_user.id,
        action="LEGACY_STOCK_CHECK_RECORDED",
        entity_type="CheckRecord",
        entity_id=str(record.id),
        reason="旧版库存盘点记录",
        before_data={"actual_quantity": actual_quantity},
        after_data={"check_quantity": check.check_quantity},
        request=request,
    )
    db.commit()

    return {
        "goods_name": goods.name,
        "location_name": location.name,
        "check_quantity": check.check_quantity,
        "actual_quantity": actual_quantity,
        "diff": check.check_quantity - actual_quantity,
        "message": "库存一致" if actual_quantity == check.check_quantity else "库存不符"
    }

# 获取出入库记录
@router.get("/inventory/logs", summary="获取出入库记录")
def get_inventory_logs(
    warehouse_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: Optional[int] = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(InventoryRecord).join(
        Goods, InventoryRecord.goods_id == Goods.id
    ).join(
        Location, InventoryRecord.location_id == Location.id
    ).join(
        Warehouse, InventoryRecord.warehouse_id == Warehouse.id
    ).join(
        User, InventoryRecord.operator_id == User.id
    )
    query = query.filter(InventoryRecord.goods_id.notin_(gsp_managed_goods_query(db)))

    if current_user.role != UserRole.ADMIN:
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(InventoryRecord.warehouse_id.in_(user_warehouse_ids))
        else:
            query = query.filter(InventoryRecord.warehouse_id == -1)

    if warehouse_id:
        query = query.filter(InventoryRecord.warehouse_id == warehouse_id)

    if start_date:
        start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(InventoryRecord.create_time >= start_datetime)

    if end_date:
        end_datetime = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        query = query.filter(InventoryRecord.create_time < end_datetime)

    # 排序和限制返回条数
    query = query.order_by(InventoryRecord.create_time.desc())
    if limit:
        query = query.limit(limit)

    records = query.all()

    result = []
    for record in records:
        result.append({
            "id": record.id,
            "warehouse_id": record.warehouse_id,
            "warehouse_name": record.warehouse.name,
            "goods_id": record.goods_id,
            "goods_name": record.goods.name,
            "goods_barcode": record.goods.barcode,
            "location_code": record.location.location_code,
            "location_name": record.location.name,
            "type": record.type,
            "quantity": record.quantity,
            "operator_name": record.operator.full_name,
            "remark": record.remark,
            "create_time": record.create_time,
            "status": "SUCCESS"
        })
    return result

# 获取盘点记录
@router.get("/check/records", summary="获取盘点记录")
def get_check_records(
    warehouse_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(CheckRecord).join(
        Goods, CheckRecord.goods_id == Goods.id
    ).join(
        Location, CheckRecord.location_id == Location.id
    ).join(
        Warehouse, CheckRecord.warehouse_id == Warehouse.id
    ).join(
        User, CheckRecord.operator_id == User.id
    )
    query = query.filter(CheckRecord.goods_id.notin_(gsp_managed_goods_query(db)))

    if current_user.role != UserRole.ADMIN:
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(CheckRecord.warehouse_id.in_(user_warehouse_ids))
        else:
            query = query.filter(CheckRecord.warehouse_id == -1)

    if warehouse_id:
        query = query.filter(CheckRecord.warehouse_id == warehouse_id)

    if start_date:
        start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(CheckRecord.check_time >= start_datetime)

    if end_date:
        end_datetime = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        query = query.filter(CheckRecord.check_time < end_datetime)

    records = query.order_by(CheckRecord.check_time.desc()).all()

    result = []
    for record in records:
        diff = record.check_quantity - record.actual_quantity
        result.append({
            "id": record.id,
            "warehouse_id": record.warehouse_id,
            "warehouse_name": record.warehouse.name,
            "goods_name": record.goods.name,
            "goods_barcode": record.goods.barcode,
            "location_code": record.location.location_code,
            "location_name": record.location.name,
            "actual_quantity": record.actual_quantity,
            "check_quantity": record.check_quantity,
            "diff": diff,
            "check_time": record.check_time,
            "operator_name": record.operator.full_name
        })
    return result


# 获取盘点统计
@router.get("/check/stats", summary="获取盘点统计")
def get_check_stats(
    warehouse_id: Optional[int] = None,
    date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if date:
        start_datetime = datetime.strptime(date, "%Y-%m-%d")
    else:
        start_datetime = datetime.combine(datetime.now().date(), datetime.min.time())
    end_datetime = start_datetime + timedelta(days=1)

    query = db.query(CheckRecord).filter(
        CheckRecord.check_time >= start_datetime,
        CheckRecord.check_time < end_datetime
    )
    query = query.filter(CheckRecord.goods_id.notin_(gsp_managed_goods_query(db)))

    if current_user.role != UserRole.ADMIN:
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(CheckRecord.warehouse_id.in_(user_warehouse_ids))
        else:
            query = query.filter(CheckRecord.warehouse_id == -1)

    if warehouse_id:
        query = query.filter(CheckRecord.warehouse_id == warehouse_id)

    records = query.all()
    matched = sum(1 for record in records if abs(record.check_quantity - record.actual_quantity) < 0.0001)
    diff_checks = len(records) - matched
    checked_goods = len({record.goods_id for record in records})

    return {
        "todayChecks": len(records),
        "matchedChecks": matched,
        "diffChecks": diff_checks,
        "checkedGoods": checked_goods
    }


# 获取盘点差异报表
@router.get("/check/diffs", summary="获取盘点差异报表")
def get_check_diffs(
    warehouse_id: Optional[int] = None,
    date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if date:
        start_datetime = datetime.strptime(date, "%Y-%m-%d")
        end_datetime = start_datetime + timedelta(days=1)
    else:
        start_datetime = None
        end_datetime = None

    query = db.query(CheckRecord).join(
        Goods, CheckRecord.goods_id == Goods.id
    ).join(
        Location, CheckRecord.location_id == Location.id
    ).join(
        Warehouse, CheckRecord.warehouse_id == Warehouse.id
    ).join(
        User, CheckRecord.operator_id == User.id
    )
    query = query.filter(CheckRecord.goods_id.notin_(gsp_managed_goods_query(db)))

    if current_user.role != UserRole.ADMIN:
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(CheckRecord.warehouse_id.in_(user_warehouse_ids))
        else:
            query = query.filter(CheckRecord.warehouse_id == -1)

    if warehouse_id:
        query = query.filter(CheckRecord.warehouse_id == warehouse_id)

    if start_datetime and end_datetime:
        query = query.filter(
            CheckRecord.check_time >= start_datetime,
            CheckRecord.check_time < end_datetime
        )

    records = query.order_by(CheckRecord.check_time.desc()).all()
    result = []
    for record in records:
        diff = record.check_quantity - record.actual_quantity
        if abs(diff) < 0.0001:
            continue
        result.append({
            "id": record.id,
            "warehouse_id": record.warehouse_id,
            "warehouse_name": record.warehouse.name,
            "goods_name": record.goods.name,
            "goods_barcode": record.goods.barcode,
            "location_code": record.location.location_code,
            "location_name": record.location.name,
            "actual_quantity": record.actual_quantity,
            "check_quantity": record.check_quantity,
            "diff": diff,
            "check_time": record.check_time,
            "operator_name": record.operator.full_name
        })
    return result

# ------------------- 盘点单管理接口 -------------------
# 创建盘点单请求模型
class CheckOrderCreate(BaseModel):
    warehouse_id: Optional[int] = None
    remark: Optional[str] = None

# 盘点单响应模型
class CheckOrderHeaderResponse(BaseModel):
    id: int
    order_no: str
    warehouse_id: int
    warehouse_name: str
    operator_id: int
    operator_name: str
    remark: Optional[str]
    status: str
    create_time: datetime
    start_time: Optional[datetime]
    complete_time: Optional[datetime]
    item_count: int

    model_config = ConfigDict(from_attributes=True)

# 盘点单明细响应模型
class CheckOrderItemResponse(BaseModel):
    id: int
    goods_id: int
    goods_name: str
    goods_barcode: str
    location_id: int
    location_code: str
    location_name: str
    check_quantity: float
    actual_quantity: float
    diff_quantity: float
    create_time: datetime

    model_config = ConfigDict(from_attributes=True)

# 完整盘点单响应模型（包含明细）
class CheckOrderFullResponse(BaseModel):
    header: CheckOrderHeaderResponse
    items: List[CheckOrderItemResponse]

# 创建盘点单
@router.post("/check-orders/", response_model=CheckOrderHeaderResponse, summary="创建盘点单")
def create_check_order(
    order: CheckOrderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 确定仓库ID
    if order.warehouse_id:
        warehouse_id = order.warehouse_id
    elif current_user.current_warehouse_id:
        warehouse_id = current_user.current_warehouse_id
    else:
        raise HTTPException(status_code=400, detail="请选择仓库或设置默认仓库")

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无该仓库权限")

    # 生成盘点单号（格式：CK + 年月日 + 5位流水号）
    today = datetime.now().strftime("%Y%m%d")
    # 查询当日最大流水号
    last_order = db.query(CheckOrderHeader).filter(
        CheckOrderHeader.order_no.like(f"CK{today}%")
    ).order_by(CheckOrderHeader.order_no.desc()).first()

    if last_order:
        last_seq = int(last_order.order_no[-5:])
        new_seq = last_seq + 1
    else:
        new_seq = 1

    order_no = f"CK{today}{new_seq:05d}"

    # 创建盘点单
    db_order = CheckOrderHeader(
        order_no=order_no,
        warehouse_id=warehouse_id,
        operator_id=current_user.id,
        remark=order.remark,
        status="DRAFT"
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    # 返回响应
    return {
        "id": db_order.id,
        "order_no": db_order.order_no,
        "warehouse_id": db_order.warehouse_id,
        "warehouse_name": db.query(Warehouse).get(warehouse_id).name,
        "operator_id": db_order.operator_id,
        "operator_name": current_user.full_name,
        "remark": db_order.remark,
        "status": db_order.status,
        "create_time": db_order.create_time,
        "start_time": db_order.start_time,
        "complete_time": db_order.complete_time,
        "item_count": 0
    }

# 获取盘点单列表
@router.get("/check-orders/", summary="获取盘点单列表")
def get_check_orders(
    warehouse_id: Optional[int] = None,
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(CheckOrderHeader).join(Warehouse, CheckOrderHeader.warehouse_id == Warehouse.id)
    controlled_order_ids = db.query(CheckOrderItem.header_id).filter(
        CheckOrderItem.goods_id.in_(gsp_managed_goods_query(db))
    )
    query = query.filter(CheckOrderHeader.id.notin_(controlled_order_ids))

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse_ids = [
            uw.warehouse_id for uw in
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            query = query.filter(CheckOrderHeader.warehouse_id.in_(user_warehouse_ids))
        else:
            return []

    # 过滤条件
    if warehouse_id:
        query = query.filter(CheckOrderHeader.warehouse_id == warehouse_id)

    if status:
        query = query.filter(CheckOrderHeader.status == status)

    if start_date:
        start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(CheckOrderHeader.create_time >= start_datetime)

    if end_date:
        end_datetime = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        query = query.filter(CheckOrderHeader.create_time < end_datetime)

    # 分页
    total_count = query.count()
    offset = (page - 1) * page_size
    orders = query.order_by(CheckOrderHeader.create_time.desc()).offset(offset).limit(page_size).all()

    # 构建响应数据
    result = []
    for order in orders:
        item_count = db.query(CheckOrderItem).filter(CheckOrderItem.header_id == order.id).count()
        result.append({
            "id": order.id,
            "order_no": order.order_no,
            "warehouse_id": order.warehouse_id,
            "warehouse_name": order.warehouse.name,
            "operator_id": order.operator_id,
            "operator_name": order.operator.full_name,
            "remark": order.remark,
            "status": order.status,
            "create_time": order.create_time,
            "start_time": order.start_time,
            "complete_time": order.complete_time,
            "item_count": item_count
        })

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "data": result
    }

# 获取盘点单详情（包含明细）
@router.get("/check-orders/{order_id}", response_model=CheckOrderFullResponse, summary="获取盘点单详情")
def get_check_order_detail(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询盘点单
    order = db.query(CheckOrderHeader).filter(CheckOrderHeader.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="盘点单不存在")

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无该仓库权限")

    # 查询明细
    items = db.query(CheckOrderItem).filter(CheckOrderItem.header_id == order_id).all()
    ensure_not_gsp_managed_goods(db, [item.goods_id for item in items])

    # 构建响应
    header_response = CheckOrderHeaderResponse(
        id=order.id,
        order_no=order.order_no,
        warehouse_id=order.warehouse_id,
        warehouse_name=order.warehouse.name,
        operator_id=order.operator_id,
        operator_name=order.operator.full_name,
        remark=order.remark,
        status=order.status,
        create_time=order.create_time,
        start_time=order.start_time,
        complete_time=order.complete_time,
        item_count=len(items)
    )

    items_response = []
    for item in items:
        items_response.append(CheckOrderItemResponse(
            id=item.id,
            goods_id=item.goods_id,
            goods_name=item.goods.name,
            goods_barcode=item.goods.barcode,
            location_id=item.location_id,
            location_code=item.location.location_code,
            location_name=item.location.name,
            check_quantity=item.check_quantity,
            actual_quantity=item.actual_quantity,
            diff_quantity=item.diff_quantity,
            create_time=item.create_time
        ))

    return {"header": header_response, "items": items_response}

# 添加盘点明细（扫码盘点）
class CheckOrderItemCreate(BaseModel):
    header_id: int
    goods_barcode: str
    location_code: str
    check_quantity: float

@router.post("/check-orders/items/", summary="添加盘点明细（扫码盘点）")
def add_check_order_item(
    item: CheckOrderItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询盘点单
    order = db.query(CheckOrderHeader).filter(CheckOrderHeader.id == item.header_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="盘点单不存在")

    # 检查盘点单状态
    if order.status == "COMPLETED":
        raise HTTPException(status_code=400, detail="盘点单已完成，无法添加明细")

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无该仓库权限")

    # 查询货物和库位
    goods = db.query(Goods).filter(Goods.barcode == item.goods_barcode).first()
    location = db.query(Location).filter(Location.location_code == item.location_code).first()

    if not goods or not location:
        raise HTTPException(status_code=404, detail="货物或库位不存在")
    ensure_not_gsp_managed_goods(db, [goods.id])

    # 检查货物和库位是否属于同一仓库
    if goods.warehouse_id != order.warehouse_id or location.warehouse_id != order.warehouse_id:
        raise HTTPException(status_code=400, detail="货物或库位不属于该盘点单仓库")

    # 获取系统库存
    stock = db.query(Stock).filter(
        Stock.goods_id == goods.id,
        Stock.location_id == location.id
    ).first()

    actual_quantity = stock.quantity if stock else 0.0

    # 计算差异
    diff_quantity = item.check_quantity - actual_quantity

    # 创建或更新明细
    existing_item = db.query(CheckOrderItem).filter(
        CheckOrderItem.header_id == item.header_id,
        CheckOrderItem.goods_id == goods.id,
        CheckOrderItem.location_id == location.id
    ).first()

    if existing_item:
        # 更新现有明细
        existing_item.check_quantity = item.check_quantity
        existing_item.actual_quantity = actual_quantity
        existing_item.diff_quantity = diff_quantity
        existing_item.create_time = datetime.now()
    else:
        # 创建新明细
        existing_item = CheckOrderItem(
            header_id=item.header_id,
            goods_id=goods.id,
            location_id=location.id,
            check_quantity=item.check_quantity,
            actual_quantity=actual_quantity,
            diff_quantity=diff_quantity
        )
        db.add(existing_item)

    # 如果盘点单状态是草稿，设置为盘点中
    if order.status == "DRAFT":
        order.status = "IN_PROGRESS"
        order.start_time = datetime.now()

    db.commit()
    db.refresh(existing_item)
    db.refresh(order)

    # 同时创建盘点记录（保留历史）
    db_record = CheckRecord(
        warehouse_id=order.warehouse_id,
        goods_id=goods.id,
        location_id=location.id,
        check_quantity=item.check_quantity,
        actual_quantity=actual_quantity,
        operator_id=current_user.id
    )
    db.add(db_record)
    db.commit()

    return {
        "id": existing_item.id,
        "goods_name": goods.name,
        "goods_barcode": goods.barcode,
        "location_code": location.location_code,
        "location_name": location.name,
        "check_quantity": existing_item.check_quantity,
        "actual_quantity": existing_item.actual_quantity,
        "diff_quantity": existing_item.diff_quantity,
        "order_status": order.status
    }

# 完成盘点
@router.post("/check-orders/{order_id}/complete", summary="完成盘点")
def complete_check_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询盘点单
    order = db.query(CheckOrderHeader).filter(CheckOrderHeader.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="盘点单不存在")

    # 检查盘点单状态
    if order.status == "COMPLETED":
        raise HTTPException(status_code=400, detail="盘点单已完成")

    if order.status == "DRAFT":
        raise HTTPException(status_code=400, detail="盘点单尚未开始，无法完成")

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无该仓库权限")

    # 设置为完成状态
    order.status = "COMPLETED"
    order.complete_time = datetime.now()
    db.commit()
    db.refresh(order)

    # 统计信息
    items = db.query(CheckOrderItem).filter(CheckOrderItem.header_id == order_id).all()
    ensure_not_gsp_managed_goods(db, [item.goods_id for item in items])
    total_items = len(items)
    matched_items = sum(1 for item in items if abs(item.diff_quantity) < 0.0001)
    diff_items = total_items - matched_items

    return {
        "order_no": order.order_no,
        "status": order.status,
        "complete_time": order.complete_time,
        "total_items": total_items,
        "matched_items": matched_items,
        "diff_items": diff_items,
        "message": "盘点完成"
    }

# 导出盘点报告
@router.get("/check-orders/{order_id}/export", summary="导出盘点报告")
def export_check_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询盘点单
    order = db.query(CheckOrderHeader).filter(CheckOrderHeader.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="盘点单不存在")

    # 权限校验
    if current_user.role != UserRole.ADMIN:
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无该仓库权限")

    # 查询明细
    items = db.query(CheckOrderItem).filter(CheckOrderItem.header_id == order_id).all()
    ensure_not_gsp_managed_goods(db, [item.goods_id for item in items])

    # 准备导出数据
    data = []
    for item in items:
        data.append({
            "序号": len(data) + 1,
            "货物名称": item.goods.name,
            "货物条码": item.goods.barcode,
            "规格": item.goods.spec or "",
            "单位": item.goods.unit,
            "库位编码": item.location.location_code,
            "库位名称": item.location.name,
            "系统库存": item.actual_quantity,
            "盘点数量": item.check_quantity,
            "差异": item.diff_quantity,
            "盘点时间": item.create_time.strftime("%Y-%m-%d %H:%M:%S")
        })

    # 创建 Excel 文件
    df = pd.DataFrame(data)
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')

    df.to_excel(writer, index=False, sheet_name='盘点明细')

    # 设置 Excel 格式
    worksheet = writer.sheets['盘点明细']
    # 自动调整列宽
    for i, width in enumerate([10, 30, 20, 20, 10, 15, 30, 15, 15, 15, 20]):
        worksheet.set_column(i, i, width)

    # 统计信息
    total_items = len(data)
    matched_items = sum(1 for item in items if abs(item.diff_quantity) < 0.0001)
    diff_items = total_items - matched_items

    worksheet.write(total_items + 2, 0, '合计')
    worksheet.write(total_items + 2, 6, f'总条数: {total_items}')
    worksheet.write(total_items + 3, 6, f'一致: {matched_items}')
    worksheet.write(total_items + 4, 6, f'差异: {diff_items}')

    writer.close()

    output.seek(0)

    # 返回文件响应
    return StreamingResponse(
        io.BytesIO(output.getvalue()),
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment; filename="盘点单_{order.order_no}.xlsx"'}
    )


# ------------------- 入库单管理接口 -------------------
@router.post("/inbound-orders/", response_model=InboundOrderHeaderResponse, summary="创建入库单")
def create_inbound_order(
    order: InboundOrderHeaderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建入库单（表头）"""
    try:
        # 检查用户是否有当前仓库
        if not current_user.current_warehouse_id:
            raise HTTPException(status_code=400, detail="请先选择当前仓库")

        # 检查用户是否有权限操作当前仓库
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == current_user.current_warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作当前仓库")

        # 生成单号
        order_no = generate_order_no("IN", db)

        # 创建入库单头
        new_order = InboundOrderHeader(
            order_no=order_no,
            warehouse_id=current_user.current_warehouse_id,
            supplier=order.supplier,
            operator_id=current_user.id,
            remark=order.remark,
            status="DRAFT"
        )

        db.add(new_order)
        db.commit()
        db.refresh(new_order)

        # 获取仓库名称
        warehouse = db.query(Warehouse).filter(Warehouse.id == new_order.warehouse_id).first()

        return {
            "id": new_order.id,
            "order_no": new_order.order_no,
            "warehouse_id": new_order.warehouse_id,
            "warehouse_name": warehouse.name if warehouse else "",
            "supplier": new_order.supplier,
            "operator_id": new_order.operator_id,
            "operator_name": current_user.full_name,
            "total_amount": new_order.total_amount,
            "remark": new_order.remark,
            "status": new_order.status,
            "create_time": new_order.create_time
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"创建入库单失败：{str(e)}")

@router.post("/inbound-orders/{order_id}/items", response_model=InboundOrderItemResponse, summary="添加入库单明细")
def add_inbound_order_item(
    order_id: int,
    item: InboundOrderItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """向入库单添加明细项"""
    try:
        # 检查订单是否存在且属于当前用户仓库
        order = db.query(InboundOrderHeader).filter(
            InboundOrderHeader.id == order_id
        ).first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查权限
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作此入库单")

        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="只能向草稿状态的单据添加明细")

        # 查询货物和库位
        goods = db.query(Goods).filter(Goods.barcode == item.goods_barcode).first()
        if not goods:
            raise HTTPException(status_code=404, detail="货物不存在")

        location = db.query(Location).filter(Location.location_code == item.location_code).first()
        if not location:
            raise HTTPException(status_code=404, detail="库位不存在")

        if location.warehouse_id != order.warehouse_id:
            raise HTTPException(status_code=400, detail="库位不属于入库单仓库")

        # 获取单价（如果未提供，使用货物默认单价）
        unit_price = item.unit_price if item.unit_price is not None else goods.price
        total_price = unit_price * item.quantity

        # 创建明细项
        new_item = InboundOrderItem(
            header_id=order_id,
            goods_id=goods.id,
            location_id=location.id,
            quantity=item.quantity,
            unit_price=unit_price,
            total_price=total_price,
            remark=item.remark
        )

        # 更新单据总金额
        order.total_amount = (order.total_amount or 0) + total_price

        db.add(new_item)
        db.commit()
        db.refresh(new_item)

        return {
            "id": new_item.id,
            "goods_id": new_item.goods_id,
            "goods_barcode": goods.barcode,
            "goods_name": goods.name,
            "location_id": new_item.location_id,
            "location_code": location.location_code,
            "quantity": new_item.quantity,
            "unit_price": new_item.unit_price,
            "total_price": new_item.total_price,
            "remark": new_item.remark
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"添加明细失败：{str(e)}")

@router.post("/inbound-orders/{order_id}/submit", summary="提交入库单")
def submit_inbound_order(
    order_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """提交入库单，更新库存"""
    try:
        # 获取订单
        order = db.query(InboundOrderHeader).filter(
            InboundOrderHeader.id == order_id
        ).first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查权限
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作此入库单")

        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="只能提交草稿状态的单据")

        # 检查是否有明细
        if not order.items:
            raise HTTPException(status_code=400, detail="入库单没有明细项")

        ensure_not_gsp_managed_goods(db, [item.goods_id for item in order.items])

        # 开始事务
        for item in order.items:
            # 更新库存
            stock = db.query(Stock).filter(
                Stock.warehouse_id == order.warehouse_id,
                Stock.goods_id == item.goods_id,
                Stock.location_id == item.location_id
            ).first()

            if stock:
                stock.quantity += item.quantity
                stock.update_time = datetime.now()
            else:
                stock = Stock(
                    warehouse_id=order.warehouse_id,
                    goods_id=item.goods_id,
                    location_id=item.location_id,
                    quantity=item.quantity
                )
                db.add(stock)

            # 记录出入库流水
            record = InventoryRecord(
                warehouse_id=order.warehouse_id,
                goods_id=item.goods_id,
                location_id=item.location_id,
                type=InventoryType.IN,
                quantity=item.quantity,
                operator_id=current_user.id,
                remark=f"入库单：{order.order_no}"
            )
            db.add(record)

        # 更新订单状态
        order.status = "COMPLETED"
        order.submit_time = datetime.now()
        order.complete_time = datetime.now()

        write_legacy_audit(
            db,
            actor_id=current_user.id,
            action="LEGACY_INBOUND_ORDER_COMPLETED",
            entity_type="InboundOrderHeader",
            entity_id=str(order.id),
            reason=order.remark or "旧版入库单提交",
            before_data={"status": "DRAFT"},
            after_data={"status": order.status, "order_no": order.order_no},
            request=request,
        )

        db.commit()

        return {"message": "入库单提交成功", "order_no": order.order_no}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"提交入库单失败：{str(e)}")

@router.get("/inbound-orders/", response_model=List[InboundOrderHeaderResponse], summary="获取入库单列表")
def get_inbound_orders(
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取入库单列表"""
    try:
        query = db.query(InboundOrderHeader).join(
            Warehouse, InboundOrderHeader.warehouse_id == Warehouse.id
        ).join(
            User, InboundOrderHeader.operator_id == User.id
        )
        controlled_order_ids = db.query(InboundOrderItem.header_id).filter(
            InboundOrderItem.goods_id.in_(gsp_managed_goods_query(db))
        )
        query = query.filter(InboundOrderHeader.id.notin_(controlled_order_ids))

        # 权限过滤
        if current_user.role != UserRole.ADMIN:
            # 获取用户有权限的仓库
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                query = query.filter(InboundOrderHeader.warehouse_id.in_(user_warehouse_ids))
            else:
                query = query.filter(InboundOrderHeader.warehouse_id == -1)  # 返回空结果

        # 状态过滤
        if status:
            query = query.filter(InboundOrderHeader.status == status)

        # 日期过滤
        if start_date:
            start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(InboundOrderHeader.create_time >= start_datetime)

        if end_date:
            end_datetime = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(InboundOrderHeader.create_time < end_datetime)

        orders = query.order_by(InboundOrderHeader.create_time.desc()).all()

        result = []
        for order in orders:
            result.append({
                "id": order.id,
                "order_no": order.order_no,
                "warehouse_id": order.warehouse_id,
                "warehouse_name": order.warehouse.name,
                "supplier": order.supplier,
                "operator_id": order.operator_id,
                "operator_name": order.operator.full_name,
                "total_amount": order.total_amount,
                "remark": order.remark,
                "status": order.status,
                "create_time": order.create_time,
                "submit_time": order.submit_time,
                "complete_time": order.complete_time,
                "item_count": len(order.items)
            })

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取入库单列表失败：{str(e)}")

@router.get("/inbound-orders/{order_id}", response_model=InboundOrderDetailResponse, summary="获取入库单详情")
def get_inbound_order_detail(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取入库单详情"""
    try:
        query = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id)

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                query = query.filter(InboundOrderHeader.warehouse_id.in_(user_warehouse_ids))
            else:
                raise HTTPException(status_code=403, detail="无权限查看此入库单")

        order = query.first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")
        if legacy_order_contains_gsp_goods(db, InboundOrderItem, order.id):
            raise HTTPException(409, "GSP药品历史入库单须通过批号追溯接口查询")

        # 获取明细
        items = []
        for item in order.items:
            items.append({
                "id": item.id,
                "goods_id": item.goods_id,
                "goods_barcode": item.goods.barcode,
                "goods_name": item.goods.name,
                "location_id": item.location_id,
                "location_code": item.location.location_code,
                "quantity": item.quantity,
                "unit_price": item.unit_price,
                "total_price": item.total_price,
                "remark": item.remark
            })

        return {
            "id": order.id,
            "order_no": order.order_no,
            "warehouse_id": order.warehouse_id,
            "warehouse_name": order.warehouse.name,
            "supplier": order.supplier,
            "operator_id": order.operator_id,
            "operator_name": order.operator.full_name,
            "total_amount": order.total_amount,
            "remark": order.remark,
            "status": order.status,
            "create_time": order.create_time,
            "submit_time": order.submit_time,
            "complete_time": order.complete_time,
            "item_count": len(order.items),
            "items": items
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取入库单详情失败：{str(e)}")


@router.put("/inbound-orders/{order_id}", response_model=InboundOrderHeaderResponse, summary="更新入库单")
def update_inbound_order(
    order_id: int,
    order: InboundOrderHeaderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """更新入库单（仅允许更新草稿状态的订单）"""
    try:
        # 查询订单
        db_order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()

        if not db_order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查订单状态
        if db_order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许更新草稿状态的入库单")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            # 检查订单是否属于当前用户可操作的仓库
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == db_order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此入库单")

        # 更新订单信息
        db_order.supplier = order.supplier
        db_order.remark = order.remark
        db.commit()
        db.refresh(db_order)

        # 返回更新后的订单
        return format_inbound_order_response(db_order)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"更新入库单失败：{str(e)}")

@router.put("/inbound-orders/{order_id}/items/{item_id}", response_model=InboundOrderItemResponse, summary="更新入库单明细")
def update_inbound_order_item(
    order_id: int,
    item_id: int,
    item: InboundOrderItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """更新入库单明细（仅允许更新草稿状态的订单的明细）"""
    try:
        # 查询订单
        order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许更新草稿状态的入库单的明细")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此入库单")

        # 查询明细项
        db_item = db.query(InboundOrderItem).filter(
            InboundOrderItem.id == item_id,
            InboundOrderItem.header_id == order_id
        ).first()

        if not db_item:
            raise HTTPException(status_code=404, detail="入库单明细不存在")

        # 查询货物信息
        goods = db.query(Goods).filter(Goods.barcode == item.goods_barcode).first()
        if not goods:
            raise HTTPException(status_code=404, detail="货物不存在")

        # 查询库位信息
        location = db.query(Location).filter(Location.location_code == item.location_code).first()
        if not location:
            raise HTTPException(status_code=404, detail="库位不存在")

        # 更新明细信息（goods/location 详情由响应端经关联读取，模型无冗余列）
        db_item.goods_id = goods.id
        db_item.location_id = location.id
        db_item.quantity = item.quantity
        db_item.unit_price = item.unit_price
        db_item.total_price = item.quantity * item.unit_price
        db_item.remark = item.remark
        db.commit()
        db.refresh(db_item)

        # 重新计算订单总金额
        recalculate_inbound_order_total(order_id, db)

        return format_inbound_order_item_response(db_item)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"更新入库单明细失败：{str(e)}")

@router.delete("/inbound-orders/{order_id}/items/{item_id}", summary="删除入库单明细")
def delete_inbound_order_item(
    order_id: int,
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除入库单明细（仅允许删除草稿状态的订单的明细）"""
    try:
        # 查询订单
        order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许删除草稿状态的入库单的明细")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此入库单")

        # 查询明细项
        db_item = db.query(InboundOrderItem).filter(
            InboundOrderItem.id == item_id,
            InboundOrderItem.header_id == order_id
        ).first()

        if not db_item:
            raise HTTPException(status_code=404, detail="入库单明细不存在")

        # 删除明细项
        db.delete(db_item)
        db.commit()

        # 重新计算订单总金额
        recalculate_inbound_order_total(order_id, db)

        return {"message": "入库单明细删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"删除入库单明细失败：{str(e)}")

@router.post("/inbound-orders/{order_id}/return", summary="退库")
def return_inbound_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """根据入库单创建退库出库单"""
    try:
        # 查询入库单
        inbound_order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()

        if not inbound_order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查订单状态
        if inbound_order.status != "COMPLETED":
            raise HTTPException(status_code=400, detail="仅允许对已完成的入库单进行退库操作")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == inbound_order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此入库单")

        # 检查是否已经有退库单（使用英文备注避免编码问题）
        existing_return_order = db.query(OutboundOrderHeader).filter(
            OutboundOrderHeader.remark.contains(f"Return: Original inbound order {inbound_order.order_no}")
        ).first()

        if existing_return_order:
            raise HTTPException(status_code=400, detail=f"该入库单已创建退库单 {existing_return_order.order_no}")

        # 生成退库出库单
        order_no = generate_order_no("OUT", db)
        outbound_order = OutboundOrderHeader(
            order_no=order_no,
            warehouse_id=inbound_order.warehouse_id,
            customer=inbound_order.supplier,  # 退库时客户填原供应商
            operator_id=current_user.id,
            total_amount=inbound_order.total_amount,
            remark=f"Return: Original inbound order {inbound_order.order_no}",
            status="DRAFT"
        )
        db.add(outbound_order)
        db.commit()
        db.refresh(outbound_order)

        # 转换入库单明细为出库单明细
        for inbound_item in inbound_order.items:
            outbound_item = OutboundOrderItem(
                header_id=outbound_order.id,
                goods_id=inbound_item.goods_id,
                location_id=inbound_item.location_id,
                quantity=inbound_item.quantity,
                unit_price=inbound_item.unit_price,
                total_price=inbound_item.total_price,
                remark="退库：原入库单明细"
            )
            db.add(outbound_item)

        db.commit()
        db.refresh(outbound_order)

        # 重新计算出库单总金额
        recalculate_outbound_order_total(outbound_order.id, db)

        return format_outbound_order_response(outbound_order)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"创建退库单失败：{str(e)}")

@router.delete("/inbound-orders/{order_id}", summary="删除入库单")
def delete_inbound_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除入库单（仅允许删除草稿状态的订单）"""
    try:
        # 查询订单
        order = db.query(InboundOrderHeader).filter(InboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="入库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许删除草稿状态的入库单")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            # 检查订单是否属于当前用户
            if order.operator_id != current_user.id:
                raise HTTPException(status_code=403, detail="无权限删除此入库单")

        # 删除订单（包括所有明细项）
        db.delete(order)
        db.commit()

        return {"message": "入库单删除成功"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"删除入库单失败：{str(e)}")

# ------------------- 出库单管理接口 -------------------
@router.post("/outbound-orders/", response_model=OutboundOrderHeaderResponse, summary="创建出库单")
def create_outbound_order(
    order: OutboundOrderHeaderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建出库单（表头）"""
    try:
        # 检查用户是否有当前仓库
        if not current_user.current_warehouse_id:
            raise HTTPException(status_code=400, detail="请先选择当前仓库")

        # 检查用户是否有权限操作当前仓库
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == current_user.current_warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作当前仓库")

        # 生成单号
        order_no = generate_order_no("OUT", db)

        # 创建出库单头
        new_order = OutboundOrderHeader(
            order_no=order_no,
            warehouse_id=current_user.current_warehouse_id,
            customer=order.customer,
            operator_id=current_user.id,
            remark=order.remark,
            status="DRAFT"
        )

        db.add(new_order)
        db.commit()
        db.refresh(new_order)

        # 获取仓库名称
        warehouse = db.query(Warehouse).filter(Warehouse.id == new_order.warehouse_id).first()

        return {
            "id": new_order.id,
            "order_no": new_order.order_no,
            "warehouse_id": new_order.warehouse_id,
            "warehouse_name": warehouse.name if warehouse else "",
            "customer": new_order.customer,
            "operator_id": new_order.operator_id,
            "operator_name": current_user.full_name,
            "total_amount": new_order.total_amount,
            "remark": new_order.remark,
            "status": new_order.status,
            "create_time": new_order.create_time
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"创建出库单失败：{str(e)}")

@router.post("/outbound-orders/{order_id}/items", response_model=OutboundOrderItemResponse, summary="添加出库单明细")
def add_outbound_order_item(
    order_id: int,
    item: OutboundOrderItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """向出库单添加明细项"""
    try:
        order = db.query(OutboundOrderHeader).filter(
            OutboundOrderHeader.id == order_id
        ).first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查权限
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作此出库单")

        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="只能向草稿状态的单据添加明细")

        # 查询货物和库位
        goods = db.query(Goods).filter(Goods.barcode == item.goods_barcode).first()
        if not goods:
            raise HTTPException(status_code=404, detail="货物不存在")

        location = db.query(Location).filter(Location.location_code == item.location_code).first()
        if not location:
            raise HTTPException(status_code=404, detail="库位不存在")

        if location.warehouse_id != order.warehouse_id:
            raise HTTPException(status_code=400, detail="库位不属于出库单仓库")

        # 检查库存是否足够
        stock = db.query(Stock).filter(
            Stock.warehouse_id == order.warehouse_id,
            Stock.goods_id == goods.id,
            Stock.location_id == location.id
        ).first()

        if not stock or stock.quantity < item.quantity:
            raise HTTPException(status_code=400, detail="库存不足")

        # 获取单价
        unit_price = item.unit_price if item.unit_price is not None else goods.price
        total_price = unit_price * item.quantity

        # 创建明细项
        new_item = OutboundOrderItem(
            header_id=order_id,
            goods_id=goods.id,
            location_id=location.id,
            quantity=item.quantity,
            unit_price=unit_price,
            total_price=total_price,
            remark=item.remark
        )

        # 更新单据总金额
        order.total_amount = (order.total_amount or 0) + total_price

        db.add(new_item)
        db.commit()
        db.refresh(new_item)

        return {
            "id": new_item.id,
            "goods_id": new_item.goods_id,
            "goods_barcode": goods.barcode,
            "goods_name": goods.name,
            "location_id": new_item.location_id,
            "location_code": location.location_code,
            "quantity": new_item.quantity,
            "unit_price": new_item.unit_price,
            "total_price": new_item.total_price,
            "remark": new_item.remark
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"添加明细失败：{str(e)}")

@router.post("/outbound-orders/{order_id}/submit", summary="提交出库单")
def submit_outbound_order(
    order_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """提交出库单，更新库存"""
    try:
        order = db.query(OutboundOrderHeader).filter(
            OutboundOrderHeader.id == order_id
        ).first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查权限
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == order.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作此出库单")

        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="只能提交草稿状态的单据")

        if not order.items:
            raise HTTPException(status_code=400, detail="出库单没有明细项")

        ensure_not_gsp_managed_goods(db, [item.goods_id for item in order.items])

        # 再次检查库存
        for item in order.items:
            stock = db.query(Stock).filter(
                Stock.warehouse_id == order.warehouse_id,
                Stock.goods_id == item.goods_id,
                Stock.location_id == item.location_id
            ).first()

            if not stock or stock.quantity < item.quantity:
                raise HTTPException(status_code=400, detail=f"货物{item.goods.name}库存不足")

        # 更新库存和记录流水
        for item in order.items:
            stock = db.query(Stock).filter(
                Stock.warehouse_id == order.warehouse_id,
                Stock.goods_id == item.goods_id,
                Stock.location_id == item.location_id
            ).first()

            stock.quantity -= item.quantity
            stock.update_time = datetime.now()

            # 记录出库流水
            record = InventoryRecord(
                warehouse_id=order.warehouse_id,
                goods_id=item.goods_id,
                location_id=item.location_id,
                type=InventoryType.OUT,
                quantity=item.quantity,
                operator_id=current_user.id,
                remark=f"出库单：{order.order_no}"
            )
            db.add(record)

        # 更新订单状态
        order.status = "COMPLETED"
        order.submit_time = datetime.now()
        order.complete_time = datetime.now()

        write_legacy_audit(
            db,
            actor_id=current_user.id,
            action="LEGACY_OUTBOUND_ORDER_COMPLETED",
            entity_type="OutboundOrderHeader",
            entity_id=str(order.id),
            reason=order.remark or "旧版出库单提交",
            before_data={"status": "DRAFT"},
            after_data={"status": order.status, "order_no": order.order_no},
            request=request,
        )

        db.commit()

        return {"message": "出库单提交成功", "order_no": order.order_no}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"提交出库单失败：{str(e)}")

@router.get("/outbound-orders/", response_model=List[OutboundOrderHeaderResponse], summary="获取出库单列表")
def get_outbound_orders(
    status: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取出库单列表"""
    try:
        query = db.query(OutboundOrderHeader).join(
            Warehouse, OutboundOrderHeader.warehouse_id == Warehouse.id
        ).join(
            User, OutboundOrderHeader.operator_id == User.id
        )
        controlled_order_ids = db.query(OutboundOrderItem.header_id).filter(
            OutboundOrderItem.goods_id.in_(gsp_managed_goods_query(db))
        )
        query = query.filter(OutboundOrderHeader.id.notin_(controlled_order_ids))

        if current_user.role != UserRole.ADMIN:
            # 获取用户有权限的仓库
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                query = query.filter(OutboundOrderHeader.warehouse_id.in_(user_warehouse_ids))
            else:
                query = query.filter(OutboundOrderHeader.warehouse_id == -1)  # 返回空结果

        if status:
            query = query.filter(OutboundOrderHeader.status == status)

        if start_date:
            start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(OutboundOrderHeader.create_time >= start_datetime)

        if end_date:
            end_datetime = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(OutboundOrderHeader.create_time < end_datetime)

        orders = query.order_by(OutboundOrderHeader.create_time.desc()).all()

        result = []
        for order in orders:
            result.append({
                "id": order.id,
                "order_no": order.order_no,
                "warehouse_id": order.warehouse_id,
                "warehouse_name": order.warehouse.name,
                "customer": order.customer,
                "operator_id": order.operator_id,
                "operator_name": order.operator.full_name,
                "total_amount": order.total_amount,
                "remark": order.remark,
                "status": order.status,
                "create_time": order.create_time,
                "submit_time": order.submit_time,
                "complete_time": order.complete_time,
                "item_count": len(order.items)
            })

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取出库单列表失败：{str(e)}")

@router.get("/outbound-orders/{order_id}", response_model=OutboundOrderDetailResponse, summary="获取出库单详情")
def get_outbound_order_detail(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取出库单详情"""
    try:
        query = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id)

        if current_user.role != UserRole.ADMIN:
            # 权限检查
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                query = query.filter(OutboundOrderHeader.warehouse_id.in_(user_warehouse_ids))
            else:
                raise HTTPException(status_code=403, detail="无权限查看此出库单")

        order = query.first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")
        if legacy_order_contains_gsp_goods(db, OutboundOrderItem, order.id):
            raise HTTPException(409, "GSP药品历史出库单须通过批号追溯接口查询")

        items = []
        for item in order.items:
            items.append({
                "id": item.id,
                "goods_id": item.goods_id,
                "goods_barcode": item.goods.barcode,
                "goods_name": item.goods.name,
                "location_id": item.location_id,
                "location_code": item.location.location_code,
                "quantity": item.quantity,
                "unit_price": item.unit_price,
                "total_price": item.total_price,
                "remark": item.remark
            })

        return {
            "id": order.id,
            "order_no": order.order_no,
            "warehouse_id": order.warehouse_id,
            "warehouse_name": order.warehouse.name,
            "customer": order.customer,
            "operator_id": order.operator_id,
            "operator_name": order.operator.full_name,
            "total_amount": order.total_amount,
            "remark": order.remark,
            "status": order.status,
            "create_time": order.create_time,
            "submit_time": order.submit_time,
            "complete_time": order.complete_time,
            "item_count": len(order.items),
            "items": items
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取出库单详情失败：{str(e)}")


@router.put("/outbound-orders/{order_id}", response_model=OutboundOrderHeaderResponse, summary="更新出库单")
def update_outbound_order(
    order_id: int,
    order: OutboundOrderHeaderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """更新出库单（仅允许更新草稿状态的订单）"""
    try:
        # 查询订单
        db_order = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id).first()

        if not db_order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查订单状态
        if db_order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许更新草稿状态的出库单")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            # 检查订单是否属于当前用户可操作的仓库
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == db_order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此出库单")

        # 更新订单信息
        db_order.customer = order.customer
        db_order.remark = order.remark
        db.commit()
        db.refresh(db_order)

        # 返回更新后的订单
        return format_outbound_order_response(db_order)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"更新出库单失败：{str(e)}")

@router.put("/outbound-orders/{order_id}/items/{item_id}", response_model=OutboundOrderItemResponse, summary="更新出库单明细")
def update_outbound_order_item(
    order_id: int,
    item_id: int,
    item: OutboundOrderItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """更新出库单明细（仅允许更新草稿状态的订单的明细）"""
    try:
        # 查询订单
        order = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许更新草稿状态的出库单的明细")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此出库单")

        # 查询明细项
        db_item = db.query(OutboundOrderItem).filter(
            OutboundOrderItem.id == item_id,
            OutboundOrderItem.header_id == order_id
        ).first()

        if not db_item:
            raise HTTPException(status_code=404, detail="出库单明细不存在")

        # 查询货物信息
        goods = db.query(Goods).filter(Goods.barcode == item.goods_barcode).first()
        if not goods:
            raise HTTPException(status_code=404, detail="货物不存在")

        # 查询库位信息
        location = db.query(Location).filter(Location.location_code == item.location_code).first()
        if not location:
            raise HTTPException(status_code=404, detail="库位不存在")

        # 更新明细信息（goods/location 详情由响应端经关联读取，模型无冗余列）
        db_item.goods_id = goods.id
        db_item.location_id = location.id
        db_item.quantity = item.quantity
        db_item.unit_price = item.unit_price
        db_item.total_price = item.quantity * item.unit_price
        db_item.remark = item.remark
        db.commit()
        db.refresh(db_item)

        # 重新计算订单总金额
        recalculate_outbound_order_total(order_id, db)

        return format_outbound_order_item_response(db_item)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"更新出库单明细失败：{str(e)}")

@router.delete("/outbound-orders/{order_id}/items/{item_id}", summary="删除出库单明细")
def delete_outbound_order_item(
    order_id: int,
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除出库单明细（仅允许删除草稿状态的订单的明细）"""
    try:
        # 查询订单
        order = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许删除草稿状态的出库单的明细")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            user_warehouse = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == current_user.id,
                UserWarehouse.warehouse_id == order.warehouse_id
            ).first()
            if not user_warehouse:
                raise HTTPException(status_code=403, detail="无权限操作此出库单")

        # 查询明细项
        db_item = db.query(OutboundOrderItem).filter(
            OutboundOrderItem.id == item_id,
            OutboundOrderItem.header_id == order_id
        ).first()

        if not db_item:
            raise HTTPException(status_code=404, detail="出库单明细不存在")

        # 删除明细项
        db.delete(db_item)
        db.commit()

        # 重新计算订单总金额
        recalculate_outbound_order_total(order_id, db)

        return {"message": "出库单明细删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"删除出库单明细失败：{str(e)}")

@router.delete("/outbound-orders/{order_id}", summary="删除出库单")
def delete_outbound_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除出库单（仅允许删除草稿状态的订单）"""
    try:
        # 查询订单
        order = db.query(OutboundOrderHeader).filter(OutboundOrderHeader.id == order_id).first()

        if not order:
            raise HTTPException(status_code=404, detail="出库单不存在")

        # 检查订单状态
        if order.status != "DRAFT":
            raise HTTPException(status_code=400, detail="仅允许删除草稿状态的出库单")

        # 权限检查
        if current_user.role != UserRole.ADMIN:
            # 检查订单是否属于当前用户
            if order.operator_id != current_user.id:
                raise HTTPException(status_code=403, detail="无权限删除此出库单")

        # 删除订单（包括所有明细项）
        db.delete(order)
        db.commit()

        return {"message": "出库单删除成功"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"删除出库单失败：{str(e)}")

# 包含路由到app
app.include_router(router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
