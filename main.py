from fastapi import FastAPI, HTTPException, Depends, status, Form, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
import enum
import logging

# ------------------- 配置项 -------------------
SECRET_KEY = "c00eb077-fb38-11f0-8000-4d5e10ca617a"  # 生产环境需更换为随机密钥
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
router = APIRouter()

# 数据库配置
DATABASE_URL = "postgresql://warehouse_user:cuwxwms@localhost:5432/warehouse_db"

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ------------------- 数据库初始化 -------------------
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------- 枚举定义 -------------------
class UserRole(str, enum.Enum):
    ADMIN = "admin"       # 仓库管理员，可管理所有数据
    OPERATOR = "operator" # 操作员，仅可做出入库和盘点

class InventoryType(str, enum.Enum):
    IN = "入库"
    OUT = "出库"

# ------------------- 数据库模型 -------------------
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
    create_time = Column(DateTime, default=datetime.now)
    current_warehouse_id = Column(Integer, nullable=True, comment="当前选择的仓库ID")
    
    # 多对多关联
    warehouses = relationship("Warehouse", secondary="user_warehouses",
                            backref="users", lazy="dynamic")

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

# 7. 盘点记录表
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

# 创建所有表
Base.metadata.create_all(bind=engine)

# ------------------- FastAPI应用初始化 -------------------
app = FastAPI(title="多仓库管理系统API")

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://10.80.101.39", "http://localhost", "http://127.0.0.1"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- 工具函数 -------------------
# 获取数据库会话
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 密码验证
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# 密码加密
def get_password_hash(password: str):
    return pwd_context.hash(password)

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
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    if user is None:
        raise credentials_exception
    return user

# 生成单据编号
def generate_order_no(prefix: str, db: Session) -> str:
    """生成单据编号"""
    today = datetime.now().strftime("%Y%m%d")
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
    
    class Config:
        json_encoders = {
            UserRole: lambda v: v.value  # 确保枚举被正确序列化
        }

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    warehouse_id: int
    warehouse_name: str
    role: UserRole
    
    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None

    class Config:
        json_encoders = {
            UserRole: lambda v: v.value
        }

class WarehouseCreate(BaseModel):
    code: str
    name: str
    address: Optional[str] = ""

class WarehouseResponse(BaseModel):
    id: int
    code: str
    name: str
    address: str
    
    class Config:
        from_attributes = True

class WarehouseUpdate(BaseModel):
    code: Optional[str] = None
    name: Optional[str] = None
    address: Optional[str] = None

class LocationCreate(BaseModel):
    warehouse_id: int
    location_code: str
    name: str

class LocationResponse(BaseModel):
    id: int
    warehouse_id: int
    location_code: str
    name: str
    
    class Config:
        from_attributes = True

class LocationUpdate(BaseModel):
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
    
    class Config:
        from_attributes = True

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
    
    class Config:
        from_attributes = True

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
    
    class Config:
        from_attributes = True

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
    
    class Config:
        from_attributes = True

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
    
    class Config:
        from_attributes = True

class OutboundOrderDetailResponse(OutboundOrderHeaderResponse):
    items: List[OutboundOrderItemResponse] = []

# ------------------- 认证接口 -------------------
@app.post("/token", summary="用户登录获取Token")
async def login_for_access_token(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
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
        data={"sub": user.username, "user_id": user.id, "role": user.role},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
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
@app.post("/users/", response_model=UserResponse, summary="新增用户")
async def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 权限校验：仅admin可创建用户
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    
    # 检查用户名是否存在
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    try:
        # 创建用户
        hashed_password = get_password_hash(user.password)
        new_user = User(
            username=user.username,
            hashed_password=hashed_password,
            full_name=user.full_name,
            role=user.role
        )
        db.add(new_user)
        db.flush()  # 先获取用户ID
        
        # 如果是管理员，分配所有现有仓库
        if user.role == UserRole.ADMIN:
            all_warehouses = db.query(Warehouse).filter(Warehouse.is_active == True).all()
            for i, warehouse in enumerate(all_warehouses):
                is_default = (i == 0)  # 第一个仓库设为默认
                user_warehouse = UserWarehouse(
                    user_id=new_user.id,
                    warehouse_id=warehouse.id,
                    is_default=is_default
                )
                db.add(user_warehouse)
            # 设置当前仓库（第一个仓库）
            if all_warehouses:
                new_user.current_warehouse_id = all_warehouses[0].id
        else:
            # 普通操作员，按传入的仓库分配
            for warehouse_id in user.warehouse_ids:
                warehouse = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
                if not warehouse:
                    raise HTTPException(status_code=400, detail=f"仓库ID {warehouse_id} 不存在")
                is_default = (user.warehouse_ids.index(warehouse_id) == 0)
                user_warehouse = UserWarehouse(
                    user_id=new_user.id,
                    warehouse_id=warehouse_id,
                    is_default=is_default
                )
                db.add(user_warehouse)
            # 设置当前仓库（第一个）
            if user.warehouse_ids:
                new_user.current_warehouse_id = user.warehouse_ids[0]
        
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"创建用户失败：{str(e)}")

# 用户切换仓库接口
@app.post("/users/{user_id}/switch-warehouse", summary="切换当前仓库")
async def switch_user_warehouse(
    user_id: int,
    warehouse_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
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
@app.get("/users/{user_id}/warehouses", summary="获取用户可管理的仓库")
async def get_user_warehouses(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限查看")
    
    user = db.query(User).filter(User.id == user_id).first()
    
    # 如果是管理员，返回所有仓库
    if user.role == UserRole.ADMIN:
        all_warehouses = db.query(Warehouse).filter(Warehouse.is_active == True).all()
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

# 获取所有用户
@app.get("/users/", summary="获取所有用户")
async def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 权限校验：仅管理员可查看所有用户
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限查看用户列表")
    
    users = db.query(User).filter(User.is_active == True).all()
    
    # 返回简化用户信息
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active
        })
    return result

# 修改用户（仅管理员可操作）
@app.put("/users/{user_id}", summary="修改用户信息")
async def update_user(
    user_id: int,
    user_update: UserUpdate,
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
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    if user_update.password:
        user.hashed_password = get_password_hash(user_update.password)

    db.commit()
    return {"message": "用户更新成功"}

# 为用户分配/取消分配仓库
@app.post("/users/{user_id}/assign-warehouse", summary="为用户分配仓库")
async def assign_warehouse_to_user(
    user_id: int,
    warehouse_id: int,
    is_default: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    
    # 检查是否已分配
    existing = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == user_id,
        UserWarehouse.warehouse_id == warehouse_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="已分配该仓库给用户")
    
    # 如果是设为默认，先取消其他默认
    if is_default:
        db.query(UserWarehouse).filter(
            UserWarehouse.user_id == user_id,
            UserWarehouse.is_default == True
        ).update({"is_default": False})
    
    # 分配新仓库
    user_warehouse = UserWarehouse(
        user_id=user_id,
        warehouse_id=warehouse_id,
        is_default=is_default
    )
    db.add(user_warehouse)
    
    # 如果用户没有当前仓库，设置为当前仓库
    user = db.query(User).filter(User.id == user_id).first()
    if not user.current_warehouse_id:
        user.current_warehouse_id = warehouse_id
    
    db.commit()
    return {"message": "仓库分配成功"}

@app.delete("/users/{user_id}/unassign-warehouse", summary="取消用户仓库分配")
async def unassign_warehouse_from_user(
    user_id: int,
    warehouse_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    
    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == user_id,
        UserWarehouse.warehouse_id == warehouse_id
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=404, detail="未找到分配记录")
    
    db.delete(user_warehouse)
    
    # 如果这是用户的当前仓库，需要重新设置
    user = db.query(User).filter(User.id == user_id).first()
    if user.current_warehouse_id == warehouse_id:
        # 尝试找默认仓库，没有就找第一个
        default = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == user_id,
            UserWarehouse.is_default == True
        ).first()
        if default:
            user.current_warehouse_id = default.warehouse_id
        else:
            first = db.query(UserWarehouse).filter(
                UserWarehouse.user_id == user_id
            ).first()
            user.current_warehouse_id = first.warehouse_id if first else None
    
    db.commit()
    return {"message": "取消分配成功"}

# ------------------- 仓库管理接口 -------------------
@app.post("/warehouses/", response_model=WarehouseResponse, summary="新增仓库")
async def create_warehouse(
    warehouse: WarehouseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    
    db_warehouse = db.query(Warehouse).filter(Warehouse.code == warehouse.code).first()
    if db_warehouse:
        raise HTTPException(status_code=400, detail="仓库编码已存在")
    
    new_warehouse = Warehouse(**warehouse.dict())
    db.add(new_warehouse)
    db.flush()  # 获取新仓库的ID
    
    # 自动将新仓库分配给所有管理员
    admin_users = db.query(User).filter(User.role == UserRole.ADMIN).all()
    for admin in admin_users:
        # 检查是否已经分配（理论上不会，因为是新建的仓库）
        existing = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == admin.id,
            UserWarehouse.warehouse_id == new_warehouse.id
        ).first()
        if not existing:
            user_warehouse = UserWarehouse(
                user_id=admin.id,
                warehouse_id=new_warehouse.id,
                is_default=False  # 不设为默认，保持原有默认仓库
            )
            db.add(user_warehouse)
    
    db.commit()
    db.refresh(new_warehouse)
    return new_warehouse

@app.get("/warehouses/", response_model=List[WarehouseResponse], summary="获取所有仓库")
async def get_warehouses(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == UserRole.ADMIN:
        return db.query(Warehouse).filter(Warehouse.is_active == True).all()
    else:
        # 非管理员只返回自己有权限的仓库
        user_warehouse_ids = [
            uw.warehouse_id for uw in 
            db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
        ]
        if user_warehouse_ids:
            return db.query(Warehouse).filter(
                Warehouse.id.in_(user_warehouse_ids),
                Warehouse.is_active == True
            ).all()
        else:
            return []

@app.put("/warehouses/{id}", response_model=WarehouseResponse, summary="修改仓库信息")
async def update_warehouse(
    id: int,
    warehouse: WarehouseUpdate,  # 使用 Pydantic 模型
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    
    db_warehouse = db.query(Warehouse).filter(Warehouse.id == id).first()
    if not db_warehouse:
        raise HTTPException(status_code=404, detail="仓库未找到")
    
    # 只更新提供的字段
    for key, value in warehouse.dict(exclude_unset=True).items():
        setattr(db_warehouse, key, value)
    
    db.commit()
    db.refresh(db_warehouse)
    return db_warehouse

# ------------------- 库位管理接口 -------------------
@app.post("/locations/", response_model=LocationResponse, summary="新增库位")
async def create_location(
    location: LocationCreate, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # 检查用户是否有权限在该仓库操作
    user_warehouse = db.query(UserWarehouse).filter(
        UserWarehouse.user_id == current_user.id,
        UserWarehouse.warehouse_id == location.warehouse_id
    ).first()
    if not user_warehouse:
        raise HTTPException(status_code=403, detail="无权限在此仓库操作")
    
    db_location = db.query(Location).filter(Location.location_code == location.location_code).first()
    if db_location:
        raise HTTPException(status_code=400, detail="库位编码已存在")
    
    new_location = Location(**location.dict())
    db.add(new_location)
    db.commit()
    db.refresh(new_location)
    return new_location

@app.get("/locations/", response_model=List[LocationResponse], summary="获取库位列表")
async def get_locations(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    try:
        # 如果是管理员，返回所有库位
        if current_user.role == UserRole.ADMIN:
            locations = db.query(Location).filter(Location.is_active == True).all()
        else:
            # 非管理员，获取用户可管理的所有仓库ID
            user_warehouse_ids = [
                uw.warehouse_id for uw in
                db.query(UserWarehouse).filter(UserWarehouse.user_id == current_user.id).all()
            ]
            if user_warehouse_ids:
                locations = db.query(Location).filter(
                    Location.is_active == True,
                    Location.warehouse_id.in_(user_warehouse_ids)
                ).all()
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
                "name": loc.name
            })
        return result
    except Exception as e:
        # 记录错误日志
        print(f"获取库位列表出错: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"获取库位列表失败: {str(e)}"
        )

@app.put("/locations/{id}", response_model=LocationResponse, summary="修改库位信息")
async def update_location(
    id: int,
    location: LocationUpdate,  
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 检查权限
    db_location = db.query(Location).filter(Location.id == id).first()
    if not db_location:
        raise HTTPException(status_code=404, detail="库位未找到")
    
    if current_user.role != UserRole.ADMIN:
        # 检查用户是否有权限操作这个仓库
        user_warehouse = db.query(UserWarehouse).filter(
            UserWarehouse.user_id == current_user.id,
            UserWarehouse.warehouse_id == db_location.warehouse_id
        ).first()
        if not user_warehouse:
            raise HTTPException(status_code=403, detail="无权限操作")
    
    for key, value in location.dict(exclude_unset=True).items():
        setattr(db_location, key, value)
    
    db.commit()
    db.refresh(db_location)
    return db_location

@app.delete("/locations/{id}", summary="删除库位")
async def delete_location(
    id: int, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="无权限操作")
    
    db_location = db.query(Location).filter(Location.id == id).first()
    if not db_location:
        raise HTTPException(status_code=404, detail="库位未找到")
    
    db.delete(db_location)
    db.commit()
    return {"message": "删除成功"}

# ------------------- 货物管理接口 -------------------
@app.post("/goods/", response_model=GoodsResponse, summary="新增货物")
async def create_goods(
    goods: GoodsCreate, 
    current_user: User = Depends(get_current_user), 
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

@app.get("/goods/", response_model=List[GoodsResponse], summary="获取所有货物")
async def get_goods(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    return db.query(Goods).all()

@app.put("/goods/{id}", response_model=GoodsResponse, summary="修改货物信息")
async def update_goods(
    id: int,
    goods: GoodsUpdate,
    current_user: User = Depends(get_current_user),
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

@app.delete("/goods/{id}", summary="删除货物")
async def delete_goods(
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

# ------------------- 扫码出入库接口 -------------------
@app.post("/inventory/scan", summary="扫码出入库")
async def scan_inventory(
    inventory: InventoryCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. 查询货物
    goods = db.query(Goods).filter(Goods.barcode == inventory.goods_barcode).first()
    if not goods:
        raise HTTPException(status_code=404, detail="货物不存在")
    
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
    ).first()
    
    if inventory.type == InventoryType.IN:
        # 入库
        if not stock:
            stock = Stock(
                warehouse_id=warehouse_id,
                goods_id=goods.id,
                location_id=location.id,
                quantity=inventory.quantity
            )
            db.add(stock)
        else:
            stock.quantity += inventory.quantity
    else:
        # 出库
        if not stock or stock.quantity < inventory.quantity:
            raise HTTPException(status_code=400, detail="库存不足")
        stock.quantity -= inventory.quantity
    
    # 4. 记录出入库日志
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
    db.commit()
    
    return {
        "message": f"{inventory.type}成功",
        "goods_name": goods.name,
        "location_name": location.name,
        "current_stock": stock.quantity
    }

# ------------------- 库存查询接口（带仓库+库位） -------------------
@app.get("/stock/", response_model=List[StockResponse], summary="库存查询（带仓库库位）")
async def get_stock(
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    query = (
        db.query(Stock)
        .join(Warehouse, Stock.warehouse_id == Warehouse.id)
        .join(Goods, Stock.goods_id == Goods.id)
        .join(Location, Stock.location_id == Location.id)
    )
    
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
    result = []
    for stock in stocks:
        result.append({
            "id": stock.id,
            "warehouse_name": stock.warehouse.name,
            "goods_name": stock.goods.name,
            "goods_barcode": stock.goods.barcode,
            "location_code": stock.location.location_code,
            "location_name": stock.location.name,
            "quantity": stock.quantity,
            "update_time": stock.update_time
        })
    return result

# ------------------- 扫码盘点接口 -------------------
@app.post("/check/scan", summary="扫码盘点")
async def scan_check(
    check: CheckCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 查询货物和库位
    goods = db.query(Goods).filter(Goods.barcode == check.goods_barcode).first()
    location = db.query(Location).filter(Location.location_code == check.location_code).first()
    
    if not goods or not location:
        raise HTTPException(status_code=404, detail="货物或库位不存在")
    
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
    db.commit()
    
    return {
        "goods_name": goods.name,
        "location_name": location.name,
        "check_quantity": check.check_quantity,
        "actual_quantity": actual_quantity,
        "diff": check.check_quantity - actual_quantity,
        "message": "库存一致" if actual_quantity == check.check_quantity else "库存不符"
    }

# 获取盘点记录
@app.get("/check/records", summary="获取盘点记录")
async def get_check_records(
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
@app.get("/check/stats", summary="获取盘点统计")
async def get_check_stats(
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
@app.get("/check/diffs", summary="获取盘点差异报表")
async def get_check_diffs(
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

# ------------------- 入库单管理接口 -------------------
@app.post("/inbound-orders/", response_model=InboundOrderHeaderResponse, summary="创建入库单")
async def create_inbound_order(
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

@app.post("/inbound-orders/{order_id}/items", response_model=InboundOrderItemResponse, summary="添加入库单明细")
async def add_inbound_order_item(
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

@app.post("/inbound-orders/{order_id}/submit", summary="提交入库单")
async def submit_inbound_order(
    order_id: int,
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
        
        db.commit()
        
        return {"message": "入库单提交成功", "order_no": order.order_no}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"提交入库单失败：{str(e)}")

@app.get("/inbound-orders/", response_model=List[InboundOrderHeaderResponse], summary="获取入库单列表")
async def get_inbound_orders(
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

@app.get("/inbound-orders/{order_id}", response_model=InboundOrderDetailResponse, summary="获取入库单详情")
async def get_inbound_order_detail(
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

# ------------------- 出库单管理接口 -------------------
@app.post("/outbound-orders/", response_model=OutboundOrderHeaderResponse, summary="创建出库单")
async def create_outbound_order(
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

@app.post("/outbound-orders/{order_id}/items", response_model=OutboundOrderItemResponse, summary="添加出库单明细")
async def add_outbound_order_item(
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

@app.post("/outbound-orders/{order_id}/submit", summary="提交出库单")
async def submit_outbound_order(
    order_id: int,
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
        
        db.commit()
        
        return {"message": "出库单提交成功", "order_no": order.order_no}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"提交出库单失败：{str(e)}")

@app.get("/outbound-orders/", response_model=List[OutboundOrderHeaderResponse], summary="获取出库单列表")
async def get_outbound_orders(
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

@app.get("/outbound-orders/{order_id}", response_model=OutboundOrderDetailResponse, summary="获取出库单详情")
async def get_outbound_order_detail(
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

# 包含路由到app
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
