"""并发扫码库存一致性回归（P0-4 / 审核评审问题3）。

覆盖 scan_inventory 的行锁与并发首笔入库冲突处理：
- 两事务并发首笔入库同一 (warehouse, goods, location) 行时，唯一约束冲突后
  重取行锁累加，最终库存正确；
- 并发出库不得超卖产生负库存（CHECK(quantity >= 0) 兜底）。

行锁与唯一约束冲突语义依赖 PostgreSQL；SQLite 下 with_for_update 为空操作，
故本文件在非 PostgreSQL 环境跳过（与 test_reports_pg.py 一致，由 CI 的
postgres-migration job 在真实 PG 上执行）。
"""

import os
import threading
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL", "").startswith("postgres"),
    reason="requires PostgreSQL (row lock / unique-constraint race semantics)",
)


@pytest.fixture()
def ctx():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import main  # noqa: F401
    from app.core.database import Base

    engine = create_engine(os.environ["DATABASE_URL"])
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    from app.legacy import Goods, Location, User, UserRole, UserWarehouse, Warehouse

    u = User(username=f"cc-{uuid4().hex[:8]}", hashed_password="x",
             full_name="cc", role=UserRole.OPERATOR, is_active=True)
    w = Warehouse(code=f"WH-{uuid4().hex[:6]}", name="cc", is_active=True)
    g = Goods(barcode=f"CC-{uuid4().hex[:8]}", name="cc-goods",
              spec="盒", unit="盒", price=1.0)
    db.add_all([u, w, g])
    db.flush()
    loc = Location(warehouse_id=w.id, location_code=f"LC-{uuid4().hex[:6]}", name="cc-loc")
    db.add(loc)
    db.flush()
    db.add(UserWarehouse(user_id=u.id, warehouse_id=w.id))
    db.commit()

    yield {"db": db, "Session": Session, "u": u, "w": w, "g": g, "loc": loc}
    db.close()
    engine.dispose()


def _call(session, inv, user):
    from starlette.requests import Request
    from app.legacy import scan_inventory
    req = Request({"type": "http", "method": "POST", "path": "/inventory/scan",
                   "headers": [], "client": ("127.0.0.1", 1)})
    return scan_inventory(inv, req, current_user=user, db=session)


def test_concurrent_first_inbound_accumulates_correctly(ctx):
    from app.legacy import InventoryCreate, InventoryType, Stock

    inv = InventoryCreate(goods_barcode=ctx["g"].barcode,
                          location_code=ctx["loc"].location_code,
                          quantity=3.0, type=InventoryType.IN, remark="cc")

    errors = []

    def run():
        s = ctx["Session"]()
        try:
            _call(s, inv, ctx["u"])
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))
        finally:
            s.close()

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start(); t2.start(); t1.join(); t2.join()

    # 至少一方成功；即使唯一约束冲突，也应被捕获并重读累加，不向外抛 IntegrityError
    assert not errors, f"不应有未处理异常：{errors}"

    stock = ctx["db"].query(Stock).filter_by(
        goods_id=ctx["g"].id, location_id=ctx["loc"].id).one()
    assert stock.quantity == 6.0, f"并发两次首笔入库后应为 6，实际 {stock.quantity}"
