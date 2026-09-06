"""并发扫码库存一致性回归（P0-4 / 审核评审问题 3、4）。

覆盖 scan_inventory 的行锁、并发首笔入库冲突处理与并发出库不超卖：
- 两事务并发首笔入库同一 (warehouse, goods, location) 行时，唯一约束冲突后
  重取行锁累加，最终库存正确；
- 预置库存下并发出库，总量不足的一方必须被拒（400），库存不得为负
  （行锁序列化 + CHECK(quantity >= 0) 兜底）；
- 每次用例结束清理本用例创建的全部数据，避免污染共享 PG 测试库
  （曾导致 test_gsp_managed_product_cannot_use_legacy_stock_mutation 误报）。

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
    from app.legacy import Goods, Location, User, UserRole, UserWarehouse, Warehouse

    engine = create_engine(os.environ["DATABASE_URL"])
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    u = User(username=f"cc-{uuid4().hex[:10]}", hashed_password="x",
             full_name="cc", role=UserRole.OPERATOR, is_active=True)
    w = Warehouse(code=f"WH-{uuid4().hex[:8]}", name="cc", is_active=True)
    g = Goods(barcode=f"CC-{uuid4().hex[:10]}", name="cc-goods",
              spec="盒", unit="盒", price=1.0)
    db.add_all([u, w, g])
    db.flush()
    loc = Location(warehouse_id=w.id, location_code=f"LC-{uuid4().hex[:8]}", name="cc-loc")
    db.add(loc)
    db.flush()
    db.add(UserWarehouse(user_id=u.id, warehouse_id=w.id))
    db.commit()

    ids = {"user": u.id, "warehouse": w.id, "goods": g.id, "location": loc.id}

    def _cleanup():
        from app.gsp.models import GspAuditEvent
        from app.legacy import (
            Goods,
            InboundOrderHeader,
            InboundOrderItem,
            InventoryRecord,
            Location,
            OutboundOrderHeader,
            OutboundOrderItem,
            Stock,
            User,
            UserWarehouse,
            Warehouse,
        )

        c = db
        c.query(InboundOrderItem).filter(
            InboundOrderItem.header_id.in_(
                c.query(InboundOrderHeader.id).filter_by(warehouse_id=ids["warehouse"])
            )).delete(synchronize_session=False)
        c.query(InboundOrderHeader).filter_by(warehouse_id=ids["warehouse"]).delete(synchronize_session=False)
        c.query(OutboundOrderItem).filter(
            OutboundOrderItem.header_id.in_(
                c.query(OutboundOrderHeader.id).filter_by(warehouse_id=ids["warehouse"])
            )).delete(synchronize_session=False)
        c.query(OutboundOrderHeader).filter_by(warehouse_id=ids["warehouse"]).delete(synchronize_session=False)
        c.query(InventoryRecord).filter_by(goods_id=ids["goods"]).delete(synchronize_session=False)
        c.query(Stock).filter_by(goods_id=ids["goods"]).delete(synchronize_session=False)
        c.query(GspAuditEvent).filter_by(actor_user_id=ids["user"]).delete(synchronize_session=False)
        c.query(UserWarehouse).filter_by(user_id=ids["user"]).delete(synchronize_session=False)
        c.query(Location).filter_by(id=ids["location"]).delete(synchronize_session=False)
        c.query(Goods).filter_by(id=ids["goods"]).delete(synchronize_session=False)
        c.query(Warehouse).filter_by(id=ids["warehouse"]).delete(synchronize_session=False)
        c.query(User).filter_by(id=ids["user"]).delete(synchronize_session=False)
        c.commit()

    yield {"db": db, "Session": Session, "u": u, "g": g, "loc": loc}
    try:
        _cleanup()
    except Exception:  # noqa: BLE001
        db.rollback()
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
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"不应有未处理异常：{errors}"
    stock = ctx["db"].query(Stock).filter_by(goods_id=ctx["g"].id,
                                             location_id=ctx["loc"].id).one()
    assert stock.quantity == 6.0, f"并发两次首笔入库后应为 6，实际 {stock.quantity}"


def test_concurrent_outbound_never_oversells(ctx):
    """预置库存 10，两线程各出库 7：总量 14 > 10，至少一方被拒，库存非负且为 3。"""
    from fastapi import HTTPException

    from app.legacy import InventoryCreate, InventoryType, Stock

    db = ctx["db"]
    db.add(Stock(goods_id=ctx["g"].id, location_id=ctx["loc"].id, quantity=10.0))
    db.commit()

    inv = InventoryCreate(goods_barcode=ctx["g"].barcode,
                          location_code=ctx["loc"].location_code,
                          quantity=7.0, type=InventoryType.OUT, remark="cc-out")
    outcomes = []

    def run():
        s = ctx["Session"]()
        try:
            _call(s, inv, ctx["u"])
            outcomes.append("ok")
        except HTTPException as e:
            outcomes.append(e.status_code)
        except Exception as e:  # noqa: BLE001
            outcomes.append(repr(e))
        finally:
            s.close()

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert "ok" in outcomes, f"至少一方出库成功：{outcomes}"
    # 行锁串行化后第二笔余额必然不足，被拒为 400
    assert any(o == 400 for o in outcomes), f"应有一方因余额不足被拒：{outcomes}"

    stock = db.query(Stock).filter_by(goods_id=ctx["g"].id, location_id=ctx["loc"].id).one()
    assert stock.quantity == 3.0, f"并发出库后库存应为 3（10-7），实际 {stock.quantity}"
    assert stock.quantity >= 0
