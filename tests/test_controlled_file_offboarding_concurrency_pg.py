"""并发"业务绑定受控文件" vs "上传人停用级联" 一致性回归（审核 P1 / P1-2 竞态）。

背景竞态（修复前）：
- 停用上传人时 ``deactivate_user_access`` -> ``_deactivate_uploaded_controlled_files``
  先 SELECT ACTIVE 受控文件（不带行锁），再 ``referenced_by_business`` 检查业务引用；
- 业务绑定流程 ``bindings.resolve_attachment`` 用 ``with_for_update()`` 锁文件行后，
  向 ``gsp_partner_documents`` 等表插入引用并提交。

若停用事务的引用检查跑在并发绑定事务提交之前，就看不到尚未提交的引用，随后把
"刚被绑定为证据"的受控文件误置 DISABLED -> 证据文件无法再下载（虽然引用已落库）。

修复：停用侧同样先 ``with_for_update()`` 锁定候选文件行、再检查引用并决定停用，
与绑定侧的 FOR UPDATE 互斥串行化，杜绝"已提交引用 + 文件被禁"的不一致态。

行锁/FOR UPDATE 语义依赖 PostgreSQL；SQLite 下 with_for_update 为空操作，故本文件
在非 PostgreSQL 环境跳过（与 test_inventory_concurrency_pg.py 一致，由 CI 的
postgres job 在真实 PG 上执行）。
"""

import threading
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not __import__("os").environ.get("DATABASE_URL", "").startswith("postgres"),
    reason="requires PostgreSQL (row-lock race semantics)",
)


@pytest.fixture()
def ctx():
    from datetime import date

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import main  # noqa: F401 - registers all tables on Base
    from app.core.database import Base
    from app.core.time import utc_now
    from app.gsp.attachments.models import GspControlledFile
    from app.gsp.models import GspBusinessPartner, GspPartnerDocument
    from app.legacy import User, UserRole, UserWarehouse, Warehouse

    engine = create_engine(__import__("os").environ["DATABASE_URL"])
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # 被停用的上传人 uploader；执行停用的操作者 actor（deactivate 禁止停用自己）
    uploader = User(
        username=f"up-{uuid4().hex[:10]}", hashed_password="x",
        full_name="uploader", role=UserRole.OPERATOR, is_active=True,
    )
    actor = User(
        username=f"act-{uuid4().hex[:10]}", hashed_password="x",
        full_name="actor", role=UserRole.ADMIN, is_active=True,
    )
    w = Warehouse(code=f"WH-{uuid4().hex[:8]}", name="offboard-w", is_active=True)
    db.add_all([uploader, actor, w])
    db.flush()
    db.add(UserWarehouse(user_id=uploader.id, warehouse_id=w.id))
    db.flush()

    partner = GspBusinessPartner(
        code=f"P-{uuid4().hex[:8]}", name="offboard-partner",
        partner_type="SUPPLIER", license_no=f"LN-{uuid4().hex[:8]}",
        license_scope="药品经营", license_valid_to=date(2035, 12, 31),
        status="APPROVED", created_by=actor.id,
    )
    db.add(partner)
    db.flush()

    # 由 uploader 上传的一个 ACTIVE 受控证据文件
    cfile = GspControlledFile(
        object_key=uuid4().hex,
        file_name="evidence.pdf",
        content_type="application/pdf",
        size_bytes=12,
        sha256="a" * 64,
        purpose="PARTNER_DOCUMENT",
        status="ACTIVE",
        uploaded_by=uploader.id,
        uploaded_at=utc_now(),
    )
    db.add(cfile)
    db.commit()

    ids = {"uploader": uploader.id, "actor": actor.id, "partner": partner.id,
           "warehouse": w.id, "file": cfile.id, "key": cfile.object_key}

    def _cleanup():
        c = db
        c.query(GspPartnerDocument).filter_by(partner_id=ids["partner"]).delete(synchronize_session=False)
        c.query(GspControlledFile).filter_by(id=ids["file"]).delete(synchronize_session=False)
        from app.gsp.models import GspAuditEvent
        c.query(GspAuditEvent).filter_by(actor_user_id=ids["actor"]).delete(synchronize_session=False)
        c.query(UserWarehouse).filter_by(user_id=ids["uploader"]).delete(synchronize_session=False)
        c.query(GspBusinessPartner).filter_by(id=ids["partner"]).delete(synchronize_session=False)
        c.query(Warehouse).filter_by(id=ids["warehouse"]).delete(synchronize_session=False)
        from app.legacy import User as _U
        c.query(_U).filter(_U.id.in_([ids["uploader"], ids["actor"]])).delete(synchronize_session=False)
        c.commit()

    yield {"db": db, "Session": Session, "ids": ids,
           "uploader": uploader, "actor": actor, "cfile": cfile}
    try:
        _cleanup()
    except Exception:  # noqa: BLE001
        db.rollback()
    db.close()
    engine.dispose()


def _do_bind_and_commit(Session, ids, actor_id):
    """模拟业务绑定：FOR UPDATE 锁定受控文件行 -> 校验通过 -> 插入引用 -> 提交。"""
    from datetime import date

    from app.core.time import utc_now
    from app.gsp.attachments import bindings
    from app.gsp.attachments.models import GspControlledFile
    from app.gsp.attachments.refs import build_ref
    from app.gsp.models import GspPartnerDocument

    s = Session()
    try:
        # 与业务创建流程同构：resolve_attachment 内部对文件行 with_for_update() 加锁并校验 ACTIVE。
        # 此处额外 with_for_update() 再取一次行，确保本事务在插入引用前已持有该行锁。
        token = build_ref(ids["key"])
        _obj = (
            s.query(GspControlledFile)
            .filter(GspControlledFile.id == ids["file"])
            .with_for_update()
            .one()
        )
        file_ref, sha, size = bindings.resolve_attachment(
            s, value=token, expected_purpose="PARTNER_DOCUMENT",
        )
        assert file_ref == token, "受控引用解析应返回令牌引用"
        doc = GspPartnerDocument(
            partner_id=ids["partner"],
            document_type="QUALIFICATION",
            valid_to=date(2035, 12, 31),
            file_ref=file_ref,
            file_sha256=sha,
            file_size_bytes=size,
            created_by=actor_id,
            status="PENDING",
            created_at=utc_now(),
        )
        s.add(doc)
        s.commit()
        return ("bound", _obj.object_key)
    except Exception as e:  # noqa: BLE001
        s.rollback()
        return ("bind_error", repr(e))
    finally:
        s.close()


def _do_offboard(Session, ids, uploader_id, actor_id):
    """模拟停用上传人：deactivate_user_access（含 FOR UPDATE 行锁 + 引用检查级联）。"""
    from fastapi import HTTPException

    from app.gsp.access_control import deactivate_user_access
    from app.legacy import User

    s = Session()
    try:
        target = s.query(User).filter(User.id == uploader_id).one()
        deactivate_user_access(
            s, user=target, actor_id=actor_id, reason="offboard-test",
            source_ip="127.0.0.1",
        )
        s.commit()
        return ("offboarded", None)
    except HTTPException as e:
        s.rollback()
        return ("offboard_http", e.status_code)
    except Exception as e:  # noqa: BLE001
        s.rollback()
        return ("offboard_error", repr(e))
    finally:
        s.close()


def _committed_reference_to_disabled_file(db, ids) -> bool:
    """存在引用已提交到 gsp_partner_documents、但其文件被 DISABLED 的不一致态？"""
    from app.gsp.attachments.models import STATUS_DISABLED, GspControlledFile
    from app.gsp.attachments.refs import build_ref
    from app.gsp.models import GspPartnerDocument

    token = build_ref(ids["key"])
    bound = (
        db.query(GspPartnerDocument)
        .filter(GspPartnerDocument.file_ref == token)
        .count()
    )
    f = db.query(GspControlledFile).filter(GspControlledFile.id == ids["file"]).one()
    return bound > 0 and f.status == STATUS_DISABLED


def test_concurrent_bind_vs_offboard_never_leaves_bound_file_disabled(ctx):
    """并发绑定 + 停用多轮后，绝不出现"已提交引用 + 文件被禁"的不一致态。"""
    ids = ctx["ids"]
    bad_states = []
    for _ in range(30):
        # 每轮都新建一个独立文件，避免上一轮残留状态干扰

        from app.core.time import utc_now
        from app.gsp.attachments.models import GspControlledFile

        db = ctx["db"]
        new_file = GspControlledFile(
            object_key=uuid4().hex, file_name="e.pdf", content_type="application/pdf",
            size_bytes=12, sha256="b" * 64, purpose="PARTNER_DOCUMENT",
            status="ACTIVE", uploaded_by=ids["uploader"],
            uploaded_at=utc_now(),
        )
        db.add(new_file)
        db.commit()
        ids["file"] = new_file.id
        ids["key"] = new_file.object_key

        barrier = threading.Barrier(2)

        def run(fn, args):
            barrier.wait()
            return fn(*args)

        results = {}
        t1 = threading.Thread(
            target=lambda: results.update(bind=run(_do_bind_and_commit, (ctx["Session"], ids, ids["actor"])))
        )
        t2 = threading.Thread(
            target=lambda: results.update(off=run(_do_offboard, (ctx["Session"], ids, ids["uploader"], ids["actor"])))
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if _committed_reference_to_disabled_file(db, ids):
            bad_states.append((results.get("bind"), results.get("off")))

    # 允许两种安全结局：绑定先胜(文件保持 ACTIVE 且引用落库) / 停用先胜(文件 DISABLED，绑定被拒)。
    # 唯一不允许的是：引用已提交 且 文件被禁。
    assert not bad_states, f"存在并发竞态不一致态（引用已提交但文件被禁）：{bad_states}"
