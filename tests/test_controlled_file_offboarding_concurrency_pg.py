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

因此任意交错下只有两种安全结局：
- 绑定先胜：文件保持 ACTIVE 且引用已提交；
- 停用先胜：文件被置 DISABLED，随后绑定因 resolve_attachment 校验 ACTIVE 失败被拒。
唯一不允许的是"引用已提交 + 文件被禁"同时成立。

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


def _models():
    from app.gsp.attachments.models import STATUS_ACTIVE, GspControlledFile
    from app.gsp.attachments.refs import build_ref
    from app.gsp.models import GspPartnerDocument
    from app.legacy import User

    return {
        "STATUS_ACTIVE": STATUS_ACTIVE,
        "GspControlledFile": GspControlledFile,
        "build_ref": build_ref,
        "GspPartnerDocument": GspPartnerDocument,
        "User": User,
    }


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
        c.query(GspControlledFile).filter_by(uploaded_by=ids["uploader"]).delete(synchronize_session=False)
        from app.gsp.models import GspAuditEvent
        c.query(GspAuditEvent).filter_by(actor_user_id=ids["actor"]).delete(synchronize_session=False)
        c.query(UserWarehouse).filter_by(user_id=ids["uploader"]).delete(synchronize_session=False)
        c.query(GspBusinessPartner).filter_by(id=ids["partner"]).delete(synchronize_session=False)
        c.query(Warehouse).filter_by(id=ids["warehouse"]).delete(synchronize_session=False)
        from app.legacy import User as _U
        c.query(_U).filter(_U.id.in_([ids["uploader"], ids["actor"]])).delete(synchronize_session=False)
        c.commit()

    yield {"db": db, "Session": Session, "ids": ids, "engine": engine,
           "uploader": uploader, "actor": actor}
    try:
        _cleanup()
    except Exception:  # noqa: BLE001
        db.rollback()
    db.close()
    engine.dispose()


def _make_new_file(Session, ids):
    """为 uploader 新建一个独立 ACTIVE 受控文件，返回 (id, object_key, object_key_hex)。"""
    from app.core.time import utc_now
    from app.gsp.attachments.models import GspControlledFile

    hexkey = uuid4().hex
    s = Session()
    try:
        f = GspControlledFile(
            object_key=hexkey, file_name="e.pdf", content_type="application/pdf",
            size_bytes=12, sha256="b" * 64, purpose="PARTNER_DOCUMENT",
            status="ACTIVE", uploaded_by=ids["uploader"], uploaded_at=utc_now(),
        )
        s.add(f)
        s.commit()
        return f.id, f.object_key
    finally:
        s.close()


def _bind_and_commit(Session, ids, actor_id):
    """模拟业务绑定：FOR UPDATE 锁定受控文件行 -> 校验通过 -> 插入引用 -> 提交。

    返回 ("bound", None) 或 ("bind_rejected", 详情)：resolve_attachment 对已停用文件
    (非 ACTIVE) 会抛错/拒，属停用先胜的安全结局。
    """
    from datetime import date

    from app.core.time import utc_now
    from app.gsp.attachments import bindings

    m = _models()
    s = Session()
    try:
        token = m["build_ref"](ids["key"])
        # resolve_attachment 内部对文件行 with_for_update() 加锁并校验 ACTIVE
        file_ref, sha, size = bindings.resolve_attachment(
            s, value=token, expected_purpose="PARTNER_DOCUMENT",
        )
        doc = m["GspPartnerDocument"](
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
        return ("bound", None)
    except Exception as e:  # noqa: BLE001 - resolve may reject a disabled file
        s.rollback()
        return ("bind_rejected", repr(e))
    finally:
        s.close()


def _offboard(Session, ids, uploader_id, actor_id):
    """模拟停用上传人：deactivate_user_access（含 FOR UPDATE 行锁 + 引用检查级联）。

    返回 ("offboarded", None) 或错误元组。
    """
    from app.gsp.access_control import deactivate_user_access

    m = _models()
    s = Session()
    try:
        target = s.query(m["User"]).filter(m["User"].id == uploader_id).one()
        deactivate_user_access(
            s, user=target, actor_id=actor_id, reason="offboard-test",
            source_ip="127.0.0.1",
        )
        s.commit()
        return ("offboarded", None)
    except Exception as e:  # noqa: BLE001
        s.rollback()
        return ("offboard_error", repr(e))
    finally:
        s.close()


def _final_state(Session, ids):
    """用全新会话读取 DB 终态，规避主会话 identity map / 隔离级别导致的旧状态缓存。

    返回 dict：
      file_status     : ACTIVE / DISABLED / (缺失则 "MISSING")
      bound_count     : gsp_partner_documents 中引用该文件的已提交行数
      inconsistent    : bound_count>0 且 file_status==DISABLED
    """
    m = _models()
    s = Session()
    try:
        token = m["build_ref"](ids["key"])
        bound_count = (
            s.query(m["GspPartnerDocument"]).filter(m["GspPartnerDocument"].file_ref == token).count()
        )
        f = s.query(m["GspControlledFile"]).filter(m["GspControlledFile"].id == ids["file"]).one_or_none()
        file_status = f.status if f is not None else "MISSING"
        return {
            "file_status": file_status,
            "bound_count": bound_count,
            "inconsistent": bound_count > 0 and file_status == "DISABLED",
        }
    finally:
        s.close()


def _assert_safe_outcome(bind_res, off_res, state, iter_no):
    """断言某轮交错落入了两种安全结局之一（而不是"引用已提交+文件被禁"或线程异常）。"""
    bound, off = bind_res[0], off_res[0]
    # 双操作都必须真实执行完成：不允许线程未返回或停用报错（停用单跑已验证成功，
    # 并发下若报错即回归/环境异常，必须暴露而非静默通过）。
    assert bound != "NO_RESULT", f"轮次{iter_no} 绑定线程未返回: {bind_res}"
    assert off != "NO_RESULT", f"轮次{iter_no} 停用线程未返回: {off_res}"
    assert bound in ("bound", "bind_rejected"), f"绑定线程异常结果: {bind_res}"
    assert off == "offboarded", f"轮次{iter_no} 停用线程异常结果: {off_res}"

    assert not state["inconsistent"], (
        f"轮次{iter_no} 出现竞态不一致：引用已提交(bound={state['bound_count']}) "
        f"但文件被禁(status={state['file_status']}) | bind={bind_res} off={off_res}"
    )

    if state["bound_count"] > 0:
        # 绑定已提交：停用侧必须把它识别为"已绑定证据"而保留 ACTIVE。
        assert state["file_status"] == "ACTIVE", (
            f"轮次{iter_no} 停用把已绑定证据误置 {state['file_status']}（bound 提交但文件非 ACTIVE）"
        )
    else:
        # 无绑定提交：停用侧应把该未绑定文件置 DISABLED。
        assert state["file_status"] == "DISABLED", (
            f"轮次{iter_no} 停用成功但文件状态为 {state['file_status']}（应为 DISABLED）"
        )
        # 文件已禁，绑定侧应被 resolve_attachment 拒绝（若它没抢到先手）。
        if bound == "bound":
            # 理论上不会发生：若绑定先胜，state 里 bound_count 应 >0。兜底断言。
            assert False, (
                f"轮次{iter_no} 绑定返回 bound 但最终无引用落库且文件被禁（日志矛盾），bind={bind_res}"
            )


# ---------------------------------------------------------------------------
# 确定性的两种交错顺序：证明每种安全结局端到端成立（修复后的正确行为）。
# ---------------------------------------------------------------------------


def test_order_bind_first_then_offboard_keeps_bound_file_active(ctx):
    """顺序：先绑定并提交引用 -> 再停用上传人。绑定已提交，停用侧应保留证据 ACTIVE。"""
    ids = ctx["ids"]
    fid, fkey = _make_new_file(ctx["Session"], ids)
    ids["file"], ids["key"] = fid, fkey

    bind_res = _bind_and_commit(ctx["Session"], ids, ids["actor"])
    assert bind_res[0] == "bound", f"先行绑定应成功，实际 {bind_res}"
    off_res = _offboard(ctx["Session"], ids, ids["uploader"], ids["actor"])
    assert off_res[0] == "offboarded", f"停用应成功，实际 {off_res}"

    st = _final_state(ctx["Session"], ids)
    # 绑定已提交 -> 停用侧识别为已绑定证据 -> 文件保持 ACTIVE。
    assert st["bound_count"] == 1
    assert st["file_status"] == "ACTIVE", f"已绑定证据文件被误置 {st['file_status']}"


def test_order_offboard_first_then_bind_is_rejected(ctx):
    """顺序：先停用上传人（级联把未绑定文件置 DISABLED）-> 再尝试绑定。绑定应被拒。"""
    ids = ctx["ids"]
    fid, fkey = _make_new_file(ctx["Session"], ids)
    ids["file"], ids["key"] = fid, fkey

    off_res = _offboard(ctx["Session"], ids, ids["uploader"], ids["actor"])
    assert off_res[0] == "offboarded", f"停用应成功，实际 {off_res}"
    bind_res = _bind_and_commit(ctx["Session"], ids, ids["actor"])

    st = _final_state(ctx["Session"], ids)
    # 无绑定提交；文件被停用侧置 DISABLED；再绑定应被拒(resolve 校验 ACTIVE 失败)。
    assert st["bound_count"] == 0
    assert st["file_status"] == "DISABLED", f"未绑定文件停用后应为 DISABLED，实际 {st['file_status']}"
    assert bind_res[0] == "bind_rejected", (
        f"文件已 DISABLED 后绑定应被拒，实际 {bind_res}"
    )


# ---------------------------------------------------------------------------
# 真正并发：多轮同时跑绑定 + 停用，用全新会话读终态验证不变量。
# ---------------------------------------------------------------------------


def test_concurrent_bind_vs_offboard_never_leaves_bound_file_disabled(ctx):
    """并发绑定 + 停用多轮，绝不出现"已提交引用 + 文件被禁"不一致，且每轮落安全结局。"""
    ids = dict(ctx["ids"])
    bad_states = []
    for iteration in range(30):
        # 每轮新建独立文件，避免残留状态干扰；用全新会话写入并读取终态。
        fid, fkey = _make_new_file(ctx["Session"], ids)
        ids["file"], ids["key"] = fid, fkey

        barrier = threading.Barrier(2)
        results = {}

        def _run_bind():
            barrier.wait()
            return _bind_and_commit(ctx["Session"], ids, ids["actor"])

        def _run_off():
            barrier.wait()
            return _offboard(ctx["Session"], ids, ids["uploader"], ids["actor"])

        t1 = threading.Thread(target=lambda: results.update(bind=_run_bind()))
        t2 = threading.Thread(target=lambda: results.update(off=_run_off()))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        st = _final_state(ctx["Session"], ids)
        bind_res = results.get("bind", ("NO_RESULT", None))
        off_res = results.get("off", ("NO_RESULT", None))
        try:
            _assert_safe_outcome(bind_res, off_res, st, iteration)
        except AssertionError as e:
            bad_states.append(str(e))

    assert not bad_states, "并发一致性校验失败：\n" + "\n".join(bad_states)
