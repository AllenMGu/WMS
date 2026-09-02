# 数据库迁移

[中文](README.md) | [English](README.en.md)

生产环境设置 `AUTO_CREATE_SCHEMA=false`。空数据库由受控变更流程直接执行：

```bash
alembic upgrade head
```

已有旧版 WMS 数据库不能直接重复创建基线表。先完成结构比对与备份，在批准的变更单中执行：

```bash
alembic stamp 20260820_00
alembic upgrade head
alembic check
```

`stamp` 只登记版本、不修改表结构，因此必须先证明现有旧 WMS 表与 `20260820_00` 基线一致。

上线前应在同版本数据库副本完成备份、升级、回滚与数据核对演练，并将命令输出、执行人、复核人和时间纳入变更记录。

当前迁移头为 `20260902_24`，新增老 GSP 历史数据迁移批次、不可变归档记录和独立核对明细；生产就绪检查会验证数据库已处于该受审迁移版本。
