# WMS / 药品 GSP 质量管理系统

本项目正在从通用多仓库 WMS 演进为“WMS 业务域 + GSP 质量域 + 外部集成域”的模块化系统。
旧版前端、小程序和 `/api` WMS 接口暂时保持兼容；新增受控功能位于 `/api/gsp`。

> 重要：软件功能不能单独证明企业符合 GSP。正式投用还需要经质量部门批准的流程与 SOP、
> 权限矩阵、主数据、培训、风险评估、计算机化系统验证、备份恢复演练和持续变更控制。

## 当前已完成

- 将 3935 行单文件入口迁入 `app/legacy.py`，新增独立的应用装配、配置、数据库和 GSP 包。
- JWT、数据库、LDAP 和跨域配置改为环境变量；生产环境拒绝弱密钥。
- LDAP 用户不再自动获得全部仓库权限，也不保存其真实 LDAP 口令派生值。
- 删除用户改为停用账号，保留历史操作人引用。
- 建立供货方/购货方资质、药品质量主数据、药品批次、批号库存、质量锁定、岗位授权模型。
- 建立强制填写变更原因的哈希链审计事件。
- 建立批号、有效期、追溯信息、冷链温度记录和验收放行的首批规则。
- 建立九州通等外部系统可共用的事务出站箱，避免接口直接修改库存核心表。
- 建立独立采购与收货子域：采购制单、质量审批、按单收货、收货/验收岗位分离，只有验收合格数量进入批次库存。
- 建立独立销售与出库子域：购货方资质复核、FEFO 批号预留、拣货、独立出库复核和发运扣减。
- 建立首个 Alembic 基线迁移，生产环境不再依赖应用启动时自动建表。
- 建立 GitHub Actions 质量门禁，覆盖 Python 3.10/3.12、PostgreSQL 迁移、测试、静态检查、编译和依赖一致性。
- 增加合规概览、批号追溯、质量锁定和审计查询 API，并为纯规则提供单元测试。

尚未完成的关键项请看 [GSP 差距矩阵](docs/GSP_GAP_ANALYSIS.md)。

## 目录

```text
WMS/
├── app/
│   ├── application.py       # 应用装配
│   ├── legacy.py            # 兼容期通用 WMS（后续继续按域拆分）
│   ├── core/                # 配置、数据库等共享基础设施
│   └── gsp/                 # 独立 GSP 质量域
│       ├── models.py        # 质量主数据、批次、锁定、审计、集成出站箱
│       ├── procurement_receiving/ # 采购、收货、验收受控闭环
│       ├── sales_shipping/ # 销售、FEFO、出库复核与发运
│       ├── rules.py         # 可评审、可验证的纯质量规则
│       ├── router.py        # /api/gsp 接口
│       └── schemas.py       # API 数据契约
├── frontend/                # 兼容期 Web 前端
├── wechat-miniprogram/      # 兼容期微信小程序
├── tests/                   # 自动化测试
├── docs/                    # 架构、差距、验证和九州通对接说明
├── migrations/              # 经评审执行的数据库结构迁移
├── scripts/                 # 运维脚本
└── main.py                  # uvicorn 兼容入口
```

## 本地运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
set -a && source .env && set +a
uvicorn main:app --host 0.0.0.0 --port 8000
```

开发时可临时使用 SQLite：

```bash
export DATABASE_URL='sqlite+pysqlite:///./wms-dev.db'
uvicorn main:app --reload
```

生产环境必须设置 `APP_ENV=production`、至少 32 字符随机 `SECRET_KEY`，并将
`AUTO_CREATE_SCHEMA=false`；数据库结构变更必须通过经过评审的 Alembic 迁移执行：

```bash
alembic upgrade head
```

已有旧版 WMS 数据库需先核对结构，再按 [迁移说明](migrations/README.md) 登记旧库基线并升级，禁止直接在生产库试跑。

API 文档：`http://localhost:8000/docs`；健康检查：`GET /health`。

## 测试

```bash
pytest
python -m compileall -q app main.py tests
```

## 设计与实施资料

- [目标架构](docs/ARCHITECTURE.md)
- [GSP 差距矩阵](docs/GSP_GAP_ANALYSIS.md)
- [CSV / 验证计划](docs/VALIDATION_PLAN.md)
- [九州通接口边界](docs/JZT_INTEGRATION.md)

## 许可证与投用声明

正式用于药品经营或药品生产企业销售、储存、运输环节前，必须由企业质量部门根据实际经营范围、
地方监管要求及批准的 URS 对本系统进行确认和验证。本仓库当前版本是可继续开发的 GSP 基础版本，
不是“开箱即合规”的商业成品。
