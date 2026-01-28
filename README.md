# 多仓库管理系统

## 项目简介

多仓库管理系统是一个专业的库存管理解决方案，支持多仓库、多用户、货物、库位、库存、出入库、盘点等全流程管理。

### 主要功能

- **仪表盘**：展示库存概况、出入库统计、库存预警
- **仓库管理**：多仓库创建与配置
- **库位管理**：库位创建、编辑、禁用
- **货物管理**：货物信息维护
- **库存查询**：多维度库存查询
- **扫码出入库**：快速扫码出入库操作
- **入库单管理**：入库单创建、提交、查询
- **出库单管理**：出库单创建、提交、查询
- **盘点管理**：库存盘点记录
- **用户管理**：用户创建、权限分配

## 技术栈

- 后端：FastAPI + SQLAlchemy + PostgreSQL
- HTML5/CSS3/JavaScript
- Tailwind CSS v3
- Font Awesome
- Chart.js

## 项目结构

```
WMS/
├── main.py             # 后端入口（FastAPI）
├── frontend/           # 前端静态页面
│   ├── index.html      # 登录页面
│   ├── dashboard.html  # 仪表盘
│   ├── warehouse.html  # 仓库管理
│   ├── location.html   # 库位管理
│   ├── goods.html      # 货物管理
│   ├── stock.html      # 库存查询
│   ├── scan.html       # 扫码出入库
│   ├── inbound.html    # 入库单管理
│   ├── outbound.html   # 出库单管理
│   ├── check.html      # 盘点管理
│   ├── user.html       # 用户管理
│   └── assets/         # 资源文件（JS/CSS）
└── README.md           # 项目说明
```

## 如何运行

### 1. 启动后端

1. 准备 PostgreSQL 数据库，并修改 `main.py` 中的 `DATABASE_URL` 为本地配置。
2. 安装依赖并运行服务（示例）：
   ```bash
   pip install fastapi uvicorn sqlalchemy psycopg2-binary passlib[bcrypt] python-jose
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

### 2. 使用前端

1. 确保后端服务运行在 `http://localhost:8000`
2. 打开 `frontend/index.html` 即可访问系统
3. 使用后端已创建的用户进行登录

## 注意事项

1. 系统需要与后端 API 配合使用，确保 API 地址正确配置（默认 `http://localhost:8000`）。
2. 部分功能需要管理员权限才能使用（如用户管理）。
3. 建议使用现代浏览器（Chrome、Firefox、Edge 等）访问系统。
