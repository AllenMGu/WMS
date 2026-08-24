# Repository Split Guide

[中文](REPOSITORY_SPLIT.md) | [English](REPOSITORY_SPLIT.en.md)

## Target Repositories

| Repository | Responsibility | Release unit |
|---|---|---|
| [`AllenMGu/WMS`](https://github.com/AllenMGu/WMS) | FastAPI backend, GSP domain, migrations, tests, operations and validation design | Python API service |
| [`AllenMGu/WMS-frontend`](https://github.com/AllenMGu/WMS-frontend) | Compatibility-period general WMS Web client | Static site/reverse-proxy assets |
| [`AllenMGu/WMS-miniprogram`](https://github.com/AllenMGu/WMS-miniprogram) | WeChat scan, inventory and document-operation client | WeChat Mini Program release |

The clients were imported from snapshots of the original monorepo and now have independent release histories. API
contract changes must identify affected clients in the backend pull request and receive corresponding client changes.

## Deployment Boundary

The Web frontend calls same-origin `/api` by default. For a different origin:

1. set the complete backend URL in frontend `config.js`;
2. register the complete frontend origin in backend `ALLOWED_ORIGINS`;
3. verify login, token expiry, import/export, scanning, and browser preflight requests.

Set `apiBaseUrl` in the Mini Program `app.js` and register the legal HTTPS request domain in the WeChat platform.

## Change Control

A coordinated production release records immutable SHAs for all participating repositories, the backend migration
revision, Mini Program version, API compatibility, rollback combination, test evidence, approval, and deployment
evidence. The production JZT adapter remains an explicitly excluded backend integration until formal specifications
and a test environment are available.
