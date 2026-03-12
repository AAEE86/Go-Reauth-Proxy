# Go Reauth Proxy

一个基于 Go 的本地优先反向代理，支持：
- 路由规则热更新
- 全局认证接入（登录跳转 + 预检）
- 同端口 HTTP/HTTPS（动态证书切换）
- 内置管理 API（含 Swagger）
- iptables/ip6tables 白黑名单与默认拒绝策略

## 目录

- [项目定位](#项目定位)
- [核心能力](#核心能力)
- [运行架构](#运行架构)
- [快速开始](#快速开始)
- [配置文件说明](#配置文件说明)
- [规则匹配与转发行为](#规则匹配与转发行为)
- [认证服务接入契约](#认证服务接入契约)
- [管理 API](#管理-api)
- [iptables 说明](#iptables-说明)
- [日志与可观测性](#日志与可观测性)
- [项目结构](#项目结构)
- [开发命令](#开发命令)
- [注意事项](#注意事项)
- [License](#license)

## 项目定位

`go-reauth-proxy` 适合部署在内网或本机网关位置，把多个本地服务统一收口到一个代理端口，并通过独立认证服务做访问控制。

它的设计重点是：
- 管理接口只监听 `127.0.0.1`
- 代理目标限制为内网/回环地址
- 配置改动自动持久化到 `config.json`

## 核心能力

- 动态路由规则（`POST /api/rules` 全量替换）
- 路径前缀匹配 + `StripPath` + HTML 绝对路径重写
- `UseAuth` 场景下自动插入悬浮切换工具栏
- `UseRootMode` 支持：将命中路径写入 cookie 后重定向到根路径
- 认证前置预检（`HEAD preflight`，返回 `X-Option: deny` 可拒绝请求）
- 认证失败自动跳转到 `/__auth__/login?redirect_uri=...`
- 动态 SSL 证书上传/清除（同一代理端口自动启停 HTTPS）
- 代理流量统计（入/出字节、活跃登录用户、5xx 计数）
- iptables/ip6tables 链初始化、白名单、黑名单、block-all/allow-all

## 运行架构

- 代理服务端口：默认 `7999`
- 管理服务端口：默认 `7996`（固定绑定 `127.0.0.1`）
- 认证服务端口：默认 `7997`（由 `auth_config.auth_port` 指定）

代理端口通过 `cmux` 同时处理：
- 明文 HTTP
- TLS(HTTPS)

当配置了证书后，明文 HTTP 请求会被 `307` 重定向到 HTTPS。

`proxy_protocol_force=true` 时，代理监听地址会从 `0.0.0.0/::` 切换为 `127.0.0.1/::1`，并优先从 `X-Forwarded-For` / `X-Real-IP` 获取客户端 IP。

## 快速开始

### 1. 环境要求

- Go `1.25+`（见 `go.mod`）
- 可选：`task`（推荐）
- 可选：`bun`（运行 `example/auth-server`）
- 可选：`swag`（生成 Swagger）
- 若使用防火墙 API：Linux + `iptables/ip6tables` + `sudo` 权限

### 2. 启动

使用 Task：

```bash
task run -- -proxy-port 7999 -admin-port 7996 -c ./config.json
```

或直接运行：

```bash
go run ./cmd/server/main.go -proxy-port 7999 -admin-port 7996 -c ./config.json
```

可用启动参数：
- `-proxy-port`：代理端口，默认 `7999`
- `-admin-port`：管理端口，默认 `7996`。传 `0` 时回退到配置文件 `admin_port`
- `-c`：配置文件路径（可传目录，自动补 `config.json`）

### 3. 打开文档

- Swagger UI：`http://127.0.0.1:7996/docs/index.html`

## 配置文件说明

配置文件默认名：`config.json`

默认值（首次运行自动写入）：

```json
{
  "rules": [],
  "default_route": "/__select__",
  "auth_config": {
    "auth_port": 7997,
    "auth_url": "/api/auth/verify",
    "login_url": "/login",
    "logout_url": "/api/auth/logout",
    "preflight_url": "/api/auth/preflight"
  },
  "admin_port": 7996,
  "proxy_protocol_force": false,
  "iptables_chain_name": "",
  "ssl_cert": "",
  "ssl_key": ""
}
```

字段说明：

- `rules`: 路由规则数组
- `default_route`: 根路径 `/` 的默认去向，默认 `"/__select__"`
- `auth_config`: 全局认证配置
- `admin_port`: 管理端口（仅在 `-admin-port=0` 时作为回退）
- `proxy_protocol_force`: 是否强制按 PROXY protocol 场景处理来源 IP
- `iptables_chain_name`: iptables 链名（默认 `REAUTH_FW`）
- `ssl_cert` / `ssl_key`: PEM 证书与私钥（由 API 写入）

## 规则匹配与转发行为

单条规则结构：

```json
{
  "path": "/app",
  "target": "http://127.0.0.1:8080",
  "use_auth": true,
  "strip_path": true,
  "rewrite_html": true,
  "use_root_mode": false
}
```

行为细节：

- 按最长前缀匹配 `path`
- `GET /app` 会 301 到 `/app/`（规则非 `/` 时）
- `strip_path=true`：转发时去掉匹配前缀
- `rewrite_html=true`：重写 HTML 中 `href/src/action/<base href>` 的绝对路径
- `use_auth=true`：转发前调用认证服务，并在 HTML 注入悬浮工具栏
- `use_root_mode=true`：命中后写入 `__proxy_path` cookie 并 302 到 `/`

未命中时：
- 请求 `/` 且无规则：返回 Welcome 页面
- 请求 `/` 且有规则：
  - 若 `default_route` 对应到某条规则，则按该规则转发
  - 否则跳转到 `/__select__`
- 其他路径：返回 404 页面

## 认证服务接入契约

代理会请求本地认证服务：

- 鉴权：`GET http://127.0.0.1:{auth_port}{auth_url}`
- 预检：`HEAD http://127.0.0.1:{auth_port}{preflight_url}`

会透传/注入的关键头：
- `Cookie`
- `Authorization`
- `X-Real-IP`
- `X-Forwarded-For`
- `X-Forwarded-Path`

### 鉴权响应格式（必须 JSON）

`/api/auth/verify`（或自定义 `auth_url`）响应体需要能被解析为：

```json
{
  "success": true,
  "message": "ok"
}
```

- `success=true`：放行
- `success=false`：代理重定向到 `/__auth__/login?redirect_uri=原地址`

### 内置认证代理路径

- `/__auth__/login` -> `auth_config.login_url`
- `/__auth__/api/auth/logout` -> `auth_config.logout_url`
- `/__auth__/*` -> 透传到认证服务对应路径

## 管理 API

统一响应结构：

```json
{
  "success": true,
  "code": 200,
  "message": "Success",
  "data": {},
  "timestamp": 1700000000000
}
```

### 路由与配置

- `GET /api/info`
- `GET /api/traffic`
- `GET /api/rules`
- `POST /api/rules`（全量替换）
- `DELETE /api/rules`
- `GET /api/config/default-route`
- `POST /api/config/default-route`
- `GET /api/config/proxy-protocol`
- `POST /api/config/proxy-protocol`
- `GET /api/auth`
- `POST /api/auth`
- `GET /api/ssl`
- `POST /api/ssl`
- `DELETE /api/ssl`

### iptables

- `POST /api/iptables/init`
- `POST /api/iptables/clean`
- `POST /api/iptables/flush`
- `POST /api/iptables/allow`
- `POST /api/iptables/block`
- `POST /api/iptables/remove`
- `POST /api/iptables/block-all`
- `POST /api/iptables/allow-all`
- `GET /api/iptables/list`

### 常用示例

设置认证配置：

```bash
curl -X POST http://127.0.0.1:7996/api/auth \
  -H "Content-Type: application/json" \
  -d '{
    "auth_port": 7997,
    "auth_url": "/api/auth/verify",
    "login_url": "/login",
    "logout_url": "/api/auth/logout",
    "preflight_url": "/api/auth/preflight"
  }'
```

设置路由规则：

```bash
curl -X POST http://127.0.0.1:7996/api/rules \
  -H "Content-Type: application/json" \
  -d '[
    {
      "path": "/app",
      "target": "http://127.0.0.1:8080",
      "use_auth": true,
      "strip_path": true,
      "rewrite_html": true,
      "use_root_mode": false
    }
  ]'
```

上传 SSL：

```bash
curl -X POST http://127.0.0.1:7996/api/ssl \
  -H "Content-Type: application/json" \
  -d '{"cert":"-----BEGIN CERTIFICATE-----\\n...","key":"-----BEGIN PRIVATE KEY-----\\n..."}'
```

## iptables 说明

`init` 后会创建/重建自定义链，并应用基础规则：

1. 放行 `lo`
2. 放行 `ESTABLISHED,RELATED`
3. 放行本地网段（v4/v6）
4. 放行 `exempt_ports`
5. 默认 `DROP`

说明：
- 默认链名：`REAUTH_FW`
- 默认父链：`INPUT` 和 `DOCKER-USER`
- 命令通过 `sudo iptables` / `sudo ip6tables` 执行

## 日志与可观测性

- HTTP 请求日志为 JSON 行（method/path/status/duration/user_agent/remote_ip）
- `GET /api/traffic` 返回：
  - `total_in` / `total_out`
  - `active_conns`（最近 2 分钟活跃已登录身份）
  - `error_5xx`

## 项目结构

```text
cmd/server/           # 入口与 swagger 文档
pkg/admin/            # 管理 API
pkg/proxy/            # 反向代理核心逻辑
pkg/config/           # 配置加载与持久化
pkg/iptables/         # iptables 管理
pkg/response/         # 内置页面与响应封装
pkg/middleware/       # 日志/CORS 中间件
example/auth-server/  # Bun 示例认证服务
```

## 开发命令

```bash
task build            # 构建 macOS ARM64 + Linux AMD64
task build:mac
task build:linux
task run
task run:auth-server
task test
task docs
```

## 注意事项

- 管理 API 仅监听本地回环地址，不会对外暴露
- 代理目标必须是内网/本地地址，禁止外网目标
- `POST /api/rules` 是全量覆盖，不是增量追加
- SSL 证书与私钥会写入 `config.json` 明文保存，请注意文件权限
- 仓库中的 `example/auth-server` 当前实现返回的是纯文本鉴权结果；若直接联调，请将鉴权接口改为返回 JSON `{"success":...}` 以满足代理解析逻辑

## License

[MIT](./LICENSE)
