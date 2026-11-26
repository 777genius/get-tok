# 共享身份部署与恢复

本文记录 GetTok 共享身份接入的启动、升级、临时数据和故障恢复约束。账户规则见[身份与租户](../domains/identity_and_tenancy.md#shared_identity_sessions)，字段定义见[共享身份配置](../interfaces/configuration.md#shared_identity_configuration)，浏览器接口见[HTTP 接口](../interfaces/http_api.md#shared_identity_browser)。当前 ordinary TEST 接入不能作为独立连续性、真实 GitHub/GitLab brokerage 或生产恢复策略已经通过验证的证据。

## 部署边界

Identity 负责中央账户状态和 admission；Keycloak 负责本次用户认证；GetTok 保留本地账户、资金、团队及资源权限。human 和 workload 使用不同 client ID 与 secret，浏览器没有服务凭据。当前 Go wire 依赖固定到 `github.com/agent-teams-ai/identity/packages/contracts/gen/go v0.0.0-20261126211321-63142e164669`。协议更新需要同时检查 consumer 的兼容性和拒绝语义，不能替换为浮动 main 或本地 `replace` 后发布。

先在独立 TEST 环境配置 issuer、authority incarnation、consumer 及 exact callback。生产配置使用 HTTPS，并让反向代理保留与 `central_identity.origin` 相同的 Host。浏览器页面与 `/api/v1/auth/central/*` 使用同一公开 origin；不允许用 sibling origin 或宽泛 CORS 补偿不匹配。代理日志必须避免保存 callback query、Cookie、Authorization、密码和 CSRF headers。

固定的 `TOTP_ENCRYPTION_KEY` 由现有 AES-GCM adapter 加密一次性 browser intent，多副本共用并与数据库一起备份。轮换前停止新 login starts，等待最长 5 分钟的旧事务结束，再按既有 secret 运维程序切换。已经提交的 opaque sessions 不保存 upstream token，不能把换密钥当成全部退出。

Keycloak broker alias 的存在和真实 provider 回调需要单独验证。`providers: [github, gitlab]` 只是 GetTok 的允许列表；它不会创建 Keycloak identity provider、GitHub App 或 GitLab application。用户可直接选择已配置的 GitHub/GitLab broker，无需经过 Google。真实 provider 凭据和生产域名应由对应环境提供，不能用 fixture client secret 替代。

## 升级与迁移 308

按[部署与迁移](deployment_and_migrations.md#migration_execution)停止旧后端，备份并验证恢复，然后整体部署配套前后端。迁移 `308_central_identity_sessions.sql` 增加默认 false 的 `users.central_managed` 以及 binding、session、login transaction 三张表。初始化过程中先执行迁移，成功后才监听请求。

升级后共享身份仍默认关闭。先验证 unmanaged 用户的现有登录、刷新和 API Key 网关调用，再显式启用 TEST 接入。新中央注册仅创建独立的新本地 owner；既有邮箱冲突必须显示冲突。只有已独立批准并实现的迁移 proof profile 才能开放旧账户转换，当前 password/TOTP 候选保持 TEST-only。

一旦存在 `central_managed=true` 的用户，不能回退到忽略该字段的旧二进制：旧实现会重新接受之前已经被关闭的 human 认证路径。回退必须保留理解栅栏的兼容版本，或在完全停止业务写入后执行经过验证的整体数据库恢复，并处理恢复期间的资金与凭据变化。不得清空栅栏或删除 binding 来恢复登录。

## 时限与临时数据

| 数据 | 准入期限 | 清理 |
| --- | --- | --- |
| login transaction | 创建后最多 5 分钟，一次消费 | 新 start 最多清理 100 个已过期超过 1 小时的事务 |
| opaque session | 本地最多 5 分钟，且不晚于 human admission 和 ID-token expiry | 新 start 最多清理 100 个已过期超过 24 小时的 session |
| account status | 60 秒总预算，已包含 5 秒 clock uncertainty | 新观察按 revision 单调合并，不能丢掉已见的拒绝状态 |
| workload token | 服务端缓存最多 60 秒，且早于 provider expiry 至少 5 秒 | 过期后重新申请独立 client-credentials grant |
| binding 与 `central_managed` | 持久的归属及认证栅栏 | 临时数据清理永不删除 |

清理通过带索引和 `SKIP LOCKED` 的有界数据库操作执行；无新登录时，过期临时记录保留但不会获得认证能力。清理保留期与准入期限是两件事。数据库备份应包含 sticky fence、bindings 和业务账户，不能只恢复 users 或只恢复 Identity 的账户表。

## 故障处理

Identity、Keycloak 或网络故障时，不使用旧的 ACTIVE 观察继续放行，也不切回 legacy credential。上游暂时不可用返回 503；显式拒绝的 session 返回 401。局部退出只依赖当前本地 session 和 CSRF，因此无需 Keycloak 在线；本地数据库故障则不能报告退出成功。

账户仍 ACTIVE 但 session 的 security epoch、attachment generation 或截止时间不同，必须重新进行 human flow。修正数据库、重启服务、重新取得 workload token 都不能更新原 session proof。相同 revision 的冲突证据按错误处理，先排查 authority 数据恢复或版本错误，不覆盖已有观察。

生产保护操作仍要求已经验证的独立连续性 profile。403 `CENTRAL_PROOF_REQUIRED` 不表示账户丢失，也不应自动退出普通 session；客户端应说明需要额外账户验证。后台模式只保留 central capability、session bootstrap 和退出，新登录与 callback 继续被后台模式 guard 拒绝。

## 验证入口

普通单元测试覆盖协议时间、计数器、生产 cookie 属性、Origin 和旧 JWT 栅栏。`integration` 标签的 PostgreSQL 测试执行完整应用迁移，验证一次性消费、原子注册、失败回滚、并发归属、密码变化后的绑定拒绝以及已见撤销不会被旧 ACTIVE 覆盖。

原生 join 使用 `TestCentralNativeBFFCookieFlow`，构建标签为 `integration,native_identity,embed`。Identity 的 native runner 启动真实 Keycloak 和 Identity HTTP，并传入 loopback TEST 数据库及单独的 browser/lifecycle argv。缺少这些依赖时，测试失败，不跳过。前端使用既有 `make build-frontend` 生成 `backend/internal/web/dist`，由生产 SPA middleware 交付；不使用测试 HTML、伪造 session 接口或手工注入浏览器 cookie。

持续验证由 [Shared Identity E2E workflow](../../.github/workflows/shared-identity-e2e.yml) 运行，authority checkout 固定到明确的 commit，两个仓库各自使用固定工具链。在 Identity checkout 中执行 `pnpm test:native-gettok`；consumer 配置使用 `GETTOK_NATIVE_REPOSITORY`、`GETTOK_NATIVE_GO`、`GETTOK_NATIVE_BROWSER_COMMAND` 和 `GETTOK_NATIVE_DATABASE_URL`，同时提供 workflow 列出的独立 PostgreSQL、Keycloak 和 TEST client 参数。launcher 先从实际 consumer 源码编译 Go fixture，再启动 Keycloak；预编译 binary 路径由 launcher 自己管理，不接受外部替代。

完整链路包括未绑定 login 拒绝、显式注册、真实浏览器点击进入 Keycloak、callback、刷新页面、CSRF 拒绝、本地 logout，以及 production Identity lifecycle suspend 后原 cookie 被拒绝。Go 测试只输出有界 stage/result JSON；浏览器和 lifecycle 子进程有超时和退出处理。这个链路通过与否以对应 exact commit 的实际执行结果为准，编译、fixture 代码或 provider-only 测试不能替代 joined E2E 的结果。
