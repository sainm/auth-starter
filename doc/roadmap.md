# Roadmap

## Current

- Multi-module starter structure
- JDBC default persistence
- Password login, register, refresh, logout
- Token blacklist
- Login/security audit
- User, role, permission, tenant, group management APIs
- Password change / reset
- Login failure lock strategy
- QR login with scan / confirm / cancel / cleanup
- Configurable Google / WeChat providers with mock fallback
- Demo project and automated tests
- Method-level permission checks on management endpoints
- Group role inheritance and tenant-scoped management queries

## Next

1. Enrich Google and WeChat logins with stronger profile mapping and error normalization.
2. Add Redis-based QR concurrency control and background cleanup scheduling.
3. Add stronger permission strategy extension points beyond the built-in evaluator.
4. Deepen organization tree capabilities and cross-tenant administration strategy.
5. Add more automated end-to-end tests against real PostgreSQL infrastructure.

## Later

1. Add enterprise providers such as DingTalk or Enterprise WeChat.
2. Add rate limiting, CAPTCHA integration, and IP-level lock strategy.
3. Add richer audit dimensions such as user agent, location, and password lifecycle events.
4. Add Maven Central-ready publishing metadata and signed release automation.
