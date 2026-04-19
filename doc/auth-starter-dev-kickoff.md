# auth-starter 开发启动说明

这份文档面向当前仓库的真实代码状态，不再保留早期草案里的 Java 25、虚拟线程默认开启等过时设定。

## 当前技术基线

- JDK 21
- Kotlin 2.x
- Spring Boot 3.x
- Spring Security 6.x
- Gradle Kotlin DSL
- PostgreSQL

## 当前模块

- `auth-core`：领域模型与 SPI
- `auth-security`：HTTP API、JWT、过滤器、鉴权
- `auth-persistence`：JDBC 默认实现
- `auth-qr`：扫码登录
- `auth-social-google`
- `auth-social-wechat`
- `auth-audit`
- `auth-autoconfigure`
- `auth-spring-boot-starter`
- `auth-demo`

## 关键默认值

实际代码中的默认配置如下：

```yaml
auth-module:
  enabled: true
  organization:
    mode: BASIC
    tenant-enabled: false
  authentication:
    enabled-types:
      - PASSWORD
  qr-login:
    enabled: true
    ttl-seconds: 180
    transport: http-polling
  performance:
    virtual-threads:
      enabled: false
      auth-executor-enabled: false
      qr-listener-enabled: false
  audit:
    enabled: true
    record-success-logins: true
    record-failed-logins: true
    record-access-denied: true
```

说明：

- `qr-login.enabled` 默认是 `true`
- `qr-login.transport` 默认是 `http-polling`
- 虚拟线程相关默认全部是 `false`

## 开发环境准备

```bash
./gradlew build
./gradlew :auth-demo:bootJar
```

Demo 运行前需要准备 PostgreSQL，并导入：

- [schema-postgresql.sql](/D:/source/auth-starter/doc/schema-postgresql.sql)

## 当前主能力

- 用户名密码登录
- JWT access/refresh token
- 注销、刷新、修改密码、管理员重置密码
- 登录失败锁定策略
- 登录日志与安全事件审计
- 用户会话治理
- 设备画像与设备治理 SPI
- 管理员用户、角色、权限、组织管理
- Google / WeChat provider 模式登录
- QR 登录

## 设备治理说明

`auth-starter` 已经提供统一的设备治理接口面，但它依赖宿主应用提供 `DeviceGovernanceService`。

当宿主应用没有这个 Bean 时：

- 设备治理接口不会注册
- 其余认证与会话能力仍可正常使用

设备接口包括：

- `GET /auth/me/devices`
- `POST /auth/me/devices`
- `POST /auth/me/devices/{deviceId}/deactivate`
- `GET /auth/users/{userId}/devices`
- `POST /auth/users/{userId}/devices/{deviceId}/deactivate`

## 开发注意事项

- 不要在仓库中硬编码本地 `org.gradle.java.home`
- 所有对外文档统一按 JDK 21 编写
- 默认示例密码统一使用 `PleaseChangeThisPassword`
- Bearer 请求的会话触达节流使用内存缓存，但已加入陈旧条目清理

## 参考文档

- [README.md](/D:/source/auth-starter/README.md)
- [api.md](/D:/source/auth-starter/doc/api.md)
- [architecture.md](/D:/source/auth-starter/doc/architecture.md)
- [roadmap.md](/D:/source/auth-starter/doc/roadmap.md)
