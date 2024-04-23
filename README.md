# Go Single Sign-On for Console applications

![ssoclient/coverage](https://img.shields.io/badge/ssoclient%2Fcoverage-73.5%25-brightgreen)
![ssoproxy/coverage](https://img.shields.io/badge/ssoproxy%2Fcoverage-84.0%25-brightgreen)

This project provides SSO functionality for console applications. Currently, 2 authentication methods are supported:

- [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628).
- [OpenID Connect Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)

These methods require usage of at least one of the two provided libraries **ssoproxy** and **ssoclient**.

### OAuth 2.0 Device Authorization Grant

For this method only **ssoclient** is needed. The disadvantage of using this method is that client id will need to be passed to the CLI application. This parameter will probably be retrieved from user's config file or command flags. Either way it will be known to the user. Polling the IdP can also lead to slower logins if there is a long polling interval set in the IdP. The authentication process is illustrated in the following diagram:

```mermaid
sequenceDiagram
    actor User
    participant ssoclient
    participant IdP
    User-)+ssoclient: LoginWithDeviceAuth(...)
    ssoclient->>+IdP: user code, verification URI, ... := GET /device/auth
    deactivate IdP
    ssoclient--)User: show verification URI and user code
    loop Poll /token until user logs in
        ssoclient->>+IdP: pending login error code := GET /token
        deactivate IdP
    end
    User->>+IdP: Login at verification URI
    deactivate IdP
    Note over ssoclient,IdP: Request to /token succeeds now
    ssoclient->>+IdP: access, refresh tokens, ... := GET /token
    deactivate IdP
    ssoclient-)-User: show access, refresh tokens, ...
```

### OpenID Connect Authorization Code Flow

This method requires usage of **ssoclient** and **ssoproxy**. The proxy provides 2 HTTP handlers - OIDCLoginHandler and OIDCRedirectHandler. These handlers must exposed from the Go server using this library.

- If you are already running your own utility Go server, exposing these handlers should be trivial, just create a **shared** OIDCContext (provided by ssoproxy) and pass it to both handlers
- If you are running your own utility server in another language, consider running a simple Go binary on the same server on a different port
- If you are not running a utility server, the easiest way to start is to deploy `./examples/proxy` using the provided `Dockerfile`.

Under the hood **ssoproxy** uses _HTTP text/event-stream_ and _Server-Sent Events_ format for asynchronous communication with **ssoclient** and by this achieves that no polling is needed.

The authentication process is illustrated in the following diagram:

```mermaid
sequenceDiagram
    actor User
    participant ssoclient
    participant ssoproxy
    participant IdP
    User-)+ssoclient: LoginWithSSOProxy(...)
    ssoclient-)+ssoproxy: GET {OIDCLoginHandler}
    ssoproxy-)ssoproxy: generate request id,<br>add it to context
    ssoproxy--)ssoclient: send login URI
    ssoproxy-)+ssoproxy: wait for {OIDCRedirectHandler} to add tokens to request id
    ssoclient--)User: show login URI
    User-)+IdP: Login at login URI
    IdP-)-User: responds with redirect to {OIDCRedirectHandler}
    User-->>+ssoproxy: User is redirected to {OIDCRedirectHandler}
    deactivate ssoproxy
    ssoproxy->>+IdP: tokens := POST /token using<br> authorization code
    deactivate IdP
    ssoproxy-->>-ssoproxy: {OIDCRedirectHandler} adds tokens to context to <br>request id that was held in OIDC state parameter
    ssoproxy->>-ssoclient: {OIDCLoginHandler} sends tokens
    ssoclient-)-User: show tokens
```

The following parameters can be configured on _OIDC context_:

- `Logger` - logger for HTTP handlers, does not log any messages by default
- `SuccessRedirectURI` - if set users will be redirected to it after login to IdP if the redirect processing was successful
- `FailedRedirectURI` - if set users will be redirected to it after login to IdP if the redirect processing failed
- `LoginTimeout` - time for user to login to IdP after login was initiated, default 5 minutes

### Example

```bash
docker compose up
go run ./examples/cli/main.go login \
  -grant code \
  -login-uri "http://localhost:8000/cli-login"
# login with username: mlosinsky, password: mlosinsky
# Outputs: &{AccessToken:eyJhb... RefreshToken:eyJhb... Expiration:300}
go run ./examples/cli/main.go login \
  -grant device \
  -token-uri "http://localhost:8080/realms/test/protocol/openid-connect/token" \
  -device-uri "http://localhost:8080/realms/test/protocol/openid-connect/auth/device" \
  -client-id test
# login with user code and username: mlosinsky, password: mlosinsky
# Outputs: &{AccessToken:eyJhb... RefreshToken:eyJhb... Expiration:300}
```
