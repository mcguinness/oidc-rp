# Introduction

This app provides a test client that acts as a Relying Party (RP) for [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html).

## Implemented specs & features

The following client/RP features from OpenID Connect/OAuth2.0 specifications are implemented by the app.

- [OpenID Connect Core 1.0][feature-core]
  - Authorization Callback
    - Authorization Code Flow
    - Implicit Flow
    - Hybrid Flow
  - UserInfo Request
  - Fetching Distributed Claims
  - Unpacking Aggregated Claims
  - Offline Access / Refresh Token Grant
  - Client Credentials Grant
  - Client Authentication
    - none (PKCE)
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
  - Consuming Self-Issued OpenID Provider ID Token response
- [OpenID Connect Discovery 1.0][feature-discovery]
  - Discovery of OpenID Provider (Issuer) Metadata
- [OpenID Connect Session Management 1.0 - draft 28][feature-rp-logout]
  - RP-Initiated Logout

# Installation

`npm install`

## OAuth Client Registration

An OAuth 2.0 Client needs to be registered for this application with your OpenID Provider (OP).

Parameter                   | Default Value                           | Description
--------------------------- |---------------------------------------- | -------------------------------------
`response_types`            | `code`                                  | Requests an authorization code for the OAuth2 Authorization Response (Authorization Code flow)
`grant_types`               | `authorization_code`                    | Authorization Code flow
`redirect_uris`             | `http://localhost:7080/oauth/callback`  | Callback for OAuth2 Authorization Response
`post_logout_redirect_uris` | `http://localhost:7080/logout/callback` | Callback for OIDC RP-initiated logout

> Note: These values match defaults, changing command-line arguments may require additional client registration configuration

### Sample Dynamic Client Registration

```json
{
  "client_name": "Simple OIDC RP",
  "client_uri": null,
  "logo_uri": null,
  "redirect_uris": [
    "http://localhost:7080/oauth/callback"
  ],
  "post_logout_redirect_uris": [
    "http://localhost:7080/logout/callback"
  ],
  "response_types": [
    "code"
  ],
  "grant_types": [
    "authorization_code"
  ],
  "token_endpoint_auth_method": "client_secret_basic",
  "application_type": "web"
}
```

# Usage

`node server.js --iss {url} --cid {client_id} --cs {client_secret}`

```
Options:
  --help                    Show help                                                                                                                      [boolean]
  --version                 Show version number                                                                                                            [boolean]
  --host, -h                Web Server Hostname                                                                           [string] [required] [default: "localhost"]
  --port, -p                Web Server Port                                                                                      [number] [required] [default: 7080]
  --issuer, --iss           OpenID Connect Provider (OP) Issuer URL                                                                              [string] [required]
  --clientId, --cid         Client ID for Relying Party (Must be registered with OP)                                                             [string] [required]
  --clientSecret, --cs      Client Secret for Relying Party (Must be registered with OP)                                                         [string] [required]
  --redirectUrl             Authorization Response Redirect URL (Must be registered with OP)                        [string] [required] [default: "/oauth/callback"]
  --logoutUrl               Post Logout Redirect URL (Must be registered with OP)                                  [string] [required] [default: "/logout/callback"]
  --scope, --scp            OAuth 2.0 Scopes to request from OP (openid must be specified)       [string] [required] [default: "openid email phone address profile"]
  --responseType            Response Type(s) for Authorization Request                                                         [string] [required] [default: "code"]
  --responseMode            Response Mode for Authorization Request                                                       [string] [required] [default: "form_post"]
  --usePKCE                 Use Proof Key for Code Exchange (PKCE) to secure authorization codes                                           [boolean] [default: true]
  --httpsPrivateKey, --key  Web Server TLS/SSL Private Key (pem)                                                                                            [string]
  --httpsCert, --cert       Web Server TLS/SSL Certificate (pem)                                                                                            [string]
  --https                   Enables HTTPS Listener (requires key and cert params)                                              [boolean] [required] [default: false]
```

> **Note:** You must register the Relying Party (RP) as a client at the OpenID Provider (OP) manually to obtain a `client_id` and `client_secret`.  The default `redirect_uri` for the client is `http://localhost:7080/oauth/callback`.

## Example

`node server.js --iss https://example.okta.com --cid YRBDFADvhbcsuwGJfP96 --cs 296iRuRznZFupE1F1yjxIw7y-kSYeGGtUJIfGJqo`

## Default Routes

Route              | Description
------------------ | ------------------------------------------------------------------------------
`/login`           | Initiates an OIDC authentication request to the OpenID Provider (OP)
`/login/force`     | Initiates an OIDC authentication request with `max_age=0` to force re-authentication with the OpenID Provider (OP)
`/logout`          | Initiates an OIDC logout request to the OpenID Provider (OP)
`/logout/callback` | Callback for RP-initiated logout (`post_logout_redirect_uris`)
`/profile`         | Displays the claims and userinfo for the authenticated user
`/oauth/callback`  | Callback for OAuth2 Authorization Response (`redirect_uri`)


[openid-connect]: http://openid.net/connect/
[feature-core]: http://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: http://openid.net/specs/openid-connect-discovery-1_0.html
[feature-rp-logout]: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout

