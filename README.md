# Introduction

This app provides a test client that acts as a Relying Party (RP) for [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html).

## Implemented specs & features

The following client/RP features from OpenID Connect/OAuth2.0 specifications are implemented by the app.

- [OpenID Connect Core 1.0 incorporating errata set 1][feature-core]
  - Authorization Callback
    - Authorization Code Flow
    - Implicit Flow
    - Hybrid Flow
  - UserInfo Request
  - Offline Access / Refresh Token Grant
  - Client Authentication
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
- [OpenID Connect Discovery 1.0 incorporating errata set 1][feature-discovery]
  - Discovery of OpenID Provider (Issuer) Metadata

# Installation

`npm install`

## Usage

`node server.js --iss {url} --cid {client_id} --cs {client_secret}`

> **Note:** You must register the Relying Party (RP) as a client at the OpenID Provider (OP) manually to obtain a `client_id` and `client_secret`

```
Options:
  --port, -p                Web Server Listener Port                                        [required]  [default: 7080]
  --issuer, --iss           OpenID Connect Provider (OP) Issuer URL                         [required]
  --clientId, --cid         Client ID registered for RP at the OP                           [required]
  --clientSecret, --cs      Client Secret registered for RP at the OP                       [required]
  --scope, --scp            OAuth 2.0 Scopes to request from OP (openid must be specified)  [required]  [default: "openid email phone address profile"]
  --responseType            OAuth 2.0 Response Type(s) for Authentication Request to OP     [required]  [default: "code"]
  --responseMode            OAuth 2.0 Response Mode for Authentication Response from OP     [required]  [default: "form_post"]
  --httpsPrivateKey, --key  Web Server TLS/SSL Private Key (pem)
  --httpsCert, --cert       Web Server TLS/SSL Certificate (pem)
  --https                   Enables HTTPS Listener (requires key and cert params)           [required]  [default: false]
```

### Example

`node server.js --iss https://example.okta.com --cid YRBDFADvhbcsuwGJfP96 --cs 296iRuRznZFupE1F1yjxIw7y-kSYeGGtUJIfGJqo`

# Default Routes

Route          | Description
-------------- | --------------------------------------------------------
`/profile`     | Displays the claims and userinfo for the authenticated user
`/login`       | Initiates an OIDC authentication request to the OpenID Provider (OP)
`/login/force` | Initiates an OIDC authentication request with `max_age=0` to force re-authentication with the OpenID Provider (OP)
`/logout`      | Destroys the user's active session



[openid-connect]: http://openid.net/connect/
[feature-core]: http://openid.net/specs/openid-connect-core-1_0.html
[feature-discovery]: http://openid.net/specs/openid-connect-discovery-1_0.html
