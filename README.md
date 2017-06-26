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

The following example shows OAuth client registration for an OP that supports [OAuth 2.0 Dynamic Client Registration Protocol][client-reg]

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

> **Note:** You must [register the Relying Party (RP) as a client](#oauth-client-registration) at the OpenID Provider (OP) manually to obtain a `client_id` and `client_secret`.  The default `redirect_uri` for the client is `http://localhost:7080/oauth/callback`.

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
[client-reg]: https://tools.ietf.org/html/rfc7591
