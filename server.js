'use strict';

const yargs      = require('yargs');
const os         = require('os');
const fs         = require('fs');
const http       = require('http');
const https      = require('https');
const url        = require('url');
const _          = require('lodash');
const appFactory = require('./app');
const Issuer     = require('openid-client').Issuer;

const argv = yargs
  .usage('\nSimple OpenID Connect Relying Party (RP)')
  .options({
    host: {
      description: 'Web Server Hostname',
      required: true,
      alias: 'h',
      string: true,
      default: 'localhost'
    },
    port: {
      description: 'Web Server Port',
      required: true,
      alias: 'p',
      number: true,
      default: 7080
    },
    issuer: {
      description: 'OpenID Connect Provider (OP) Issuer URL',
      required: true,
      alias: 'iss',
      string: true
    },
    clientId: {
      description: 'Client ID for Relying Party (Must be registered with OP)',
      required: true,
      alias: 'cid',
      string: true
    },
    clientSecret: {
      description: 'Client Secret for Relying Party (Must be registered with OP)',
      required: true,
      alias: 'cs',
      string: true
    },
    redirectUrl: {
      description: 'Authorization Response Redirect URL (Must be registered with OP)',
      required: true,
      string: true,
      default: '/oauth/callback'
    },
    logoutUrl: {
      description: 'Post Logout Redirect URL (Must be registered with OP)',
      required: true,
      string: true,
      default: '/logout/callback'
    },
    scope: {
      description: 'OAuth 2.0 Scopes to request from OP (openid must be specified)',
      required: true,
      alias: 'scp',
      string: true,
      default: 'openid email phone address profile'
    },
    responseType: {
      description: 'Response Type(s) for Authorization Request',
      required: true,
      string: true,
      default: 'code'
    },
    responseMode: {
      description: 'Response Mode for Authorization Request',
      required: true,
      string: true,
      default: 'form_post'
    },
    usePKCE: {
      description: 'Use Proof Key for Code Exchange (PKCE) to secure authorization codes',
      required: false,
      boolean: true,
      default: true
    },
    httpsPrivateKey: {
      description: 'Web Server TLS/SSL Private Key (pem)',
      required: false,
      alias: 'key',
      string: true,
    },
    httpsCert: {
      description: 'Web Server TLS/SSL Certificate (pem)',
      alias: 'cert',
      required: false,
      string: true,
    },
    https: {
      description: 'Enables HTTPS Listener (requires key and cert params)',
      required: true,
      boolean: true,
      default: false
    }
  })
  .coerce('host', function (arg) {
    let hostUrl = url.parse(arg);
    return (hostUrl.protocol === null) ? arg : hostUrl.hostname
  })
  .check(function(argv, aliases) {
    if (argv.https) {
      if (!fs.existsSync(argv.httpsPrivateKey)) {
        return 'HTTPS Private Key "' + argv.httpsPrivateKey + '" is not a valid file path';
      }
      if (!fs.existsSync(argv.httpsCert)) {
        return 'HTTPS Certificate "' + argv.httpsCert + '" is not a valid file path';
      }

      argv.httpsPrivateKey = fs.readFileSync(argv.httpsPrivateKey).toString();
      argv.httpsCert = fs.readFileSync(argv.httpsCert).toString();
    }
    return true;
  })
  .check(function(argv, aliases) {
    let baseUrl = (argv.https ? 'https' : 'http') + '://' + argv.host + ':' + argv.port;
    argv.baseUrl = baseUrl;

    let authzCallback = url.parse(argv.redirectUrl);
    if (authzCallback.protocol === null) {
      argv.redirectUrl = baseUrl + authzCallback.path;
    }

    let logoutCallback = url.parse(argv.logoutUrl);
    if (logoutCallback.protocol === null) {
      argv.logoutUrl = baseUrl + logoutCallback.path;
    }
    return true;
  })
  .example('\t$0 --iss https://example.okta.com --cid YRBDFADvhbcsuwGJfP96 --cs 296iRuRznZFupE1F1yjxIw7y-kSYeGGtUJIfGJqo', '')
  .wrap(yargs.terminalWidth())
  .argv;

// hard-code to oidc metadata discovery
Issuer.discover(argv.issuer + '/.well-known/openid-configuration').then(function(issuer) {
  console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);

  const appParams = {
    issuer, issuer,
    client: new issuer.Client({
      client_id: argv.clientId,
      client_secret: argv.clientSecret,
      redirect_uris: [argv.redirectUrl],
      post_logout_redirect_uris: [argv.logoutUrl]
    }),
    authzParams: {
      scope: argv.scope,
      response_type: argv.responseType,
      response_mode: argv.responseMode,
      redirect_uri: argv.redirectUrl
    },
    logoutParams: {
      post_logout_redirect_uri: argv.logoutUrl
    }
  }

  if (argv.usePKCE) {
    appParams.authzParams.code_challenge_method = 'S256'
  }

  const app = appFactory(appParams);
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);

  console.log();
  console.log('starting web server...');
  console.log();

  httpServer.listen(argv.port, argv.host, function() {
    console.log('[Relying Party]');
    console.log();
    console.log('App URL:\n\t' + argv.baseUrl);
    console.log('Client ID:\n\t' + argv.clientId);
    console.log('Redirect URL:\n\t' + argv.redirectUrl);
    console.log('Logout URL:\n\t' + argv.logoutUrl);
    console.log();
    console.log('[OpenID Provider]');
    console.log();
    console.log('Issuer:\n\t' + issuer.metadata.issuer);
    console.log('Authorization URL:\n\t' + issuer.metadata.authorization_endpoint);
    console.log('Token URL:\n\t' + issuer.metadata.token_endpoint);
    console.log('UserInfo URL:\n\t' + issuer.metadata.userinfo_endpoint);
    console.log('JWKS URL:\n\t' + issuer.metadata.jwks_uri);
    console.log('End Session URL:\n\t' + issuer.metadata.end_session_endpoint);
    console.log();
  });
}).catch((e) => {
  console.log(e);
  process.exit(1)
});
