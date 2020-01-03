'use strict';

const yargs      = require('yargs');
const os         = require('os');
const fs         = require('fs');
const http       = require('http');
const https      = require('https');
const _          = require('lodash');
const appFactory = require('./app');
const Issuer     = require('openid-client').Issuer;

const argv = yargs
  .usage('\nSimple OpenID Connect Relying Party (RP)')
  .options({
    host: {
      description: 'Web Server Listener Host',
      required: true,
      default: 'localhost'
    },
    port: {
      description: 'Web Server Listener Port',
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
      description: 'Client ID registered for RP at the OP',
      required: true,
      alias: 'cid',
      string: true
    },
    clientSecret: {
      description: 'Client Secret registered for RP at the OP',
      required: true,
      alias: 'cs',
      string: true
    },
    scope: {
      description: 'OAuth 2.0 Scopes to request from OP (openid must be specified)',
      required: true,
      alias: 'scp',
      string: true,
      default: 'openid email phone address profile'
    },
    responseType: {
      description: 'OAuth 2.0 Response Type(s) for Authentication Request to OP',
      required: true,
      string: true,
      default: 'code'
    },
    responseMode: {
      description: 'OAuth 2.0 Response Mode for Authentication Response from OP',
      required: true,
      string: true,
      default: 'form_post'
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
  .example('\t$0 --iss https://example.okta.com --cid YRBDFADvhbcsuwGJfP96 --cs 296iRuRznZFupE1F1yjxIw7y-kSYeGGtUJIfGJqo', '')
  .argv;

Issuer.discover(argv.issuer).then(function(issuer) {
  const client = new issuer.Client({
    client_id: argv.clientId,
    client_secret: argv.clientSecret
  });
  const redirectUrl = (argv.https ? 'https' : 'http') + '://' + argv.host + ':' + argv.port + '/oauth/callback';
  const authzParams = {
    scope: argv.scope,
    response_type: argv.responseType,
    response_mode: argv.responseMode,
    redirect_uri: redirectUrl
  };

  const app = appFactory(issuer, client, authzParams);
  const httpServer = argv.https ?
    https.createServer({ key: argv.httpsPrivateKey, cert: argv.httpsCert }, app) :
    http.createServer(app);

  console.log();
  console.log('starting web server...');
  console.log();

  httpServer.listen(argv.port, '0.0.0.0', function() {
    const scheme    = argv.https ? 'https' : 'http';
    const address   = httpServer.address();
    const baseUrl   = scheme + '://' + argv.host + ':' + address.port;

    console.log();
    console.log('RP URL:\n\t' + baseUrl);
    console.log('RP Client ID:\n\t' + argv.clientId);
    console.log('RP OAuth2 Redirect URL:\n\t' + redirectUrl);
    console.log();
    console.log('OP Issuer:\n\t' + issuer.metadata.issuer);
    console.log('OP Authorization URL:\n\t' + issuer.metadata.authorization_endpoint);
    console.log('OP Token URL:\n\t' + issuer.metadata.token_endpoint);
    console.log('OP UserInfo URL:\n\t' + issuer.metadata.userinfo_endpoint);
    console.log('OP JWKS URL:\n\t' + issuer.metadata.jwks_uri);
    console.log('OP End Session URL:\n\t' + issuer.metadata.end_session_endpoint);
    console.log();
    console.log('Authentication Request:\n\t' + client.authorizationUrl(_.defaults({state: '{state}', nonce: '{nonce}'}, authzParams)));
    console.log();
  });
}).catch((e) => {
  console.log(e);
  process.exit(1)
});
