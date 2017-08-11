'use strict';

const express             = require('express');
const url                 = require('url');
const crypto              = require('crypto');
const _                   = require('lodash');
const path                = require('path');
const hbs                 = require('hbs');
const logger              = require('morgan');
const cookieParser        = require('cookie-parser');
const bodyParser          = require('body-parser');
const session             = require('express-session');
const flash               = require('express-flash');
const passport            = require('passport');
const Strategy            = require('openid-client').Strategy;


module.exports = function(issuer, client, authzParams) {

  const app = express();
  const callbackRoute = '/oauth/callback';
  const clientModel = {
    id: client.client_id,
    redirectUrl: 'ERROR'
  };

  function redirectUrlFor(req) {
    var rv = req.protocol + "://" + req.headers.host + callbackRoute;
    console.log(rv);
    return rv;
  }

  /**
   * Middleware.
   */

  // environment
  app.set('views', path.join(__dirname, 'views'));
  // Trust the X-Forwarded-Proto header that Heroku, Ngrok, & etc set for TLS connections
  app.enable('trust proxy');

  // view engine
  app.set('view engine', 'hbs');
  app.set('view options', { layout: 'layout' });

  hbs.registerHelper('ifArray', function(item, options) {
    if(Array.isArray(item)) {
      return options.fn(this);
    } else {
      return options.inverse(this);
    }
  });

  hbs.registerHelper('select', function(selected, options) {
    return options.fn(this).replace(
      new RegExp(' value=\"' + selected + '\"'),
      '$& selected="selected"');
  });

  // middleware
  app.use(flash());
  app.use(logger(':date> :method :url - {:referrer} => :status (:response-time ms)'));
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    secret: "You tell me what you want and I'll tell you what you get",
    resave: false,
    saveUninitialized: true}));
  app.use(passport.initialize());
  app.use(passport.session());

  // passport
  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  passport.use('oidc', new Strategy({ client: client, params: authzParams }, function(tokenset, userinfo, done) {
    console.log('tokenset', tokenset);
    console.log('access_token', tokenset.access_token);
    console.log('id_token', tokenset.id_token);
    console.log('claims', tokenset.claims);
    console.log('userinfo', userinfo);

    return done(null, {
      issuer: issuer.issuer,
      claims: tokenset.claims,
      tokens: {
        id_token: tokenset.id_token,
        access_token: tokenset.access_token
      },
      userinfo: userinfo
    });
  }));

  /**
   * Routes
   */

  app.get('/login', passport.authenticate('oidc'));
  app.get('/login/force', function(req, res, next) {
    authzParams.redirect_uri = redirectUrlFor(req);
    return passport.authenticate('oidc', _.defaults({
        max_age: 0
      }, authzParams)
    )(req, res, next);
  })

  app.post(callbackRoute, passport.authenticate('oidc', { successRedirect: '/profile', failureRedirect: '/error', failureFlash: true }));
  app.get(callbackRoute, passport.authenticate('oidc', { successRedirect: '/profile', failureRedirect: '/error', failureFlash: true }));

  app.get('/logout', function(req, res) {
    clientModel.redirectUrl = redirectUrlFor(req);
    if (req.isAuthenticated()) {
      if (issuer.end_session_endpoint) {
        req.session.logout_state = crypto.randomBytes(24).toString('hex');
        const logoutUrl = url.format(Object.assign(url.parse(issuer.end_session_endpoint), {
          search: null,
          query: {
            id_token_hint: req.user.tokens.id_token,
            post_logout_redirect_uri: req.protocol + '://' + req.get('host') + req.url + '/callback',
            state: req.session.logout_state
          }
        }));
        console.log('RP-initated logout redirect with %s', logoutUrl);
        res.redirect(logoutUrl);
      } else {
        console.log('User %s successfully logged out via RP-initated logout', req.user.claims.id);
        req.logout();
        return res.render('logout', {
          client: clientModel
        });
      }
    }
  });

  app.get('/logout/callback', function(req, res) {
    clientModel.redirectUrl = redirectUrlFor(req);
    console.log(req.query);
    if (req.isAuthenticated() && req.query.state && req.session.logout_state) {
      if (req.query.state === req.session.logout_state) {
        console.log('User %s successfully logged out via callback', req.user.claims.id);
        req.logout();
        return res.render('logout', {
          client: clientModel
        });
      } else {
        console.log('Unable to logout user because the redirected state doesn\'t match the session state value');
      }
    }
  });

  app.get(['/', '/profile'], function(req, res) {
    clientModel.redirectUrl = redirectUrlFor(req);
    authzParams.redirect_uri = redirectUrlFor(req);
    if(req.isAuthenticated()){
      res.render('profile', {
        client: clientModel,
        user: req.user,
        params: authzParams
      });
    } else {
      res.redirect('/login');
    }
  });

  app.get('/error', function(req, res) {
    var msg = req.flash('error');
    console.log(msg);
    res.render('error', {
      error: {
        stack: msg
      },
      message: "Error"
    });
  });

  app.get('/welcome', function(req, res) {
    clientModel.redirectUrl = redirectUrlFor(req);
    res.render('welcome', {
      thisAppUrl: req.protocol + "://" + req.headers.host,
      client: clientModel,
      oktaAdminOrg: issuer.metadata.issuer.replace('.', '-admin.'),
      issuer: issuer
    });
  });

  // catch 404 and forward as relay state
  app.use(function(req, res) {
    if (!req.isAuthenticated()) {
      //req.session.relayState = req.originalUrl;
    }
    res.redirect('/login');
  });

  // development error handler
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      client: clientModel,
      message: err.message,
      error: err.status === 404 ? null : err
    });
  });

  return app;
}
