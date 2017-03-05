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
const passport            = require('passport');
const Strategy            = require('openid-client').Strategy;


module.exports = function(issuer, client, authzParams) {

  const app = express();
  const callbackRoute = url.parse(authzParams.redirect_uri).path;

  /**
   * Middleware.
   */

  // environment
  app.set('views', path.join(__dirname, 'views'));

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
      userinfo: userinfo
    });
  }));

  /**
   * Routes
   */

  app.get('/login', passport.authenticate('oidc'));
  app.get('/login/force', function(req, res, next) {
    return passport.authenticate('oidc', _.defaults({
        max_age: 0
      }, authzParams)
    )(req, res, next);
  })

  app.post(callbackRoute, passport.authenticate('oidc', { successRedirect: '/profile', failureRedirect: '/error' }));
  app.get(callbackRoute, passport.authenticate('oidc', { successRedirect: '/profile', failureRedirect: '/error' }));

  app.get('/logout', function(req, res) {
    if (req.isAuthenticated()) {
      req.session.destroy();
      console.log('User %s successfully logged out', req.user.claims.id);
    }
    res.render('logout', {
      client: {
        id: client.client_id,
        redirectUrl: authzParams.redirect_uri
      }
    });
  });

  app.get(['/', '/profile'], function(req, res) {
      if(req.isAuthenticated()){
        res.render('profile', {
          client: {
            id: client.client_id,
            redirectUrl: authzParams.redirect_uri
          },
          user: req.user,
          params: authzParams
        });
      } else {
        res.redirect('/login');
      }
  });

  app.get('/error', function(req, res) {
    console.log(JSON.stringify(req));
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
      message: err.message,
      error: err.status === 404 ? null : err
    });
  });

  return app;
}
