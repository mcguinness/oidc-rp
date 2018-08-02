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
const flash               = require('connect-flash');
const passport            = require('passport');
const Strategy            = require('openid-client').Strategy;


function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}


module.exports = function(issuer, client, authzParams) {

  const app = express();
  const callbackRoute = url.parse(authzParams.redirect_uri).path;
  const clientModel = {
    id: client.client_id,
    redirectUrl: authzParams.redirect_uri
  };

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
  app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  // passport
  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  passport.use('oidc', new Strategy({
    client: client,
    params: _.defaults(authzParams, {
      nonce: generateNonce()
    })
  }, function(tokenSet, userinfo, done) {
    console.log('tokenSet', tokenSet);
    console.log('access_token', tokenSet.access_token);
    console.log('id_token', tokenSet.id_token);
    console.log('claims', tokenSet.claims);
    console.log('userinfo', userinfo);

    return done(null, {
      issuer: issuer.issuer,
      claims: tokenSet.claims,
      tokens: {
        id_token: tokenSet.id_token,
        access_token: tokenSet.access_token,
        refresh_token: tokenSet.refresh_token
      },
      userinfo: userinfo
    });
  }));

  /**
   * Routes
   */

  app.get('/login', passport.authenticate('oidc'));
  app.get('/login/force', function(req, res, next) {
    return passport.authenticate('oidc',
      _.assign(authzParams, {
        prompt: 'login',
        nonce: generateNonce()
      })
    )(req, res, next);
  })

  app.post(callbackRoute, passport.authenticate('oidc', {
    successRedirect: '/profile',
    failureRedirect: '/error',
    failureFlash: true
  }));

  app.get(callbackRoute, passport.authenticate('oidc', {
    successRedirect: '/profile',
    failureRedirect: '/error',
    failureFlash: true
  }));

  app.get('/refresh', function(req, res) {
    if (req.user && req.user.tokens.refresh_token) {
      console.log('Refreshing tokens...');
      client.refresh(req.user.tokens.refresh_token)
        .then(function (tokenSet) {
          console.log('refreshed and validated tokens %j', tokenSet);
          console.log('refreshed id_token claims %j', tokenSet.claims);
          _.assign(req.user, {
            claims: tokenSet.claims,
            tokens: {
              id_token: tokenSet.id_token,
              access_token: tokenSet.access_token,
              refresh_token: tokenSet.refresh_token
            }
          });
          console.log('Fetching userinfo...');
          client.userinfo(tokenSet.access_token) // => Promise
            .then(function (userinfo) {
              console.log('refreshed userinfo %j', userinfo);
              req.user.userinfo = userinfo;
              res.render('profile', {
                client: clientModel,
                user: req.user,
                params: authzParams
              });
            })
            .catch(function(err) {
              res.render('error', {
                client: clientModel,
                message: err.message
              });
            });
        })
        .catch(function(err) {
          res.render('error', {
            client: clientModel,
            message: err.message
          });
        });
    } else {
      res.render('error', {
        client: clientModel,
        message: "Client doesn't have a refresh token.  Make sure offline_access scope was requested!"
      });
    }
  });

  app.get('/logout', function(req, res) {
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
        console.log('User %s successfully logged out', req.user.claims.id);
        req.session.destroy();
        return res.render('logout', {
          client: clientModel
        });
      }
    }
  });

  app.get('/logout/callback', function(req, res) {
    console.log(req.query);
    if (req.isAuthenticated() && req.query.state && req.session.logout_state) {
      if (req.query.state === req.session.logout_state) {
        console.log('User %s successfully logged out', req.user.claims.id);
        req.session.destroy();
        return res.render('logout', {
          client: clientModel
        });
      } else {
        console.log('Unable to logout user because the redirected state doesn\'t match the session state value');
      }
    }
  });

  app.get(['/', '/profile'], function(req, res) {
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
    const errors = req.flash('error');
    console.log(errors);
    res.render('error', {
      client: clientModel,
      message: errors.join('<br>')
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
