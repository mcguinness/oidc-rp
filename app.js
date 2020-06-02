'use strict';

const express             = require('express');
const url                 = require('url');
const _                   = require('lodash');
const path                = require('path');
const hbs                 = require('hbs');
const logger              = require('morgan');
const cookieParser        = require('cookie-parser');
const bodyParser          = require('body-parser');
const session             = require('express-session');
const flash               = require('connect-flash');
const passport            = require('passport');
const generators          = require('openid-client').generators;
const Strategy            = require('openid-client').Strategy;

module.exports = function(params) {
  const AUTHZ_CALLBACK_PATH = url.parse(params.authzParams.redirect_uri).path;
  const LOGOUT_CALLBACK_PATH = url.parse(params.logoutParams.post_logout_redirect_uri).path;

  const app = express();
  const client = params.client;
  const issuer = params.issuer;
  const authzParams = params.authzParams;
  const logoutParams = params.logoutParams;
  const clientViewModel = {
    client_id: client.client_id,
    redirect_uri: authzParams.redirect_uri,
    post_logout_redirect_uri: logoutParams.post_logout_redirect_uri,
    token_endpoint_auth_method: client.token_endpoint_auth_method
  };
  const strategy = new Strategy({
    client: client,
    params: authzParams,
    usePKCE: authzParams.code_challenge_method === 'S256'
  },
    // strategy inspects arg count to fetch userinfo
    authzParams.response_type === 'id_token' ? verifyIdTokenOnly : verifyIdTokenAndUserInfo
  );

  /**
   * Passport Authentication Verification
   */

  function verifyIdTokenOnly(tokenSet, done) {
    console.log('tokenSet', tokenSet);
    console.log('claims', tokenSet.claims());

    return done(null, {
      issuer: issuer.issuer,
      claims: tokenSet.claims(),
      tokens: {
        id_token: tokenSet.id_token
      }
    });
  }

  function verifyIdTokenAndUserInfo(tokenSet, userinfo, done) {
    console.log('tokenSet', tokenSet);
    console.log('claims', tokenSet.claims());
    console.log('userinfo', userinfo);

    return done(null, {
      issuer: issuer.issuer,
      claims: tokenSet.claims(),
      tokens: {
        id_token: tokenSet.id_token,
        access_token: tokenSet.access_token,
        refresh_token: tokenSet.refresh_token
      },
      userinfo: userinfo
    });
  }

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

  // passport
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  passport.use('oidc', strategy);


  /**
   * Routes
   */

  app.get('/login', passport.authenticate('oidc'));
  app.get('/login/force', function(req, res, next) {
    return passport.authenticate('oidc',
      _.assign(authzParams, {
        prompt: 'login'
      })
    )(req, res, next);
  })

  app.post(AUTHZ_CALLBACK_PATH, passport.authenticate('oidc', {
    successRedirect: '/profile',
    failureRedirect: '/error',
    failureFlash: true
  }));

  app.get(AUTHZ_CALLBACK_PATH, passport.authenticate('oidc', {
    successRedirect: '/profile',
    failureRedirect: '/error',
    failureFlash: true
  }));

  app.get('/refresh', function(req, res) {
    if (req.user && req.user.tokens.refresh_token) {
      console.log('Refreshing tokens for subject %s...', req.user.claims.sub);
      client.refresh(req.user.tokens.refresh_token)
        .then(function (tokenSet) {
          console.log('Successfully refreshed tokens for subject %s', req.user.claims.sub);
          console.log('tokenSet', tokenSet);
          console.log('claims', tokenSet.claims());
          const refreshUser = {
            claims: tokenSet.claims(),
            tokens: {
              id_token: tokenSet.id_token,
              access_token: tokenSet.access_token,
              refresh_token: tokenSet.refresh_token
            }
          };
          console.log('Fetching userinfo with new access token for subject %s...', req.user.claims.sub);
          client.userinfo(tokenSet.access_token) // => Promise
            .then(function (userinfo) {
              console.log('Successfully refreshed userinfo for subject %s', req.user.claims.sub);
              console.log(userinfo);
              refreshUser.userinfo = userinfo;

              req.user = refreshUser;
              res.render('profile', {
                client: clientViewModel,
                user: refreshUser,
                params: authzParams
              });


            })
            .catch(function(err) {
              res.render('error', {
                client: clientViewModel,
                message: err.message
              });
            });
        })
        .catch(function(err) {
          res.render('error', {
            client: clientViewModel,
            message: err.message
          });
        });
    } else {
      res.render('error', {
        client: clientViewModel,
        message: "Client doesn't have a refresh token.  Make sure offline_access scope was requested!"
      });
    }
  });

  app.get('/logout', function(req, res) {
    if (req.isAuthenticated()) {
      if (issuer.end_session_endpoint) {
        req.session.logout_state = generators.random();
        const logoutUrl = url.format(Object.assign(url.parse(issuer.end_session_endpoint), {
          search: null,
          query: {
            id_token_hint: req.user.tokens.id_token,
            post_logout_redirect_uri: logoutParams.post_logout_redirect_uri,
            state: req.session.logout_state
          }
        }));
        console.log('RP-initated logout redirect with %s', logoutUrl);
        res.redirect(logoutUrl);
      } else {
        console.log('User %s successfully logged out', req.user.claims.id);
        req.session.destroy();
        return res.render('logout', {
          client: clientViewModel
        });
      }
    }
  });
  app.get(LOGOUT_CALLBACK_PATH, function(req, res) {
    console.log(req.query);
    if (req.isAuthenticated() && req.query.state && req.session.logout_state) {
      if (req.query.state === req.session.logout_state) {
        console.log('User %s successfully logged out', req.user.claims.id);
        req.session.destroy();
        return res.render('logout', {
          client: clientViewModel
        });
      } else {
        console.log('Unable to logout user because the redirected state doesn\'t match the session state value');
      }
    }
  });

  app.get(['/', '/profile'], function(req, res) {
    if(req.isAuthenticated()){
      res.render('profile', {
        client: clientViewModel,
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
      client: clientViewModel,
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
      client: clientViewModel,
      message: err.message,
      error: err.status === 404 ? null : err
    });
  });

  return app;
}
