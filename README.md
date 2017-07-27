# passport-client-certificate [![npm][npm-image]][npm-url] [![circle][circle-image]][circle-url] [![coveralls][coveralls-image]][coveralls-url]

[npm-image]: https://img.shields.io/npm/v/passport-client-certificate.svg?style=flat
[npm-url]: https://npmjs.org/package/passport-client-certificate
[circle-image]: https://circleci.com/gh/ripple/passport-client-certificate.svg?style=shield
[circle-url]: https://circleci.com/gh/ripple/passport-client-certificate
[coveralls-image]: https://coveralls.io/repos/ripple/passport-client-certificate/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/r/ripple/passport-client-certificate?branch=master


[Passport](http://passportjs.org/) strategy for authenticating using client
certificates.

This module lets you authenticate using client certificates in Node.js
applications.  Client certificate authentication can be added any application or
framework that supports [Connect](http://www.senchalabs.org/connect/)-style
middleware, including [Express](http://expressjs.com/). Optionally, using
[koa-passport](https://github.com/rkusa/koa-passport) it can be integrated into
[Koa](http://koajs.com/)

## Install

```bash
$ npm install passport-client-certificate
```

## Usage

#### Configure Strategy


  The client cert authentication strategy authenticates requests based on the
  client certificate credentials submitted in the TLS handshake

  Applications must supply a `verify` callback which accepts the client
  certificate. It then calls the `done` callback supplying a
  `user`.  User should be set to `false` if the credentials are not valid.  If
  an exception occured, `err` should be set.

  Options:
    - `passReqToCallback`  when `true`, `req` is the first argument to the
       verify callback (default: `false`)
    - `allowUnauthorized` when `true` allows self-signed or certificates from untrusted CAs to be accepted.

  Examples:

```javascript
  passport.use(new ClientCertStrategy(
    function (certificate, done) {
      if (!config.auth.client_certificates_enabled) {
        return done(new UnauthorizedError('Unsupported authentication method'))
      }

      const fingerprint = clientCert.fingerprint.toUpperCase()
      Account.findByFingerprint(fingerprint)
        .then(function (userObj) {
          if (!userObj || userObj.is_disabled || userObj.fingerprint !== fingerprint) {
            return done(new UnauthorizedError('Unknown or invalid account'))
          }
          done(null, userObj)
        })
    }))

```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'client-cert'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.post('/login',
  passport.authenticate('client-cert', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });
```

## Tests

```bash
$ npm install
$ npm test
```

## Credits
Setting up certificates for the test application is based on
https://github.com/anders94/https-authorized-clients/.

