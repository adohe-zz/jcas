module.exports = function(app, config) {

  app.use(function(req, res, next) {
    if(req.url.indexOf('/auth/auth/login') === 0 || req.session.cas_user_name) {
      return next();
    } else {
      res.redirect('/auth/cas/login');
    }
  });

  config.cas_server_url = config.cas_server_url.replace(/\s+$/g, '');

  app.get('/auth/cas/login', function(req, res) {
    var service_url = req.protocol + "://" + req.get('host') + "/auth/cas/login";

    var jcas = require('../jcas');
    var cas = new jcas({
      base_url: config.cas_server_url,
      service: service_url,
      protocol_version: config.protocol_version || 1.0
    });

    var cas_login_url = config.cas_server_url + '/login?service=' + service_url;
    var ticket = req.param('ticket');
    if(ticket) {
      cas.validate(ticket, function(err, status, username) {
        if(err || !status) {
          // Handle the error
          res.send(
            "You may have logged in with invalid CAS ticket and permission denied.<br>Reason: " + err + "<br>" +
              "<a href='" + cas_login_url + "'>Try again</a>"
          );
        } else {
          // login
          req.session.cas_user_name = username;
          res.redirect('/');
        }
      });
    } else {
      if(!req.session.cas_user_name) {
        res.redirect(config.cas_server_url);
      } else {
        res.redirect('/');
      }
    }
  });
}
