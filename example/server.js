var http = require('http'),
    express = require('express'),
    cookieParser = require('cookie-parser'),
    cookieSession = require('cookie-session');

var app = express();

// Config
app.use(cookieParser());
app.use(cookieSession({ secret: 'secret' }));

require('./cas-auth')(app, require('./config'));

app.get('/', function(req, res) {
  res.end('beepboop');
});

app.listen(8080);
console.log('Server bound at http://127.0.0.1:8080');

/**
 * Expose
 */
module.exports = app;
