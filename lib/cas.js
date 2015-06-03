var http = require('http'),
    https = require('https'),
    url = require('url'),
    xml2js = require('xml2js');

var CAS = module.exports = function(options) {
    options = options || {};
    if(!options.protocol_version) {
        options.protocol_version = 2.0;
    }
    this.protocol_version = options.protocol_version;

    if(!options.base_url) {
        throw new Error("cas server cannot be null");
    }
    var cas_url = url.parse(options.base_url);
    if(cas_url.protocol !== 'https:') {
        throw new Error('must use https protocol');
    }
    if(!cas_url.hostname) {
        throw new Error('must be a valid url like: https://example.com/cas');
    }

    this.hostname = cas_url.hostname;
    this.base_path = cas_url.pathname;
    this.port = cas_url.port || 443;
    this.service = options.service;
};

/**
 * Attempt to validate a given ticket with the CAS server.
 * `callback` is called with (err, auth_status, username, extended)
 *
 * @param {String} ticket
 *     A service ticket (ST)
 * @param {Function} callback
 *     callback(err, auth_status, username, extended).
 *     `extended` is an object containing:
 *       - username
 *       - attributes
 *       - ticket
 * @param {String} service
 *     The URL of the service requesting authentication. Optional if
 *     the `service` option was already specified during initialization.
 * @param {Boolean} renew
 *     (optional) Set this to TRUE to force the CAS server to request
 *     credentials from the user even if they had already done so
 *     recently.
 * @api public
 */
CAS.prototype.validate = function(ticket, callback, service, renew) {

    var validatePath;
    var protocol_version = this.protocol_version;
    if(protocol_version < 2.0) {
        validatePath = 'validate';
    } else {
        validatePath = "serviceValidate";
    }
    var service_url = service || this.service;
    if(!service_url) {
        throw new Error('service cannot be null');
    }
    var query = {
        'ticket': ticket,
        'service': service_url
    };
    if(renew) {
        query['renew'] = 1;
    }
    var queryPath = url.format({
        pathname: this.base_path + '/' + validatePath,
        query: query
    });
    var options = {
        hostname: this.hostname,
        port: this.port,
        path: queryPath,
        rejectUnauthorized: false
    };
    var req = https.get(options, function(res) {
        res.setEncoding('utf8');
        var data = [];

        res.on('data', function(chunk) {
            data.push(chunk);
        });
        res.on('end', function() {
            var response = data.join('');
            if(protocol_version < 2.0) {
                var sections = response.split('\n');
                if(sections.length >= 1) {
                    if(sections[0] === 'no') {
                        callback(undefined, false);
                    } else if(sections[0] === 'yes' && sections.length >= 2) {
                        callback(undefined, true, sections[1]);
                        return;
                    }
                }
            }

            var parser = new xml2js.Parser();
            parser.parseString(response, function(err, result) {
                if(err) {
                    callback(new Error("xml2js cannot parse response: " + response));
                    return;
                }

                var elemSuccess = result['cas:serviceResponse']['cas:authenticationSuccess'];
                if(elemSuccess) {
                    elemSuccess = elemSuccess[0];
                    var elemUser = elemSuccess['cas:user'];
                    if(!elemUser) {
                        callback(new Error('No username'), false);
                        return;
                    }

                    var username = elemUser[0];
                    callback(null, true, username);
                    return;
                }

                var elemFailure = result['cas:serviceResponse']['cas:authenticationFailure'];
                if(elemFailure) {
                    elemFailure = elemFailure[0];
                    var code = elemFailure['$']['code'];
                    var message = 'Validation failed [' + code + ']:';
                    message += elemFailure['_'];
                    callback(new Error(message), false);
                    return;
                }

                callback(new Error('Error response format'));
                return;
            });
        });

        res.on('error', function(e) {
            callback(e);
        });
    });
    req.on('error', function(error) {
        callback(error);
    });
};
