/*
 * Copyright 2013-2018 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* jslint node: true */
'use strict';

/**
 * Module Dependencies
 */
var net = require('net'),
    tls = require('tls'),
    url = require('url'),
    util = require('util'),
    events = require('events'),
    nuid = require('nuid'),
    nkeys = require('ts-nkeys'),
    fs = require('fs');

/**
 * Constants
 */
var VERSION = '1.2.2',

    DEFAULT_PORT = 4222,
    DEFAULT_PRE = 'nats://localhost:',
    DEFAULT_URI = DEFAULT_PRE + DEFAULT_PORT,

    MAX_CONTROL_LINE_SIZE = 1024,

    // Parser state
    AWAITING_CONTROL = 0,
    AWAITING_MSG_PAYLOAD = 1,

    // Reconnect Parameters, 2 sec wait, 10 tries
    DEFAULT_RECONNECT_TIME_WAIT = 2 * 1000,
    DEFAULT_MAX_RECONNECT_ATTEMPTS = 10,

    // Ping interval
    DEFAULT_PING_INTERVAL = 2 * 60 * 1000, // 2 minutes
    DEFAULT_MAX_PING_OUT = 2,

    // Protocol
    MSG = /^MSG\s+([^\s\r\n]+)\s+([^\s\r\n]+)\s+(([^\s\r\n]+)[^\S\r\n]+)?(\d+)\r\n/i,
    OK = /^\+OK\s*\r\n/i,
    ERR = /^-ERR\s+('.+')?\r\n/i,
    PING = /^PING\r\n/i,
    PONG = /^PONG\r\n/i,
    INFO = /^INFO\s+([^\r\n]+)\r\n/i,
    SUBRE = /^SUB\s+([^\r\n]+)\r\n/i,
    CREDS = /\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))/i,

    CR_LF = '\r\n',
    CR_LF_LEN = CR_LF.length,
    EMPTY = '',
    SPC = ' ',

    // Protocol
    SUB = 'SUB',
    UNSUB = 'UNSUB',
    CONNECT = 'CONNECT',

    // Responses
    PING_REQUEST = 'PING' + CR_LF,
    PONG_RESPONSE = 'PONG' + CR_LF,

    // Errors
    BAD_AUTHENTICATION = 'BAD_AUTHENTICATION',
    BAD_AUTHENTICATION_MSG = 'User and Token can not both be provided',
    BAD_JSON = 'BAD_JSON',
    BAD_JSON_MSG = 'Message should be a non-circular JSON-serializable value',
    BAD_MSG = 'BAD_MSG',
    BAD_MSG_MSG = 'Message can\'t be a function',
    BAD_REPLY = 'BAD_REPLY',
    BAD_REPLY_MSG = 'Reply can\'t be a function',
    BAD_SUBJECT = 'BAD_SUBJECT',
    BAD_SUBJECT_MSG = 'Subject must be supplied',
    CLIENT_CERT_REQ = 'CLIENT_CERT_REQ',
    CLIENT_CERT_REQ_MSG = 'Server requires a client certificate.',
    CONN_CLOSED = 'CONN_CLOSED',
    CONN_CLOSED_MSG = 'Connection closed',
    CONN_ERR = 'CONN_ERR',
    CONN_ERR_MSG_PREFIX = 'Could not connect to server: ',
    INVALID_ENCODING = 'INVALID_ENCODING',
    INVALID_ENCODING_MSG_PREFIX = 'Invalid Encoding:',
    NATS_PROTOCOL_ERR = 'NATS_PROTOCOL_ERR',
    NON_SECURE_CONN_REQ = 'NON_SECURE_CONN_REQ',
    NON_SECURE_CONN_REQ_MSG = 'Server does not support a secure connection.',
    PERMISSIONS_ERR = "permissions violation",
    REQ_TIMEOUT = 'REQ_TIMEOUT',
    REQ_TIMEOUT_MSG_PREFIX = 'The request timed out for subscription id: ',
    SECURE_CONN_REQ = 'SECURE_CONN_REQ',
    SECURE_CONN_REQ_MSG = 'Server requires a secure connection.',
    STALE_CONNECTION_ERR = 'stale connection',
    SIGNATURE_REQUIRED = 'SIG_REQ',
    SIGNATURE_REQUIRED_MSG = 'Server requires an Nkey signature.',
    SIGCB_NOTFUNC = 'SIG_NOT_FUNC',
    SIGCB_NOTFUNC_MSG = 'Signature callback is not a function.',
    NKEY_OR_JWT_REQ = 'NKEY_OR_JWT_REQ',
    NKEY_OR_JWT_REQ_MSG = 'An Nkey or User JWT callback needs to be defined.',
    BAD_CREDS = 'BAD_CREDENTIALS',
    BAD_CREDS_MSG = 'Bad user credentials',
    NO_SEED_IN_CREDS = 'NO_SEED_IN_CREDS',
    NO_SEED_IN_CREDS_MSG = 'Can not locate signing key in credentials',
    NO_USER_JWT_IN_CREDS = 'NO_USER_JWT_IN_CREDS',
    NO_USER_JWT_IN_CREDS_MSG = 'Can not locate user jwt in credentials.',
    BAD_OPTIONS = 'BAD_OPTIONS',
    BAD_OPTIONS_MSG = 'Options should be an object as second paramater.',

    FLUSH_THRESHOLD = 65536;

/**
 * @param {String} message
 * @param {String} code
 * @param {Error} [chainedError]
 * @constructor
 *
 * @api private
 */
function NatsError(message, code, chainedError) {
    Error.captureStackTrace(this, this.constructor);
    this.name = this.constructor.name;
    this.message = message;
    this.code = code;
    this.chainedError = chainedError;
}

util.inherits(NatsError, Error);
exports.NatsError = NatsError;

/**
 * Library Version
 */
exports.version = VERSION;

/**
 * Error codes
 */
exports.BAD_SUBJECT = BAD_SUBJECT;
exports.BAD_MSG = BAD_MSG;
exports.BAD_REPLY = BAD_REPLY;
exports.CONN_CLOSED = CONN_CLOSED;
exports.BAD_JSON = BAD_JSON;
exports.BAD_AUTHENTICATION = BAD_AUTHENTICATION;
exports.INVALID_ENCODING = INVALID_ENCODING;
exports.SECURE_CONN_REQ = SECURE_CONN_REQ;
exports.NON_SECURE_CONN_REQ = NON_SECURE_CONN_REQ;
exports.CLIENT_CERT_REQ = CLIENT_CERT_REQ;
exports.NATS_PROTOCOL_ERR = NATS_PROTOCOL_ERR;
exports.REQ_TIMEOUT = REQ_TIMEOUT;


/**
 * Create a properly formatted inbox subject.
 *
 * @api public
 */
var createInbox = exports.createInbox = function() {
    return ("_INBOX." + nuid.next());
};

/**
 * Initialize a client with the appropriate options.
 *
 * @param {Mixed} [opts]
 * @api public
 */
function Client(opts) {
    events.EventEmitter.call(this);
    this.parseOptions(opts);
    this.initState();
    this.createConnection();
}

/**
 * Connect to a nats-server and return the client.
 * Argument can be a url, or an object with a 'url'
 * property and additional options.
 *
 * @params {Mixed} [url] - Url, port, or options object
 * @params {Object} [opts] - Options
 * @api public
 */
exports.connect = function(url, opts) {
    // If we receive one parameter, parser will
    // figure out intent. If we provided opts, then
    // first parameter should be url, and second an
    // options object.
    if (opts !== undefined) {
        if ('object' !== typeof opts) {
            this.emit('error', new NatsError(BAD_OPTIONS_MSG, BAD_OPTIONS));
            return;
        }
        opts.url = sanitizeUrl(url);
    } else {
        opts = url;
    }
    return new Client(opts);
};

/**
 * Connected clients are event emitters.
 */
util.inherits(Client, events.EventEmitter);

/**
 * Allow createInbox to be called on a client.
 *
 * @api public
 */
Client.prototype.createInbox = createInbox;

Client.prototype.assignOption = function(opts, prop, assign) {
    if (assign === undefined) {
        assign = prop;
    }
    if (opts[prop] !== undefined) {
        this.options[assign] = opts[prop];
    }
};

function shuffle(array) {
    for (var i = array.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
    return array;
}

/**
 * Parse the conctructor/connect options.
 *
 * @param {Mixed} [opts]
 * @api private
 */
Client.prototype.parseOptions = function(opts) {
    var options = this.options = {
        verbose: false,
        pedantic: false,
        reconnect: true,
        maxReconnectAttempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
        reconnectTimeWait: DEFAULT_RECONNECT_TIME_WAIT,
        encoding: 'utf8',
        tls: false,
        waitOnFirstConnect: false,
        pingInterval: DEFAULT_PING_INTERVAL,
        maxPingOut: DEFAULT_MAX_PING_OUT,
        useOldRequestStyle: false
    };


    if (undefined === opts) {
        options.url = DEFAULT_URI;
    } else if ('number' === typeof opts) {
        options.url = DEFAULT_PRE + opts;
    } else if ('string' === typeof opts) {
        options.url = sanitizeUrl(opts);
    } else if ('object' === typeof opts) {
        if (opts.port !== undefined) {
            options.url = DEFAULT_PRE + opts.port;
        }
        // Pull out various options here
        this.assignOption(opts, 'url');
        this.assignOption(opts, 'uri', 'url');
        this.assignOption(opts, 'user');
        this.assignOption(opts, 'pass');
        this.assignOption(opts, 'token');
        this.assignOption(opts, 'password', 'pass');
        this.assignOption(opts, 'verbose');
        this.assignOption(opts, 'pedantic');
        this.assignOption(opts, 'reconnect');
        this.assignOption(opts, 'maxReconnectAttempts');
        this.assignOption(opts, 'reconnectTimeWait');
        this.assignOption(opts, 'servers');
        this.assignOption(opts, 'urls', 'servers');
        this.assignOption(opts, 'noRandomize');
        this.assignOption(opts, 'NoRandomize', 'noRandomize');
        this.assignOption(opts, 'dontRandomize', 'noRandomize');
        this.assignOption(opts, 'encoding');
        this.assignOption(opts, 'tls');
        this.assignOption(opts, 'secure', 'tls');
        this.assignOption(opts, 'name');
        this.assignOption(opts, 'client', 'name');
        this.assignOption(opts, 'yieldTime');
        this.assignOption(opts, 'waitOnFirstConnect');
        this.assignOption(opts, 'json');
        this.assignOption(opts, 'preserveBuffers');
        this.assignOption(opts, 'pingInterval');
        this.assignOption(opts, 'maxPingOut');
        this.assignOption(opts, 'useOldRequestStyle');
        this.assignOption(opts, 'sigCB', 'sig');
        this.assignOption(opts, 'sigcb', 'sig');
        this.assignOption(opts, 'sigCallback', 'sig');
        this.assignOption(opts, 'nkey', 'nkey');
        this.assignOption(opts, 'nkeys', 'nkey');
        this.assignOption(opts, 'userjwt', 'userjwt');
        this.assignOption(opts, 'jwt', 'userjwt');
        this.assignOption(opts, 'JWT', 'userjwt');
        this.assignOption(opts, 'userJWT', 'userjwt');
        this.assignOption(opts, 'usercreds', 'usercreds');
        this.assignOption(opts, 'userCreds', 'usercreds');
        this.assignOption(opts, 'credentials', 'usercreds');
    }

    var client = this;

    // Set user/pass as needed if in options.
    client.user = options.user;
    client.pass = options.pass;

    // Set token as needed if in options.
    client.token = options.token;

    // Authentication - make sure authentication is valid.
    if (client.user && client.token) {
        throw (new NatsError(BAD_AUTHENTICATION_MSG, BAD_AUTHENTICATION));
    }

    // Encoding - make sure its valid.
    if (Buffer.isEncoding(options.encoding)) {
        client.encoding = options.encoding;
    } else {
        throw new NatsError(INVALID_ENCODING_MSG_PREFIX + options.encoding, INVALID_ENCODING);
    }
    // For cluster support
    client.servers = [];

    if (Array.isArray(options.servers)) {
        options.servers.forEach(function(server) {
            client.servers.push(new Server(url.parse(server)));
        });
        // Randomize if needed
        if (options.noRandomize !== true) {
            shuffle(client.servers);
        }

        // if they gave an URL we should add it if different
        if (options.url !== undefined && client.servers.indexOf(options.url) === -1) {
            // Make url first element so it is attempted first
            client.servers.unshift(new Server(url.parse(options.url)));
        }
    } else {
        if (undefined === options.url) {
            options.url = DEFAULT_URI;
        }
        client.servers.push(new Server(url.parse(options.url)));
    }
    // If we are not setup for tls, but were handed a url with a tls:// prefix
    // then upgrade to tls.
    if (options.tls === false) {
        client.servers.forEach(function(server) {
            if (server.url.protocol === 'tls' || server.url.protocol === 'tls:') {
                options.tls = true;
            }
        });
    }
};

function sanitizeUrl(host) {
    if ((/^.*:\/\/.*/).exec(host) === null) {
        // Does not have a scheme.
        host = 'nats://' + host;
    }
    var u = url.parse(host);
    if (u.port === null || u.port == '') {
        host += ":" + DEFAULT_PORT;
    }
    return host;
}

/**
 * Create a new server.
 *
 * @api private
 */
function Server(url) {
    this.url = url;
    this.didConnect = false;
    this.reconnects = 0;
}

/**
 * @api private
 */
Server.prototype.toString = function() {
    return this.url.href;
};

/**
 * Properly select the next server.
 * We rotate the server list as we go,
 * we also pull auth from urls as needed, or
 * if they were set in options use that as override.
 *
 * @api private
 */
Client.prototype.selectServer = function() {
    var client = this;
    var server = client.servers.shift();

    // Place in client context.
    client.currentServer = server;
    client.url = server.url;
    if ('auth' in server.url && !!server.url.auth) {
        var auth = server.url.auth.split(':');
        if (auth.length !== 1) {
            if (client.options.user === undefined) {
                client.user = auth[0];
            }
            if (client.options.pass === undefined) {
                client.pass = auth[1];
            }
        } else {
            if (client.options.token === undefined) {
                client.token = auth[0];
            }
        }
    }
    client.servers.push(server);
};

/**
 * Check for TLS configuration mismatch.
 *
 * @api private
 */
Client.prototype.checkTLSMismatch = function() {
    // Switch over to TLS as needed on the fly.
    if (this.info.tls_required === true ||
        (this.options.tls !== false && this.stream.encrypted !== true)) {
        if (undefined === this.options.tls || this.options.tls === false) {
            this.options.tls = true;
        }
    }

    if (this.info.tls_required === true &&
        this.options.tls === false) {
        this.emit('error', new NatsError(SECURE_CONN_REQ_MSG, SECURE_CONN_REQ));
        this.closeStream();
        return true;
    }

    if (!this.info.tls_required && this.options.tls !== false) {
        this.emit('error', new NatsError(NON_SECURE_CONN_REQ_MSG, NON_SECURE_CONN_REQ));
        this.closeStream();
        return true;
    }

    if (this.info.tls_verify === true &&
        this.options.tls.cert === undefined) {
        this.emit('error', new NatsError(CLIENT_CERT_REQ_MSG, CLIENT_CERT_REQ));
        this.closeStream();
        return true;
    }
    return false;
};

/**
 * Load a user jwt from a chained credential file.
 *
 * @api private
 */
Client.prototype.loadUserJWT = function() {
    var contents = fs.readFileSync(this.options.usercreds);
    var m = CREDS.exec(contents); // jwt
    if (m === null) {
        this.emit('error', new NatsError(NO_USER_JWT_IN_CREDS_MSG, NO_USER_JWT_IN_CREDS));
        this.closeStream();
        return;
    }
    return m[1];
};

/**
 * Load a user nkey seed from a chained credential file
 * and sign nonce.
 *
 * @api private
 */
Client.prototype.loadKeyAndSignNonce = function(nonce) {
    var contents = fs.readFileSync(this.options.usercreds);
    var re = new RegExp(CREDS, 'g');
    re.exec(contents); // jwt
    var m = re.exec(contents); // seed
    if (m === null) {
        this.emit('error', new NatsError(NO_SEED_IN_CREDS_MSG, NO_SEED_IN_CREDS));
        this.closeStream();
        return;
    }
    var sk = nkeys.fromSeed(Buffer.from(m[1]));
    return sk.sign(nonce);
};

/**
 * Helper that takes a user credentials file and
 * generates the proper opts object with proper handlers
 * filled in. e.g nats.connect(url, nats.creds("my_creds.ttx")
 *
 * @params {String} [filepath]
 *
 * @api public
 */
exports.creds = function(filepath) {
    if (undefined === filepath) {
        return undefined;
    }
    return {
        usercreds: filepath
    };
};

/**
 * Check for Nkey mismatch.
 *
 * @api private
 */
Client.prototype.checkNkeyMismatch = function() {
    if (undefined === this.info.nonce) {
        return false;
    }

    // If this has been specified make sure we can open the file and parse it.
    if (this.options.usercreds !== undefined) {
        // Treat this as a filename.
        // For now we will not capture an error on file not found etc.
        var contents = fs.readFileSync(this.options.usercreds);
        if (CREDS.exec(contents) === null) {
            this.emit('error', new NatsError(BAD_CREDS_MSG, BAD_CREDS));
            this.closeStream();
            return true;
        }
        // We have a valid file, set up callback handlers.
        var client = this;
        this.options.sig = function(nonce) {
            return client.loadKeyAndSignNonce(nonce);
        };
        this.options.userjwt = function() {
            return client.loadUserJWT();
        };
        return false;
    }

    if (undefined === this.options.sig) {
        this.emit('error', new NatsError(SIGNATURE_REQUIRED_MSG, SIGNATURE_REQUIRED));
        this.closeStream();
        return true;
    }
    if (typeof (this.options.sig) !== 'function') {
        this.emit('error', new NatsError(SIGCB_NOTFUNC_MSG, SIGCB_NOTFUNC));
        this.closeStream();
        return true;
    }
    if (undefined === this.options.nkey && undefined === this.options.userjwt) {
        this.emit('error', new NatsError(NKEY_OR_JWT_REQ_MSG, NKEY_OR_JWT_REQ));
        this.closeStream();
        return true;
    }
    return false;
};


/**
 * Callback for first flush/connect.
 *
 * @api private
 */
Client.prototype.connectCB = function() {
    var wasReconnecting = this.reconnecting;
    var event = (wasReconnecting === true) ? 'reconnect' : 'connect';
    this.reconnecting = false;
    this.reconnects = 0;
    this.wasConnected = true;
    this.currentServer.didConnect = true;

    this.emit(event, this);

    this.flushPending();
};


Client.prototype.scheduleHeartbeat = function() {
    this.pingTimer = setTimeout(function(client) {
        client.emit('pingtimer');
        if (client.closed) {
            return;
        }
        // we could be waiting on the socket to connect
        if (client.stream && !client.stream.connecting) {
            client.emit('pingcount', client.pout);
            client.pout++;
            if (client.pout > client.options.maxPingOut) {
                // processErr will scheduleReconnect
                client.processErr(STALE_CONNECTION_ERR);
                // don't reschedule, new connection initiated
                return;
            } else {
                // send the ping
                client.sendCommand(PING_REQUEST);
                if (client.pongs) {
                    // no callback
                    client.pongs.push(undefined);
                }

            }
        }
        // reschedule
        client.scheduleHeartbeat();
    }, this.options.pingInterval, this);
};

/**
 * Properly setup a stream event handlers.
 *
 * @api private
 */
Client.prototype.setupHandlers = function() {
    var client = this;
    var stream = client.stream;

    if (undefined === stream) {
        return;
    }

    stream.on('connect', function() {
        if (client.pingTimer) {
            clearTimeout(client.pingTimer);
            delete client.pingTimer;
        }
        client.connected = true;
        client.scheduleHeartbeat();
    });

    stream.on('close', function(hadError) {
        client.closeStream();
        client.emit('disconnect');
        if (client.closed === true ||
            client.options.reconnect === false ||
            ((client.reconnects >= client.options.maxReconnectAttempts) && client.options.maxReconnectAttempts !== -1)) {
            client.emit('close');
        } else {
            client.scheduleReconnect();
        }
    });

    stream.on('error', function(exception) {
        // If we were connected just return, close event will process
        if (client.wasConnected === true && client.currentServer.didConnect === true) {
            return;
        }

        // if the current server did not connect at all, and we in
        // general have not connected to any server, remove it from
        // this list. Unless overidden
        if (client.wasConnected === false && client.currentServer.didConnect === false) {
            // We can override this behavior with waitOnFirstConnect, which will
            // treat it like a reconnect scenario.
            if (client.options.waitOnFirstConnect) {
                // Pretend to move us into a reconnect state.
                client.currentServer.didConnect = true;
            } else {
                client.servers.splice(client.servers.length - 1, 1);
            }
        }

        // Only bubble up error if we never had connected
        // to the server and we only have one.
        if (client.wasConnected === false && client.servers.length === 0) {
            client.emit('error', new NatsError(CONN_ERR_MSG_PREFIX + exception, CONN_ERR, exception));
        }
        client.closeStream();
    });

    stream.on('data', function(data) {
        // If inbound exists, concat them together. We try to avoid this for split
        // messages, so this should only really happen for a split control line.
        // Long term answer is hand rolled parser and not regexp.
        if (client.inbound) {
            client.inbound = Buffer.concat([client.inbound, data]);
        } else {
            client.inbound = data;
        }

        // Process the inbound queue.
        client.processInbound();
    });
};

/**
 * Send the connect command. This needs to happen after receiving the first
 * INFO message and after TLS is established if necessary.
 *
 * @api private
 */
Client.prototype.sendConnect = function() {
    // Queue the connect command.
    var cs = {
        'lang': 'node',
        'version': VERSION,
        'verbose': this.options.verbose,
        'pedantic': this.options.pedantic,
        'protocol': 1
    };
    if (this.info.nonce !== undefined && this.options.sig !== undefined) {
        var sig = this.options.sig(Buffer.from(this.info.nonce));
        cs.sig = sig.toString('base64');
    }
    if (this.options.userjwt !== undefined) {
        if (typeof (this.options.userjwt) === 'function') {
            cs.jwt = this.options.userjwt();
        } else {
            cs.jwt = this.options.userjwt;
        }
    }
    if (this.options.nkey !== undefined) {
        cs.nkey = this.options.nkey;
    }
    if (this.user !== undefined) {
        cs.user = this.user;
        cs.pass = this.pass;
    }
    if (this.token !== undefined) {
        cs.auth_token = this.token;
    }
    if (this.options.name !== undefined) {
        cs.name = this.options.name;
    }
    if (this.options.nkey !== undefined) {
        cs.nkey = this.options.nkey;
    }

    // If we enqueued requests before we received INFO from the server, or we
    // reconnected, there be other data pending, write this immediately instead
    // of adding it to the queue.
    this.stream.write(CONNECT + SPC + JSON.stringify(cs) + CR_LF);
};

/**
 * Properly setup a stream connection with proper events.
 *
 * @api private
 */
Client.prototype.createConnection = function() {
    // Commands may have been queued during reconnect. Discard everything except:
    // 1) ping requests with a pong callback
    // 2) publish requests
    //
    // Rationale: CONNECT and SUBs are written directly upon connecting, any PONG
    // response is no longer relevant, and any UNSUB will be accounted for when we
    // sync our SUBs. Without this, users of the client may miss state transitions
    // via callbacks, would have to track the client's internal connection state,
    // and may have to double buffer messages (which we are already doing) if they
    // wanted to ensure their messages reach the server.
    var pong = [];
    var pend = [];
    var pSize = 0;
    var client = this;
    if (client.pending !== null) {
        var pongIndex = 0;
        client.pending.forEach(function(cmd) {
            var cmdLen = Buffer.isBuffer(cmd) ? cmd.length : Buffer.byteLength(cmd);
            if (cmd === PING_REQUEST && client.pongs !== null && pongIndex < client.pongs.length) {
                // filter out any useless ping requests (no pong callback, nop flush)
                var p = client.pongs[pongIndex++];
                if (p !== undefined) {
                    pend.push(cmd);
                    pSize += cmdLen;
                    pong.push(p);
                }
            } else if (cmd.length > 3 && cmd[0] === 'P' && cmd[1] === 'U' && cmd[2] === 'B') {
                pend.push(cmd);
                pSize += cmdLen;
            }
        });
    }
    this.pongs = pong;
    this.pending = pend;
    this.pSize = pSize;

    this.pstate = AWAITING_CONTROL;

    // Clear info processing.
    this.info = null;
    this.infoReceived = false;

    // Select a server to connect to.
    this.selectServer();

    // See #45 if we have a stream release the listeners otherwise in addition
    // to the leaking of events, the old events will still fire.
    if (this.stream) {
        this.stream.removeAllListeners();
        this.stream.destroy();
    }
    // Create the stream
    this.stream = net.createConnection(this.url.port, this.url.hostname);
    // this change makes it a bit faster on Linux, slightly worse on OS X
    this.stream.setNoDelay(true);
    // Setup the proper handlers.
    this.setupHandlers();
};

/**
 * Initialize client state.
 *
 * @api private
 */
Client.prototype.initState = function() {
    this.ssid = 1;
    this.subs = {};
    this.reconnects = 0;
    this.connected = false;
    this.wasConnected = false;
    this.reconnecting = false;
    this.server = null;
    this.pending = [];
    this.pout = 0;
};

/**
 * Close the connection to the server.
 *
 * @api public
 */
Client.prototype.close = function() {
    if (this.pingTimer) {
        clearTimeout(this.pingTimer);
        delete this.pingTimer;
    }
    this.closed = true;
    this.removeAllListeners();
    this.closeStream();
    this.ssid = -1;
    this.subs = null;
    this.pstate = -1;
    this.pongs = null;
    this.pending = null;
    this.pSize = 0;
};

/**
 * Close down the stream and clear state.
 *
 * @api private
 */
Client.prototype.closeStream = function() {
    if (this.stream !== null) {
        this.stream.destroy();
        this.stream = null;
    }
    if (this.connected === true || this.closed === true) {
        this.pongs = null;
        this.pout = 0;
        this.pending = null;
        this.pSize = 0;
        this.connected = false;
    }
    this.inbound = null;
};

/**
 * Flush all pending data to the server.
 *
 * @api private
 */
Client.prototype.flushPending = function() {
    if (this.connected === false ||
        this.pending === null ||
        this.pending.length === 0 ||
        this.infoReceived !== true) {
        return;
    }

    var client = this;
    var write = function(data) {
        client.pending = [];
        client.pSize = 0;
        return client.stream.write(data);
    };
    if (!this.pBufs) {
        // All strings, fastest for now.
        return write(this.pending.join(EMPTY));
    } else {
        // We have some or all Buffers. Figure out if we can optimize.
        var allBufs = true;
        for (var i = 0; i < this.pending.length; i++) {
            if (!Buffer.isBuffer(this.pending[i])) {
                allBufs = false;
                break;
            }
        }
        // If all buffers, concat together and write once.
        if (allBufs) {
            return write(Buffer.concat(this.pending, this.pSize));
        } else {
            // We have a mix, so write each one individually.
            var pending = this.pending;
            this.pending = [];
            this.pSize = 0;
            var result = true;
            for (i = 0; i < pending.length; i++) {
                result = this.stream.write(pending[i]) && result;
            }
            return result;
        }
    }
};

/**
 * Strips all SUBS commands from pending during initial connection completed since
 * we send the subscriptions as a separate operation.
 *
 * @api private
 */
Client.prototype.stripPendingSubs = function() {
    var pending = this.pending;
    this.pending = [];
    this.pSize = 0;
    for (var i = 0; i < pending.length; i++) {
        if (!SUBRE.test(pending[i])) {
            // Re-queue the command.
            this.sendCommand(pending[i]);
        }
    }
};

/**
 * Send commands to the server or queue them up if connection pending.
 *
 * @api private
 */
Client.prototype.sendCommand = function(cmd) {
    // Buffer to cut down on system calls, increase throughput.
    // When receive gets faster, should make this Buffer based..

    if (this.closed || this.pending === null) {
        return;
    }

    this.pending.push(cmd);
    if (!Buffer.isBuffer(cmd)) {
        this.pSize += Buffer.byteLength(cmd);
    } else {
        this.pSize += cmd.length;
        this.pBufs = true;
    }

    if (this.connected === true) {
        // First one let's setup flush..
        if (this.pending.length === 1) {
            var self = this;
            setImmediate(function() {
                self.flushPending();
            });
        } else if (this.pSize > FLUSH_THRESHOLD) {
            // Flush in place when threshold reached..
            this.flushPending();
        }
    }
};

/**
 * Sends existing subscriptions to new server after reconnect.
 *
 * @api private
 */
Client.prototype.sendSubscriptions = function() {
    var protos = "";
    for (var sid in this.subs) {
        if (this.subs.hasOwnProperty(sid)) {
            var sub = this.subs[sid];
            var proto;
            if (sub.qgroup) {
                proto = [SUB, sub.subject, sub.qgroup, sid + CR_LF];
            } else {
                proto = [SUB, sub.subject, sid + CR_LF];
            }
            protos += proto.join(SPC);
        }
    }
    if (protos.length > 0) {
        this.stream.write(protos);
    }
};

/**
 * Process the inbound data queue.
 *
 * @api private
 */
Client.prototype.processInbound = function() {
    var client = this;

    // Hold any regex matches.
    var m;

    // For optional yield
    var start;

    if (!client.stream) {
        // if we are here, the stream was reaped and errors raised
        // if we continue.
        return;
    }
    // unpause if needed.
    // FIXME(dlc) client.stream.isPaused() causes 0.10 to fail
    client.stream.resume();

    /* jshint -W083 */

    if (client.options.yieldTime !== undefined) {
        start = Date.now();
    }

    while (!client.closed && client.inbound && client.inbound.length > 0) {
        switch (client.pstate) {

            case AWAITING_CONTROL:
                // Regex only works on strings, so convert once to be more efficient.
                // Long term answer is a hand rolled parser, not regex.
                var buf = client.inbound.toString('binary', 0, MAX_CONTROL_LINE_SIZE);
                if ((m = MSG.exec(buf)) !== null) {
                    client.payload = {
                        subj: m[1],
                        sid: parseInt(m[2], 10),
                        reply: m[4],
                        size: parseInt(m[5], 10)
                    };
                    client.payload.psize = client.payload.size + CR_LF_LEN;
                    client.pstate = AWAITING_MSG_PAYLOAD;
                } else if ((m = OK.exec(buf)) !== null) {
                    // Ignore for now..
                } else if ((m = ERR.exec(buf)) !== null) {
                    client.processErr(m[1]);
                    return;
                } else if ((m = PONG.exec(buf)) !== null) {
                    client.pout = 0;
                    var cb = client.pongs && client.pongs.shift();
                    if (cb) {
                        cb();
                    } // FIXME: Should we check for exceptions?
                } else if ((m = PING.exec(buf)) !== null) {
                    client.sendCommand(PONG_RESPONSE);
                } else if ((m = INFO.exec(buf)) !== null) {
                    client.info = JSON.parse(m[1]);
                    // Always try to read the connect_urls from info
                    client.processServerUpdate();

                    // Process first INFO
                    if (client.infoReceived === false) {
                        // Check on TLS mismatch.
                        if (client.checkTLSMismatch() === true) {
                            return;
                        }
                        if (client.checkNkeyMismatch() === true) {
                            return;
                        }

                        // Switch over to TLS as needed.
                        if (client.info.tls_required === true) {
                            var tlsOpts = {
                                socket: client.stream
                            };
                            if ('object' === typeof client.options.tls) {
                                for (var key in client.options.tls) {
                                    tlsOpts[key] = client.options.tls[key];
                                }
                            }
                            // if we have a stream, this is from an old connection, reap it
                            if (client.stream) {
                                client.stream.removeAllListeners();
                            }
                            client.stream = tls.connect(tlsOpts, function() {
                                client.flushPending();
                            });
                            client.setupHandlers();
                        }

                        // Send the connect message and subscriptions immediately
                        client.sendConnect();
                        client.sendSubscriptions();

                        client.pongs.unshift(function() {
                            client.connectCB();
                        });
                        client.stream.write(PING_REQUEST);

                        // Mark as received
                        client.infoReceived = true;
                        client.stripPendingSubs();
                        client.flushPending();
                    }
                } else {
                    // FIXME, check line length for something weird.
                    // Nothing here yet, return
                    return;
                }
                break;

            case AWAITING_MSG_PAYLOAD:

                // If we do not have the complete message, hold onto the chunks
                // and assemble when we have all we need. This optimizes for
                // when we parse a large buffer down to a small number of bytes,
                // then we receive a large chunk. This avoids a big copy with a
                // simple concat above.
                if (client.inbound.length < client.payload.psize) {
                    if (undefined === client.payload.chunks) {
                        client.payload.chunks = [];
                    }
                    client.payload.chunks.push(client.inbound);
                    client.payload.psize -= client.inbound.length;
                    client.inbound = null;
                    return;
                }

                // If we are here we have the complete message.
                // Check to see if we have existing chunks
                if (client.payload.chunks) {

                    client.payload.chunks.push(client.inbound.slice(0, client.payload.psize));
                    // don't append trailing control characters
                    var mbuf = Buffer.concat(client.payload.chunks, client.payload.size);

                    if (client.options.preserveBuffers) {
                        client.payload.msg = mbuf;
                    } else {
                        client.payload.msg = mbuf.toString(client.encoding);
                    }

                } else {

                    if (client.options.preserveBuffers) {
                        client.payload.msg = client.inbound.slice(0, client.payload.size);
                    } else {
                        client.payload.msg = client.inbound.toString(client.encoding, 0, client.payload.size);
                    }

                }

                // Eat the size of the inbound that represents the message.
                if (client.inbound.length === client.payload.psize) {
                    client.inbound = null;
                } else {
                    client.inbound = client.inbound.slice(client.payload.psize);
                }

                // process the message
                client.processMsg();

                // Reset
                client.pstate = AWAITING_CONTROL;
                client.payload = null;

                // Check to see if we have an option to yield for other events after yieldTime.
                if (start !== undefined) {
                    if ((Date.now() - start) > client.options.yieldTime) {
                        client.stream.pause();
                        setImmediate(client.processInbound.bind(this));
                        return;
                    }
                }
                break;
        }

        // This is applicable for a regex match to eat the bytes we used from a control line.
        if (m && !this.closed) {
            // Chop inbound
            var psize = m[0].length;
            if (psize >= client.inbound.length) {
                client.inbound = null;
            } else {
                client.inbound = client.inbound.slice(psize);
            }
        }
        m = null;
    }
};

/**
 * Process server updates in info object
 * @api internal
 */
Client.prototype.processServerUpdate = function() {
    var client = this;
    if (client.info.connect_urls && client.info.connect_urls.length > 0) {
        // parse the infos
        var tmp = {};
        client.info.connect_urls.forEach(function(server) {
            var u = 'nats://' + server;
            var s = new Server(url.parse(u));
            // implicit servers are ones added via the info connect_urls
            s.implicit = true;
            tmp[s.url.href] = s;
        });

        // remove implicit servers that are no longer reported
        var toDelete = [];
        client.servers.forEach(function(s, index) {
            var u = s.url.href;
            if (s.implicit && client.currentServer.url.href !== u && tmp[u] === undefined) {
                // server was removed
                toDelete.push(index);
            }
            // remove this entry from reported
            delete tmp[u];
        });

        // perform the deletion
        toDelete.reverse();
        toDelete.forEach(function(index) {
            client.servers.splice(index, 1);
        });

        // remaining servers are new
        var newURLs = [];
        for (var k in tmp) {
            if (tmp.hasOwnProperty(k)) {
                client.servers.push(tmp[k]);
                newURLs.push(k);
            }
        }

        if (newURLs.length) {
            // new reported servers useful for tests
            client.emit('serversDiscovered', newURLs);
            // simpler version
            client.emit('servers', newURLs);
        }
    }
};

/**
 * Process a delivered message and deliver to appropriate subscriber.
 *
 * @api private
 */
Client.prototype.processMsg = function() {
    var sub = this.subs[this.payload.sid];
    if (sub !== undefined) {
        sub.received += 1;
        // Check for a timeout, and cancel if received >= expected
        if (sub.timeout) {
            if (sub.received >= sub.expected) {
                clearTimeout(sub.timeout);
                sub.timeout = null;
            }
        }

        // Check for auto-unsubscribe
        if (sub.max !== undefined) {
            if (sub.received === sub.max) {
                delete this.subs[this.payload.sid];
                this.emit('unsubscribe', this.payload.sid, sub.subject);
            } else if (sub.received > sub.max) {
                this.unsubscribe(this.payload.sid);
                sub.callback = null;
            }
        }

        if (sub.callback) {
            var msg = this.payload.msg;
            if (this.options.json) {
                try {
                    if (this.options.preserveBuffers) {
                        msg = JSON.parse(this.payload.msg.toString());
                    } else {
                        msg = JSON.parse(this.payload.msg.toString(this.options.encoding));
                    }
                } catch (e) {
                    msg = e;
                }
            }
            try {
                sub.callback(msg, this.payload.reply, this.payload.subj, this.payload.sid);
            } catch (error) {
                this.emit('error', error);
            }
        }
    }
};

/**
 * ProcessErr processes any error messages from the server
 *
 * @api private
 */
Client.prototype.processErr = function(s) {
    // current NATS clients, will raise an error and close on any errors
    // except stale connection and permission errors
    var m = s ? s.toLowerCase() : '';
    if (m.indexOf(STALE_CONNECTION_ERR) !== -1) {
        // closeStream() triggers a reconnect if allowed
        this.closeStream();
    } else if (m.indexOf(PERMISSIONS_ERR) !== -1) {
        this.emit('permission_error', new NatsError(s, NATS_PROTOCOL_ERR));
    } else {
        this.emit('error', new NatsError(s, NATS_PROTOCOL_ERR));
        this.closeStream();
    }
};

/**
 * Push a new cluster server.
 *
 * @param {String} uri
 * @api public
 */
Client.prototype.addServer = function(uri) {
    this.servers.push(new Server(url.parse(uri)));

    if (this.options.noRandomize !== true) {
        shuffle(this.servers);
    }
};

/**
 * Flush outbound queue to server and call optional callback when server has processed
 * all data.
 *
 * @param {Function} [opt_callback]
 * @api public
 */
Client.prototype.flush = function(opt_callback) {
    if (this.closed) {
        if (typeof opt_callback === 'function') {
            opt_callback(new NatsError(CONN_CLOSED_MSG, CONN_CLOSED));
            return;
        } else {
            throw (new NatsError(CONN_CLOSED_MSG, CONN_CLOSED));
        }
    }
    if (this.pongs) {
        this.pongs.push(opt_callback);
        this.sendCommand(PING_REQUEST);
        this.flushPending();
    }
};

/**
 * Publish a message to the given subject, with optional reply and callback.
 *
 * @param {String} subject
 * @param {String} [msg]
 * @param {String} [opt_reply]
 * @param {Function} [opt_callback]
 * @api public
 */
Client.prototype.publish = function(subject, msg, opt_reply, opt_callback) {
    // They only supplied a callback function.
    if (typeof subject === 'function') {
        opt_callback = subject;
        subject = undefined;
    }

    if (!this.options.json) {
        msg = msg || EMPTY;
    } else {
        // undefined is not a valid JSON-serializable value, but null is
        msg = msg === undefined ? null : msg;
    }

    if (!subject) {
        if (opt_callback) {
            opt_callback(new NatsError(BAD_SUBJECT_MSG, BAD_SUBJECT));
        } else {
            throw (new NatsError(BAD_SUBJECT_MSG, BAD_SUBJECT));
        }
    }
    if (typeof msg === 'function') {
        if (opt_callback || opt_reply) {
            opt_callback(new NatsError(BAD_MSG_MSG, BAD_MSG));
            return;
        }
        opt_callback = msg;
        msg = EMPTY;
        opt_reply = undefined;
    }
    if (typeof opt_reply === 'function') {
        if (opt_callback) {
            opt_callback(new NatsError(BAD_REPLY_MSG, BAD_REPLY));
            return;
        }
        opt_callback = opt_reply;
        opt_reply = undefined;
    }

    // Hold PUB SUB [REPLY]
    var psub;
    if (opt_reply === undefined) {
        psub = 'PUB ' + subject + SPC;
    } else {
        psub = 'PUB ' + subject + SPC + opt_reply + SPC;
    }

    // Need to treat sending buffers different.
    if (!Buffer.isBuffer(msg)) {
        var str = msg;
        if (this.options.json) {
            try {
                str = JSON.stringify(msg);
            } catch (e) {
                throw (new NatsError(BAD_JSON_MSG, BAD_JSON));
            }
        }
        this.sendCommand(psub + Buffer.byteLength(str) + CR_LF + str + CR_LF);
    } else {
        var b = Buffer.allocUnsafe(psub.length + msg.length + (2 * CR_LF_LEN) + msg.length.toString().length);
        var len = b.write(psub + msg.length + CR_LF);
        msg.copy(b, len);
        b.write(CR_LF, len + msg.length);
        this.sendCommand(b);
    }

    if (opt_callback !== undefined) {
        this.flush(opt_callback);
    } else if (this.closed) {
        throw (new NatsError(CONN_CLOSED_MSG, CONN_CLOSED));
    }
};

/**
 * Subscribe to a given subject, with optional options and callback. opts can be
 * ommitted, even with a callback. The Subscriber Id is returned.
 *
 * @param {String} subject
 * @param {Object} [opts]
 * @param {Function} callback
 * @return {Number}
 * @api public
 */
Client.prototype.subscribe = function(subject, opts, callback) {
    if (this.closed) {
        throw (new NatsError(CONN_CLOSED_MSG, CONN_CLOSED));
    }
    var qgroup, max;
    if (typeof opts === 'function') {
        callback = opts;
        opts = undefined;
    } else if (opts && typeof opts === 'object') {
        // FIXME, check exists, error otherwise..
        qgroup = opts.queue;
        max = opts.max;
    }
    this.ssid += 1;
    this.subs[this.ssid] = {
        'subject': subject,
        'callback': callback,
        'received': 0
    };

    var proto;
    if (typeof qgroup === 'string') {
        this.subs[this.ssid].qgroup = qgroup;
        proto = [SUB, subject, qgroup, this.ssid + CR_LF];
    } else {
        proto = [SUB, subject, this.ssid + CR_LF];
    }

    this.sendCommand(proto.join(SPC));
    this.emit('subscribe', this.ssid, subject, opts);

    if (max) {
        this.unsubscribe(this.ssid, max);
    }
    return this.ssid;
};

/**
 * Unsubscribe to a given Subscriber Id, with optional max parameter.
 * Unsubscribing to a subscription that already yielded the specified number of messages
 * will clear any pending timeout callbacks.
 *
 * @param {Number} sid
 * @param {Number} [opt_max]
 * @api public
 */
Client.prototype.unsubscribe = function(sid, opt_max) {
    if (!sid || this.closed) {
        return;
    }

    // in the case of new muxRequest, it is possible they want perform
    // an unsubscribe with the returned 'sid'. Intercept that and clear
    // the request configuration. Mux requests are always negative numbers
    if (sid < 0) {
        this.cancelMuxRequest(sid);
        return;
    }

    var proto;
    if (opt_max) {
        proto = [UNSUB, sid, opt_max + CR_LF];
    } else {
        proto = [UNSUB, sid + CR_LF];
    }
    this.sendCommand(proto.join(SPC));

    var sub = this.subs[sid];
    if (sub === undefined) {
        return;
    }
    sub.max = opt_max;
    if (sub.max === undefined || (sub.received >= sub.max)) {
        // remove any timeouts that may be pending
        if (sub.timeout) {
            clearTimeout(sub.timeout);
            sub.timeout = null;
        }
        delete this.subs[sid];
        this.emit('unsubscribe', sid, sub.subject);
    }
};

/**
 * Set a timeout on a subscription. The subscription is cancelled if the
 * expected number of messages is reached or the timeout is reached.
 * If this function is called with an SID from a multiplexed
 * request call, the original timeout handler associated with the multiplexed
 * request is replaced with the one provided to this function.
 *
 * @param {Number} sid
 * @param {Number} timeout
 * @param {Number} expected
 * @param {Function} callback
 * @api public
 */
Client.prototype.timeout = function(sid, timeout, expected, callback) {
    if (!sid) {
        return;
    }
    var sub = null;
    // check the sid is not a mux sid - which is always negative
    if (sid < 0) {
        var conf = this.getMuxRequestConfig(sid);
        if (conf && conf.timeout) {
            // clear auto-set timeout
            clearTimeout(conf.timeout);
        }
        sub = conf;
    } else {
        sub = this.subs[sid];
    }

    if (sub) {
        sub.expected = expected;
        var that = this;
        sub.timeout = setTimeout(function() {
            callback(sid);
            // if callback fails unsubscribe will leak
            that.unsubscribe(sid);
        }, timeout);
    }
};


/**
 * Publish a message with an implicit inbox listener as the reply. Message is optional.
 * This should be treated as a subscription. You can optionally indicate how many
 * messages you only want to receive using opt_options = {max:N}. Otherwise you
 * will need to unsubscribe to stop the message stream.
 *
 * You can also optionally specify the number of milliseconds to wait for the messages
 * to receive using opt_options = {timeout: N}. When the number of messages specified
 * is received before a timeout, the subscription auto-cancels. If the number of messages
 * is not specified, it is the responsibility of the client to unsubscribe to prevent
 * a timeout.
 *
 * The Subscriber Id is returned.
 *
 * @param {String} subject
 * @param {String} [opt_msg]
 * @param {Object} [opt_options]
 * @param {Function} [callback]
 * @return {Number}
 * @api public
 */
Client.prototype.request = function(subject, opt_msg, opt_options, callback) {
    if (this.options.useOldRequestStyle) {
        return this.oldRequest(subject, opt_msg, opt_options, callback);
    }
    if (typeof opt_msg === 'function') {
        callback = opt_msg;
        opt_msg = EMPTY;
        opt_options = null;
    }
    if (typeof opt_options === 'function') {
        callback = opt_options;
        opt_options = null;
    }

    opt_options = opt_options || {};
    var conf = this.initMuxRequestDetails(callback, opt_options.max);
    this.publish(subject, opt_msg, conf.inbox);

    if (opt_options.timeout) {
        var client = this;
        conf.timeout = setTimeout(function() {
            if (conf.callback) {
                conf.callback(new NatsError(REQ_TIMEOUT_MSG_PREFIX + conf.id, REQ_TIMEOUT));
            }
            client.cancelMuxRequest(conf.token);
        }, opt_options.timeout);
    }

    return conf.id;
};


/**
 * @deprecated
 * @api private
 */
Client.prototype.oldRequest = function(subject, opt_msg, opt_options, callback) {
    if (typeof opt_msg === 'function') {
        callback = opt_msg;
        opt_msg = EMPTY;
        opt_options = null;
    }
    if (typeof opt_options === 'function') {
        callback = opt_options;
        opt_options = null;
    }
    var inbox = createInbox();
    var s = this.subscribe(inbox, opt_options, function(msg, reply) {
        callback(msg, reply);
    });
    this.publish(subject, opt_msg, inbox);
    return s;
};

/**
 * Publish a message with an implicit inbox listener as the reply. Message is optional.
 * This should be treated as a subscription. The subscription is auto-cancelled after the
 * first reply is received or the timeout in millisecond is reached.
 *
 * If a timeout is reached, the callback is invoked with a NatsError with it's code set to
 * `REQ_TIMEOUT` on the first argument of the callback function, and the subscription is
 * cancelled.
 *
 * The Subscriber Id is returned.
 *
 * @param {String} subject
 * @param {String} [opt_msg]
 * @param {Object} [opt_options]
 * @param {Number} timeout
 * @param {Function} callback - can be called with message or NatsError if the request timed out.
 * @return {Number}
 * @api public
 */
Client.prototype.requestOne = function(subject, opt_msg, opt_options, timeout, callback) {
    if (this.options.useOldRequestStyle) {
        return this.oldRequestOne(subject, opt_msg, opt_options, timeout, callback);
    }

    if (typeof opt_msg === 'number') {
        callback = opt_options;
        timeout = opt_msg;
        opt_options = null;
        opt_msg = EMPTY;
    }

    if (typeof opt_options === 'number') {
        callback = timeout;
        timeout = opt_options;
        opt_options = null;
    }

    opt_options = opt_options || {};
    opt_options.max = 1;
    opt_options.timeout = timeout;

    return this.request(subject, opt_msg, opt_options, callback);
};

/**
 * Strips the prefix of the request reply to derive the token.
 * This is internal and only used by the new requestOne.
 *
 * @api private
 */
Client.prototype.extractToken = function(subject) {
    return subject.substr(this.respmux.inboxPrefixLen);
};

/**
 * Creates a subscription for the global inbox in the new requestOne.
 * Request tokens, timer, and callbacks are tracked here.
 *
 * @api private
 */
Client.prototype.createResponseMux = function() {
    if (!this.respmux) {
        var client = this;
        var inbox = createInbox();
        var ginbox = inbox + ".*";
        var sid = this.subscribe(ginbox, function(msg, reply, subject) {
            var token = client.extractToken(subject);
            var conf = client.getMuxRequestConfig(token);
            if (conf) {
                if (conf.callback) {
                    conf.callback(msg, reply);
                }
                if (conf.hasOwnProperty('expected')) {
                    conf.received++;
                    if (conf.received >= conf.expected) {
                        client.cancelMuxRequest(token);
                        client.emit('unsubscribe', sid, subject);
                    }
                }
            }
        });
        this.respmux = {};
        this.respmux.inbox = inbox;
        this.respmux.inboxPrefixLen = inbox.length + 1;
        this.respmux.subscriptionID = sid;
        this.respmux.requestMap = {};
        this.respmux.nextID = -1;
    }
    return this.respmux.inbox;
};

/**
 * Stores the request callback and other details
 *
 * @api private
 */
Client.prototype.initMuxRequestDetails = function(callback, expected) {
    var ginbox = this.createResponseMux();
    var token = nuid.next();
    var inbox = ginbox + '.' + token;

    var conf = {
        token: token,
        callback: callback,
        inbox: inbox,
        id: this.respmux.nextID--,
        received: 0
    };
    if (expected > 0) {
        conf.expected = expected;
    }

    this.respmux.requestMap[token] = conf;
    return conf;
};

/**
 * Returns the mux request configuration
 * @param token
 * @returns Object
 */
Client.prototype.getMuxRequestConfig = function(token) {
    // if the token is a number, we have a fake sid, find the request
    if (typeof token === 'number') {
        var entry = null;
        for (var p in this.respmux.requestMap) {
            if (this.respmux.requestMap.hasOwnProperty(p)) {
                var v = this.respmux.requestMap[p];
                if (v.id === token) {
                    entry = v;
                    break;
                }
            }
        }
        if (entry) {
            token = entry.token;
        }
    }
    return this.respmux.requestMap[token];
};

/**
 * Cancels the mux request
 *
 * @api private
 */
Client.prototype.cancelMuxRequest = function(token) {
    var conf = this.getMuxRequestConfig(token);
    if (conf) {
        if (conf.timeout) {
            clearTimeout(conf.timeout);
        }
        // the token could be sid, so use the one in the conf
        delete this.respmux.requestMap[conf.token];
    }
    return conf;
};

/**
 * @deprecated
 * @api private
 */
Client.prototype.oldRequestOne = function(subject, opt_msg, opt_options, timeout, callback) {
    if (typeof opt_msg === 'number') {
        callback = opt_options;
        timeout = opt_msg;
        opt_options = null;
        opt_msg = EMPTY;
    }

    if (typeof opt_options === 'number') {
        callback = timeout;
        timeout = opt_options;
        opt_options = null;
    }

    opt_options = opt_options || {};
    opt_options.max = 1;

    var sid = this.request(subject, opt_msg, opt_options, callback);
    this.timeout(sid, timeout, 1, function() {
        callback(new NatsError(REQ_TIMEOUT_MSG_PREFIX + sid, REQ_TIMEOUT));
    });
    return sid;
};

/**
 * Report number of outstanding subscriptions on this connection.
 *
 * @return {Number}
 * @api public
 */
Client.prototype.numSubscriptions = function() {
    return Object.keys(this.subs).length;
};

/**
 * Reconnect to the server.
 *
 * @api private
 */
Client.prototype.reconnect = function() {
    if (this.closed) {
        return;
    }
    this.reconnects += 1;
    this.createConnection();
    if (this.currentServer.didConnect === true) {
        this.emit('reconnecting');
    }
};

/**
 * Setup a timer event to attempt reconnect.
 *
 * @api private
 */
Client.prototype.scheduleReconnect = function() {
    var client = this;
    // Just return if no more servers
    if (client.servers.length === 0) {
        return;
    }
    // Don't set reconnecting state if we are just trying
    // for the first time.
    if (client.wasConnected === true) {
        client.reconnecting = true;
    }
    // Only stall if we have connected before.
    var wait = 0;
    if (client.servers[0].didConnect === true) {
        wait = this.options.reconnectTimeWait;
    }
    setTimeout(function() {
        client.reconnect();
    }, wait);
};
