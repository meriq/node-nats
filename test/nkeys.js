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
/* global describe: false, before: false, after: false, it: false, afterEach: false, beforeEach: false */
/* jshint -W030 */
'use strict';

var NATS = require('../'),
    nsc = require('./support/nats_server_control'),
    ncu = require('./support/nats_conf_utils'),
    os = require('os'),
    path = require('path'),
    should = require('should'),
    fs = require('fs'),
    nuid = require('nuid'),
    nkeys = require('ts-nkeys');


describe('Auth Basics', function() {

    var PORT = 6588;
    var server;
    var userKeyPair, userSeed, userPublicKey;

    // Start up our own nats-server
    before(function(done) {
        userKeyPair = nkeys.createUser();
        userSeed = userKeyPair.getSeed();
        userPublicKey = userKeyPair.getPublicKey();

        var conf = {
            authorization: {
                users: [{ nkey: userPublicKey }]
            }
        };
        var cf = path.resolve(os.tmpdir(), 'conf-' + nuid.next() + '.conf');
        fs.writeFile(cf, ncu.j(conf), function(err) {
            if(err) {
                done(err);
            } else {
                server = nsc.start_server(PORT, ['-c', cf], done);
            }
        });
    });

    // Shutdown our server
    after(function(done) {
        nsc.stop_server(server, done);
    });

    function signer(kp) {
        var ah = {};
        ah.sign = function(data) {
            return kp.sign(data);
        };
        ah.id = kp.getPublicKey();
        return ah;
    }

    it('sign in using nkeys', function(done) {
        var ah = signer(userKeyPair);

        var nc = NATS.connect({
            port: PORT,
            authHandler: ah
        });

        nc.on('permission_error', function() {
            done("error connecting");
        });
        nc.on('connect', function() {
            done();
        });
    });

    it('bad user', function(done) {
        var kp = nkeys.createUser();
        var ah = signer(kp);

        var nc = NATS.connect({
            port: PORT,
            authHandler: ah
        });

        nc.on('error', function(err) {
            should.exist(err);
            should.exist((/Authorization/).exec(err));
            nc.close();
            done();
        });
    });

    it('bad handler', function(done) {
        var ah = {};
        ah.sign = function() {
            throw new Error("testing error");
        };
        ah.id = "foo";

        var nc = NATS.connect({
            port: PORT,
            authHandler: ah
        });

        nc.on('error', function(err) {
            should.exist(err);
            (err.code).should.be.equal(NATS.API_ERR);
            nc.close();
            done();
        });
    });
});
