#!/usr/bin/env node

//override pagesigner's global vars with nodejs ones
const { exit, argv, chdir, cwd } = require('process');
const path = require('path');
fetch = require('node-fetch');
asn1js = require("asn1js"); 
pkijs = require("pkijs"); 
DOMParser = require('universal-dom-parser');
const { Crypto } = require("@peculiar/webcrypto");
crypto = new Crypto();
pkijs.setEngine("newEngine", crypto, new pkijs.CryptoEngine({ name: "", crypto: crypto, subtle: crypto.subtle }))


const node_crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const mainjs = require('../main.js');
const tlsn = require('../tlsn.js');
const utils = require('../tlsn_utils.js');
const socket = require('../socket.js');
const oracles = require('../oracles.js');
const verifychain = require('../verifychain/verifychain.js');


//make the functions callable without the prefix
ab2ba = utils.ab2ba
assert = utils.assert
ba2ab = utils.ba2ab
ba2int = utils.ba2int
ba2str = utils.ba2str
bi2ba = utils.bi2ba
b64encode = utils.b64encode
b64decode = utils.b64decode
b64urlencode = utils.b64urlencode
check_oracle = oracles.check_oracle
check_complete_records = socket.check_complete_records
checkCertSubjName = verifychain.checkCertSubjName
chosen_notary = oracles.oracle
computeCommitHash = tlsn.computeCommitHash
dechunk_http = utils.dechunk_http
decrypt_tls_responseV4 = tlsn.decrypt_tls_responseV4
eq = utils.eq
getCommonName = verifychain.getCommonName
getExpandedKeys = tlsn.getExpandedKeys
getModulus = verifychain.getModulus
getTime = utils.getTime
gunzip_http = utils.gunzip_http
oracle = oracles.oracle
parse_certs = verifychain.parse_certs
pem2ab = utils.pem2ab
pubkeyPEM2raw = utils.pubkeyPEM2raw
sha256 = utils.sha256
sigDER2p1363 = utils.sigDER2p1363
str2ba = utils.str2ba
wildTest = utils.wildTest
verifyChain = verifychain.verifyChain
verifyECParamsSig = tlsn.verifyECParamsSig
verifyNotarySig = tlsn.verifyNotarySig
verifyOldOracle = oracles.verifyOldOracle
verifyPgsg = mainjs.verifyPgsg


//override 
getRandom = function(size){
    return node_crypto.randomBytes(size).toJSON().data;
}

//override Socket
Socket = function(server, port){
    this.server = server;
    this.port = port;
    this.sock = new net.Socket();
    this.buf = [];
    this.complete_records = []; //complete records
    var parent = this

    this.sock.on('data', function(d) {
        //"this" resolves to net.Socket() not to Socket, that's why we use "parent"
        var data = d.toJSON().data
        parent.buf = [].concat(parent.buf, data)
        var rv = check_complete_records(parent.buf);
        parent.complete_records = [].concat(parent.complete_records, rv.comprecs);
        if (!rv.is_complete) {
            parent.buf = rv.incomprecs;
        }
        if (rv.is_complete){
            parent.buf = []
        }
        console.log('Received data complete', parent.complete_records.length);
        console.log('Received data incomplete', parent.buf.length);
    });
}
Socket.prototype.constructor = Socket;
Socket.prototype.connect = async function() {
    await this.sock.connect(this.port, this.server)
}
Socket.prototype.send = function(d) {
    var data = new Buffer.from(d)
    this.sock.write(data);
}
Socket.prototype.recv = async function(is_handshake) {
    if (typeof(is_handshake) === 'undefined') {
        is_handshake = false;
    }
    var that = this;
    var resolved = false;

    return await new Promise(function(resolve, reject){  
        
        var timer = setTimeout(function() {
            resolved = true;
            reject('recv: socket timed out');
          }, 20*1000);
        
        function finished_receiving() {
            clearTimeout(timer);
            console.log('recv promise resolving');
            resolved = true;
            resolve(that.complete_records);
            //zero out the records because we're gonna be reusing this socket 
            that.complete_records = [] 
        };

        var check = function(){
            if (resolved) {
                return;
            }
            if (that.complete_records.length == 0 || that.buf.length > 0) {
                console.log(that.complete_records.length,   that.buf.length )
                //either have not yet begun receiving of in the middle of receiving
                setTimeout(function() {
                  check()
                }, 100);
                return;
            }
            if (that.complete_records.length > 0 && that.buf.length == 0) {
                if (is_handshake){
                    finished_receiving();
                    return
                }
                //else give the server another second to send more data
                setTimeout(function() {
                    if (that.buf.length === 0) {
                        finished_receiving();
                        return;
                    } else {
                        console.log('more data received after waiting for a second');
                        check();
                    }
                }, 1000);
            }
        }
        check();

    }); 
}

//override
import_resource = async function(path){
    //change to the PageSigner's base dir first
    path = '../'+path
    return fs.readFileSync(path).toString()
}

//override
Certificate = pkijs.Certificate;
CertificateChainValidationEngine = pkijs.CertificateChainValidationEngine
use_max_fragment_length = false;

//override
createNewSession = async function(creationTime, commonName, notaryName, cleartext, pgsg, is_imported){
    var suffix = is_imported ? "_imported" : ""
    var dirname = 'session_'+ creationTime + "_" + commonName + suffix 
    fs.mkdirSync(dirname)
    fs.writeFileSync(path.join(__dirname, dirname, "cleartext"), cleartext)
    fs.writeFileSync(path.join(__dirname, dirname, commonName+'.pgsg'), Buffer.from(JSON.stringify(pgsg)))
    return dirname
}

function showUsage(){
    console.log("Usage: pgsg-node <command> [option] \r\n")
    console.log("where <command> is one of notarize, verify, awscheck\r\n")
    console.log("Examples:\r\n")
    console.log("pgsg-node notarize example.com --headers headers.txt")
    console.log("Notarize example.com using HTTP headers from headers.txt\r\n")
    console.log("pgsg-node verify imported.pgsg")
    console.log("Verify a Pagesigner session from imported.pgsg. This will create a session directory with the decrypted cleartext and the copy of the pgsg file.\r\n")
    console.log("pgsg-node awscheck")
    console.log("Check that Pagesigner's oracle server is correctly set up. This check must be performed only once on the first use of pgsg-node. There is no need to perform the check more than once because the oracle server's parameters are hardcoded. Once the check completes successfully, the hardcoded parameters can be trusted for all future invocations of pgsg-node.")
    console.log("\r\n")
    exit()
}


async function main (){

if (argv[2] === 'awscheck') {
 console.log('checking...may take up to 10 secs')
 if (await check_oracle(oracles.oracle) != true){
     console.log('verification failed')
 }
 console.log('verification successful')
 exit()
}

if (argv[2] === 'notarize') {
    if (argv.length !== 6 || (argv.length == 6 && argv[4] !== '--headers')){
        showUsage();
    }
    var server = argv[3]
    var headersfile = argv[5]
    var headers = fs.readFileSync(headersfile).toString()
    headers = headers.replace(/\n/g, '\r\n')
    await verifychain.parse_certs()
    var rv = await tlsn.start_audit(server, 443, headers)
    var dirname = await mainjs.save_session(rv)
    console.log('session saved in', dirname)
    exit()
}  

if (argv[2] === 'verify') {
    if (argv.length !== 4){
        showUsage()
    }
    var pgsgfile = argv[3]
    var pgsgBuf = fs.readFileSync(pgsgfile)
    console.log('pgsg.length', pgsgBuf.length)
    var pgsg = JSON.parse(pgsgBuf)
    await verifychain.parse_certs()
    var rv = await mainjs.verifyPgsg(pgsg)
    var server_name = rv[1]
    var cleartext = rv[0]
    var dirname = await createNewSession(getTime(), server_name, 'notary name', cleartext, pgsg, true)
    console.log('session saved in', dirname)
    exit()
}
showUsage()
}
main()