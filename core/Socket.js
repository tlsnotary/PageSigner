// The only way to determine if the server is done sending data is to check that out receiving
// buffer has nothing but complete TLS records i.e. that there is no incomplete TLS records
// However it was observed that in cases when getting e.g. zip files, some servers first send HTTP header as one
// TLS record followed by the body as another record(s)
// That's why after receiving a complete TLS record we wait to get some more data
// This extra waiting must not be done for the handshake messages to avoid adding latency and having the handshake
// dropped by the server
// We do not communicate directly with the server but we send messages to the helper app
// It is the helper app which opens a TCP socket and sends/receives data

import {global} from './globals.js';
import {ba2str, b64decode, concatTA, b64encode, str2ba, ba2int} from './utils.js';

export class Socket {
  constructor(name, port){
    this.name = name;
    this.port = port;
    this.uid = Math.random().toString(36).slice(-10);

    this.buffer = new Uint8Array();
    // connect will throw if we couldnt establish a connection to the server for this long
    this.connectTimeout = 5 * 1000;
    // recv() will reject if no data was seen for this long
    this.noDataTimeout = 5 * 1000; 
    // close the socket after this time, even if it is in the middle of receiving data
    this.lifeTime = 40 * 1000; 
    // delay after which we make a final check of the receicing buffer and if there was no data,
    // from the server, the we consider the data transmission finished
    this.delayBeforeFinalIteration = 500;  
    this.wasClosed = false;
    this.backendPort = 20022;
  }

  async connect() {
    const that = this;
    let timer;
    const response = await new Promise(async function(resolve, reject) {
      // dont wait for connect for too long
      timer = setTimeout(function() {
        reject('Unable to connect to the webserver. Please check your internet connection.');
        return;
      }, that.connectTimeout);

      const msg = {'command': 'connect','args': {'name': that.name,'port': that.port},'uid': that.uid};
      if (global.usePythonBackend){
        const url = 'http://127.0.0.1:' + that.backendPort;
        const payload = JSON.stringify(msg);
        try{
          var req = await fetch (url, {method:'POST', body: str2ba(payload).buffer, cache: 'no-store'});
        }
        catch (error) {
          reject('connection error');
          return;
        }
        const text = new Uint8Array (await req.arrayBuffer());
        const response = ba2str(text);
        resolve(JSON.parse(response));
        return;
      }
      else {
        chrome.runtime.sendMessage(global.appId, msg, function(response) {resolve(response);});
      }
    })
      .catch(function(e){
        throw(e);
      });

    // we need to access runtime.lastError to prevent Chrome from complaining
    // about unchecked error 
    chrome.runtime.lastError;
    clearTimeout(timer);
    if (response == undefined){
      throw (undefined);
    }
    if (response.retval != 'success') {
      // throw(response.retval)
    }
    // else if (response.retval == 'success') {
    setTimeout(function() {
      if (! that.wasClosed)
        that.close();
    }, that.lifeTime);
    // endless data fetching loop for the lifetime of this Socket
    that.fetchLoop();
    return 'ready'; 
  }

  async send(data_in) {
    var msg = {'command': 'send', 'args': {'data': Array.from(data_in)}, 'uid': this.uid};
    if (global.usePythonBackend){
      msg.args.data = Array.from(b64encode(msg.args.data));
      await fetch('http://127.0.0.1:20022', {method:'POST', body: JSON.stringify(msg),
        cache: 'no-store'});
    }
    else{
      chrome.runtime.sendMessage(global.appId, msg);
    }
  }

  // poll the backend for more data
  async fetchLoop() {
    if (this.wasClosed) {
      return;
    }
    var that = this;
    var response = await new Promise(async function(resolve){
      var msg = {'command': 'recv', 'uid': that.uid};
      if (global.usePythonBackend){
        var req = await fetch('http://127.0.0.1:20022', {method:'POST', body: JSON.stringify(msg),
          cache: 'no-store'});
        var text = new Uint8Array(await req.arrayBuffer());
        var response = JSON.parse(ba2str(text));
        if (response.data.length > 0){
          response.data = Array.from(b64decode(response.data));
        }
        resolve(response);
      }
      else {
        chrome.runtime.sendMessage(global.appId, msg, function(response) {resolve(response);});
      }
    });
    if (response.data.length > 0){
      console.log('fetched some data', response.data.length, that.uid);
      that.buffer = concatTA(that.buffer, new Uint8Array(response.data));
    }
    setTimeout(function() {
      that.fetchLoop();
    }, 100);
  }
 
  // fetchLoop has built up the recv buffer
  // check if there are complete records in the buffer,return them if yes or wait some more if no
  recv (is_handshake) {
    if (is_handshake == undefined) {
      is_handshake = false;
    }
    var that = this;
    return new Promise(function(resolve, reject) {
      var dataLastSeen = new Date().getTime();
      var complete_records = new Uint8Array();
      var buf = new Uint8Array();
      var resolved = false;
      var lastIteration = false;

      function finished_receiving() {
        console.log('recv promise resolving', that.uid);
        resolved = true;
        resolve(complete_records);
      }

      var check = function() {
        var now = new Date().getTime();
        if ((now - dataLastSeen) > that.noDataTimeout){
          reject('recv: no data timeout');
          return;
        }
        // console.log('check()ing for more data', uid);
        if (resolved) {
          console.log('returning because resolved');
          return;
        }
        if (that.buffer.length === 0) {
          if (lastIteration){
            finished_receiving();
            return;
          }
          setTimeout(function() {check();}, 100);
          return;
        }
        // else got new data
        if (lastIteration){
          console.log('more data received on last iteration', that.uid);
          lastIteration = false;
        }
        console.log('new data in check', that.buffer.length);
        dataLastSeen = now;
        buf = concatTA(buf, that.buffer);
        that.buffer = new Uint8Array();
        const rv = that.check_complete_records(buf);
        complete_records = concatTA(complete_records, rv.comprecs);
        if (!rv.is_complete) {
          console.log('check_complete_records failed', that.uid);
          buf = rv.incomprecs;
          setTimeout(function() {check();}, 100);
          return;
        } 
        else {
          console.log('got complete records', that.uid);
          if (is_handshake) {
            finished_receiving();
            return;
          }
          else {
            console.log('in recv waiting for an extra second', that.uid);
            buf = new Uint8Array();
            // give the server another second to send more data
            lastIteration = true;
            setTimeout(function() {check();}, that.delayBeforeFinalIteration);
          }
        }
      };
      check();
    })
      .catch(function(error){
        throw(error);
      });
  }

  async close() {
    this.wasClosed = true;
    var msg = {'command': 'close','uid': this.uid};
    console.log('closing socket', this.uid);
    if (global.usePythonBackend){
      await fetch('http://127.0.0.1:20022', {method:'POST', body: JSON.stringify(msg),
        cache: 'no-store'});
    }
    else {
      chrome.runtime.sendMessage(global.appId, msg);
    }
  }

  check_complete_records(d) {
    /* '''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
    */
    let complete_records = new Uint8Array();

    while (d) {
      if (d.length < 5) {
        return {
          'is_complete': false,
          'comprecs': complete_records,
          'incomprecs': d
        };
      }
      var l = ba2int(d.slice(3, 5));
      if (d.length < (l + 5)) {
        return {
          'is_complete': false,
          'comprecs': complete_records,
          'incomprecs': d
        };
      } else if (d.length === (l + 5)) {
        return {
          'is_complete': true,
          'comprecs': concatTA(complete_records, d)
        };
      } else {
        complete_records = concatTA(complete_records, d.slice(0, l + 5));
        d = d.slice(l + 5);
        continue;
      }
    }
  }
}


if (typeof module !== 'undefined'){ // we are in node.js environment
  module.exports={
  };
}