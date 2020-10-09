//The only way to determine if the server is done sending data is to check that the receiving
//buffer has nothing but complete TLS records i.e. that there is no incomplete TLS records
//However it was observed that in cases when getting e.g. zip files, some servers first send HTTP header as one
//TLS record followed by the body as another record(s)
//That's why after receiving a complete TLS record we wait to get some more data
//This extra waiting must not be done for the handshake messages to avoid adding latency and having the handshake
//dropped by the server
function AbstractSocket() {};
AbstractSocket.prototype.recv = function(is_handshake) {
  if (typeof(is_handshake) === 'undefined') {
    is_handshake = false;
  }
  var that = this;
  return new Promise(function(resolve, reject) {
    var startTime = new Date().getTime();
    var complete_records = [];
    var buf = [];
    var resolved = false;

    var timer = setTimeout(function() {
      resolved = true;
      reject('recv: socket timed out');
    }, that.recv_timeout);

    var check = function() {
      //console.log('check()ing for more data', uid);
      if (resolved) {
        console.log('returning because resolved');
        return;
      }
      if (that.buffer.length === 0) {
        setTimeout(function() {
          check()
        }, 100);
        return;
      }
      console.log('new data in check', that.buffer.length);
      //else got new data
      buf = [].concat(buf, that.buffer);
      that.buffer = [];
      var rv = check_complete_records(buf);
      complete_records = [].concat(complete_records, rv.comprecs);
      if (!rv.is_complete) {
        console.log("check_complete_records failed", that.uid);
        buf = rv.incomprecs;
        setTimeout(function() {
          check()
        }, 100);
        return;
      } else {
        function finished_receiving() {
          clearTimeout(timer);
          console.log('recv promise resolving', that.uid);
          resolved = true;
          resolve(complete_records);
        };

        console.log("got complete records", that.uid);
        if (is_handshake) {
          finished_receiving();
          return;
        } else {
          console.log("in recv waiting for an extra second", that.uid);
          buf = [];
          //give the server another second to send more data
          setTimeout(function() {
            if (that.buffer.length === 0) {
              finished_receiving();
              return;
            } else {
              console.log('more data received after waiting for a second', that.uid);
              check();
            }
          }, 1000);
        }
      }
    };
    check();
  });
};


//We do not communicate directly with the server but we send messages to the helper app
//It is the helper app which opens the raw sockets and sends/receives data
function Socket(name, port) {
  this.name = name;
  this.port = port;
  this.uid = Math.random().toString(36).slice(-10);
  this.buffer = [];
  this.recv_timeout = 20 * 1000;
}
//inherit the base class
Socket.prototype = Object.create(AbstractSocket.prototype);
Socket.prototype.constructor = Socket;

Socket.prototype.connect = function() {
  var that = this;
  return new Promise(function(resolve, reject) {
    chrome.runtime.sendMessage(appId, {
        'command': 'connect',
        'args': {
          'name': that.name,
          'port': that.port
        },
        'uid': that.uid
      },
      function(response) {
        //we need to access runtime.lastError to prevent Chrome from complaining
        //about unchecked error 
        chrome.runtime.lastError
        clearInterval(timer);
        if (response === undefined){
          reject(undefined);
          return;
        }
        if (response.retval === 'success') {
          //endless data fetching loop for the lifetime of this Socket
          var fetch = function() {
            chrome.runtime.sendMessage(appId, {
              'command': 'recv',
              'uid': that.uid
            }, function(response) {
              console.log('fetched some data', response.data.length, that.uid);
              that.buffer = [].concat(that.buffer, response.data);
              setTimeout(function() {
                fetch()
              }, 100);
            });
          };
          //only needed for Chrome
          fetch();
          resolve('ready');
        }
        reject(response.retval);
      });
    //dont wait for connect for too long
    var timer = setTimeout(function() {
      reject('connect: socket timed out');
    }, 1000 * 20);
  });
};
Socket.prototype.send = function(data_in) {
  chrome.runtime.sendMessage(appId, {
    'command': 'send',
    'args': {
      'data': data_in
    },
    'uid': this.uid
  });
};
Socket.prototype.close = function() {
  console.log('closing socket', this.uid);
  chrome.runtime.sendMessage(appId, {
    'command': 'close',
    'uid': this.uid
  });
};


function check_complete_records(d) {
  /*'''Given a response d from a server,
  we want to know if its contents represents
  a complete set of records, however many.'''
  */
  var complete_records = [];

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
        'comprecs': [].concat(complete_records, d)
      };
    } else {
      complete_records = [].concat(complete_records, d.slice(0, l + 5));
      d = d.slice(l + 5);
      continue;
    }
  }
}

if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    check_complete_records
  }
}