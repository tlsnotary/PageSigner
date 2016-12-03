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
      reject('recv: socket timed out');
      resolved = true;
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


function check_complete_records(d) {
  /*'''Given a response d from a server,
  we want to know if its contents represents
  a complete set of records, however many.'''
  */
  var complete_records = [];
  var incomplete_records = [];

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
