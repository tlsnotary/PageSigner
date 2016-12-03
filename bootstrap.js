//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/bootstrap.js
var bootstrapjs_exception;
var api = null;
var window = null;
var setTimeout;
var clearTimeout;
var clearInterval;
var setInterval;
var connections = {}; //uid:{buffer:, socketId:} dictionary
console.log = function(){};


//js native ArrayBuffer to Array of numbers
function ab2ba(ab) {
  var view = new DataView(ab);
  var int_array = [];
  for (var i = 0; i < view.byteLength; i++) {
    int_array.push(view.getUint8(i));
  }
  return int_array;
}


function ba2ab(ba) {
  var ab = new ArrayBuffer(ba.length);
  var dv = new DataView(ab);
  for (var i = 0; i < ba.length; i++) {
    dv.setUint8(i, ba[i]);
  }
  return ab;
}


function Socket(name, port) {
  this.name = name;
  this.port = port;
  this.sckt = null;
  this.buffer = [];
  this.uid = Math.random().toString(36).slice(-10);
  this.recv_timeout = 20 * 1000;
}

Socket.prototype.constructor = Socket;

Socket.prototype.connect = function() {
  var that = this;
  return new Promise(function(resolve, reject) {
    that.sckt = new window.TCPSocket(that.name, that.port, {
      binaryType: "arraybuffer"
    });
    that.sckt.ondata = function(event) {
      var int_array = ab2ba(event.data)
      console.log('ondata got bytes:', int_array.length);
      that.buffer = [].concat(that.buffer, int_array);
    };
    //dont wait for connect for too long
    var timer = setTimeout(function() {
      reject('connect: socket timed out');
    }, 1000 * 20)

    that.sckt.onopen = function() {
      clearInterval(timer);
      console.log('onopen');
      resolve('ready');
    };
    that.sckt.onerror = function(event) {
      clearInterval(timer);
      console.log('onerror', event);
      reject(event.data);
    };
  });
};
Socket.prototype.send = function(data_in) {
  var ab = ba2ab(data_in);
  console.log('socket putting data on the wire');
  this.sckt.send(ab, 0, ab.byteLength);
};
Socket.prototype.close = function() {
  this.sckt.close();
};

var first_listener_connect = true;

function listener(request, sender, sendResponse) {
  console.log('got data in listener in bootstrap');
  if (first_listener_connect) {
    first_listener_connect = false;
    var {
      classes: Cc,
      interfaces: Ci,
      utils: Cu
    } = Components;
    var win = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator).getMostRecentWindow('navigator:browser');
    window = win.window;
    setTimeout = window.setTimeout;
    setInterval = window.setInterval;
    clearTimeout = window.clearTimeout;
    clearInterval = window.clearInterval;
  }
  if (request.command === 'connect') {
    connections[request.uid] = {
      socket: {}
    };
    var socket = new Socket(request.args.name, request.args.port);
    connections[request.uid].socket = socket;
    socket.connect().then(function() {
      console.log('retval of connect');
      sendResponse({
        'retval': 'success'
      });
    });
    return true; //for async sendResponse
  } else if (request.command === 'send') {
    connections[request.uid].socket.send(request.args.data);
  } else if (request.command === 'close') {
    connections[request.uid].socket.close();
  } else if (request.command === 'recv') {
    //only send back when there is actual data to send
    //request will become a dead Object after some time, so we copy it's uid while it is not yet dead
    var uid = request.uid;
    var timer = setInterval(function() {
      if (connections[uid].socket.buffer.length > 0) {
        clearInterval(timer);
        var buffer = connections[uid].socket.buffer;
        connections[request.uid].socket.buffer = [];
        console.log('sending back', buffer);
        sendResponse({
          'data': buffer
        });
      }
    }, 100);
    setTimeout(function() {
      clearInterval(timer);
    }, 60 * 1000);
    return true; //for async sendResponse
  }
}


function startup({
  webExtension
}) {
  console.log('getting webextension');
  webExtension.startup().then(apis => {
    api = apis;
    api.browser.runtime.onMessage.addListener(listener);
  });
  console.log('got webextension');
}

function shutdown(data, reason) {}

function install(data, reason) {}

function uninstall(data, reason) {}
