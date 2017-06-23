var received_once = false; // only receive the data to be displayed once
//otherwise we will intercept the data meant for another viewer's tab

//only load when html is displayed
function loadViewerTest() {
  chrome.storage.local.get('testing', function(obj) {
    if (obj.testing == true) {
      var script = document.createElement('script');
      script.src = 'testing/viewer_test.js';
      document.body.appendChild(script);
    }
  });
}

var message;

chrome.runtime.onMessage.addListener(function(msg) {
  message = msg;
  if (msg.destination !== 'viewer') return;
  if (received_once) return;
  received_once = true;
  
  //console.log('got data in viewer', msg.data.slice(0, 100));
  var hideButton = false;
  if (['html', 'json', 'xml'].indexOf(msg.type) > -1) {
    document.getElementsByTagName('html')[0].innerHTML = decode_str(ba2str(msg.data));
  } else if (msg.type == 'raw') {
    hideButton = true;
    document.getElementsByTagName('plaintext')[0].innerHTML = decode_str(msg.data);
    document.getElementById('text').removeAttribute('hidden');
    document.title = 'PageSigner raw viewer';
  } else if (['pdf', 'zip'].indexOf(msg.type) > -1) {
    document.getElementById('type').textContent = msg.type;
    document.getElementById('view file button').onclick = function() {view_file(msg.data)};
    document.getElementById('view file').removeAttribute('hidden');
  }  
  install_bar(msg.sessionId, msg.serverName, hideButton);
  if (msg.type == 'html') {
    loadViewerTest();
  }
});

function view_file(data){
    console.log('view file button clicked');
    //get the Blob and create an invisible download link
    var ab = ba2ab(data);
    var exportedBlob = new Blob([ab]);
    var exportedBlobUrl = URL.createObjectURL(exportedBlob, {
      type: 'application/octet-stream'
    });
    var fauxLink = document.createElement('a');
    fauxLink.href = exportedBlobUrl;
    fauxLink.setAttribute('download', message.serverName + '.' + message.type);
    document.body.appendChild(fauxLink);
    fauxLink.click();
}

  
function decode_str(str){
  var utf_string;
  try {
  return decodeURIComponent(escape(str));
  }
  catch (err){
    //not a utf-encoded string
    return str;
  }
}

function ba2ab(ba) {
  var ab = new ArrayBuffer(ba.length);
  var dv = new DataView(ab);
  for (var i = 0; i < ba.length; i++) {
    dv.setUint8(i, ba[i]);
  }
  return ab;
};

function str2ba(str) {
  if (typeof(str) !== "string") {
    throw ("Only type string is allowed in str2ba");
  }
  ba = [];
  for (var i = 0; i < str.length; i++) {
    ba.push(str.charCodeAt(i));
  }
  return ba;
}

function ba2str(ba) {
  if (typeof(ba) !== "object") {
    throw ("Only type object is allowed in ba2str");
  }
  var result = "";
  for (var i = 0; i < ba.length; i++) {
    result += String.fromCharCode(ba[i]);
  }
  return result;
}
