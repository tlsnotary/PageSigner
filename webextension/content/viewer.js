var received_once = false; // only receive the data to be displayed once
//otherwise we will intercept the data meant for another viewer's tab
var tabid = null; //allow the extension to put the id of the tab which opened this page

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

function getType (data_with_headers){
  var headers = data_with_headers.split('\r\n\r\n')[0]
  var header_lines = headers.split('\r\n');
  for (let line of header_lines) {
    if (line.search(/content-type:\s*/i) < 0) continue;
    if (line.match('application/pdf')){
      return 'pdf';
    } 
    else if (line.match('image/jpeg')){
      return 'jpg';
    } 
  return 'html'
  }
}


function changeColor(){
  var div = document.getElementById(this.id) 
  if (div.classList.contains('div-toggled')){
    div.classList.remove('div-toggled')
  }
  else {
    div.classList.add('div-toggled')
  }
}


function main(){
  chrome.runtime.onMessage.addListener(function(msg) {
    if (msg.destination !== 'viewer') return;
    if (received_once) return;
    //in case this was a file picker, toggle it back so that this window doesnt get reused
    //as a future file picker
    is_file_picker = false; 
    message = msg;
    received_once = true;
    
    console.log('got data in viewer', msg.data);
    let type;
    if (msg.type == 'raw') type = 'raw'
    else{
      type = getType(msg.data)
    }
    var hideButton = false;
    if (['html', 'json', 'xml', 'txt'].indexOf(type) > -1) {
      var rv = msg.data.split('\r\n\r\n')
      var data = rv.splice(1).join('\r\n\r\n');
      console.log('will document.write(decode_str(data))')
      //add CSP to prevent loading any resources from the page
      var csp = "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; img-src data:\"></meta>\r\n"
      document.write(csp + decode_str(data))
    } else if (type == 'raw') {
      hideButton = true;
      var data = decode_str(msg.data)
      document.getElementsByTagName('plaintext')[0].innerHTML = data;
      // var div = document.createElement('div')
      // for (var i=0; i<1000; i++){
      //     var div = document.createElement('div')
      //     div.innerText = data.slice(16*i, 16*i+16) 
      //     div.className = 'div-1'
      //     div.id = 'div'+ i.toString()
      //     div.setAttribute('seqnum', i)
      //     document.body.append(div)    
      //     div.onclick = changeColor;
      // }
    
      document.getElementById('text').removeAttribute('hidden');
      document.title = 'PageSigner raw viewer';
    } else { 
      //a file which has to be downloaded like e.g. PDF
      //remove the HTTP headers from the data
      var rv = msg.data.split('\r\n\r\n')
      var data = str2ba(rv.splice(1).join('\r\n\r\n'));
      document.getElementById('type').textContent = type;
      document.getElementById('view file button').onclick = function() {
      view_file(data, message.serverName + '.' + type)};
      document.getElementById('view file').removeAttribute('hidden');
    }  
    install_bar(msg.sessionId, msg.serverName, hideButton);
    if (msg.type == 'html') {
      loadViewerTest();
    }
  });
}

main();

function view_file(data, filename){
    console.log('view file button clicked');
    //get the Blob and create an invisible download link
    var ab = ba2ab(data);
    var exportedBlob = new Blob([ab]);
    var exportedBlobUrl = URL.createObjectURL(exportedBlob, {
      type: 'application/octet-stream'
    });
    var fauxLink = document.createElement('a');
    fauxLink.href = exportedBlobUrl;
    fauxLink.setAttribute('download', filename);
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
