//Because file picker doesn't work from popup.html we open a new tab just for this purpose
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;

chrome.storage.local.get('testing', function(obj) {
  if (obj.testing == true) {
    var script = document.createElement('script');
    script.src = 'testing/file_picker_test.js';
    document.body.appendChild(script);
  }
});

var fileChooser = document.getElementById("import");

function onload(e) {
  var contents = e.target.result;
  var view = new DataView(contents);
  var int_array = [];
  for (var i = 0; i < view.byteLength; i++) {
    int_array.push(view.getUint8(i));
  }
  console.log('will send array now');
  if (!is_chrome) {
    var port = chrome.runtime.connect({
      name: "filepicker-to-extension"
    });
    port.postMessage({
      'destination': 'extension',
      'message': 'import',
      'args': {
        'data': int_array
      }
    });
  } else {
    chrome.runtime.sendMessage({
      'destination': 'extension',
      'message': 'import',
      'args': {
        'data': int_array
      }
    });
  }
  window.close();
}

fileChooser.addEventListener('change', function(evt) {
  var f = evt.target.files[0];
  if (f) {
    var reader = new FileReader();
    reader.onload = onload;
    reader.readAsArrayBuffer(f);
  }
});
