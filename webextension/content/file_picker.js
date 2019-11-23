//Because file picker doesn't work from popup.html we open a new tab just for this purpose
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
var is_file_picker = false; //toggled to true when invoked as a file picker

function prepare_testing(){
  var script = document.createElement('script');
  script.src = 'testing/file_picker_test.js';
  document.body.appendChild(script);
}


//triggered by exrension
function showFilePicker(){
  is_file_picker = true
  var label = document.getElementById("import_label");
  label.style.display = "";

  var fileChooser = document.getElementById("import");
  fileChooser.addEventListener('change', function(evt) {
    var f = evt.target.files[0];
    if (f) {
      var reader = new FileReader();
      reader.onload = onload;
      reader.readAsArrayBuffer(f);
    }
  });
}





function onload(e) {
  var loader = document.getElementById("loader");
  loader.classList.toggle("m-fadeIn");
  loader.removeAttribute('hidden');
  var import_label = document.getElementById("import_label");
  //import_label.style.display = 'none'
  import_label.classList.toggle("m-fadeOut");


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
  //don't close the window, we reuse it to display html
  //window.close();
}

