//Because file picker doesn't work from popup.html we open a new tab just for this purpose

var fileChooser = document.getElementById("import");

fileChooser.addEventListener('change', function (evt) {
  var f = evt.target.files[0];
  if(f) {
    var reader = new FileReader();
    reader.onload = function(e) {
      var contents = e.target.result;
      var view = new DataView(contents);
		var int_array = [];
		for(var i=0; i < view.byteLength; i++){
			int_array.push(view.getUint8(i));
		}
      chrome.runtime.sendMessage({'destination':'extension',
									'message':'import',
									'args':{'data':int_array}});
    }
    reader.readAsArrayBuffer(f);
  }
});
