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


chrome.runtime.onMessage.addListener(function(msg) {
  if (msg.destination !== 'viewer') return;
  if (received_once) return;
  received_once = true;
  //console.log('got data in viewer', msg.data.slice(0, 100));
  var utf_string = decodeURIComponent(escape(msg.data));
  var hideButton = null;
  if (msg.type == 'html') {
    hideButton = false;
    document.getElementsByTagName('html')[0].innerHTML = utf_string;
  } else if (msg.type == 'raw') {
    hideButton = true;
    document.getElementsByTagName('plaintext')[0].innerHTML = utf_string;
    document.getElementById('text').removeAttribute('hidden');
    document.title = 'PageSigner raw viewer';
  }
  install_bar(msg.sessionId, msg.serverName, hideButton);
  if (msg.type == 'html') {
    loadViewerTest();
  }
});
