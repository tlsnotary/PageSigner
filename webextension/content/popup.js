//in FF53 in popup.js I tried
//chrome.runtime.sendMessage - it gave me Dead Object
//also tried browser.tabs.sendMessage() - it reprodicibly crashed FF while debugging
//so as a temporary kludge I use ports for communication
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
var port;

function getPref(pref) {
  return new Promise(function(resolve, reject) {
    chrome.storage.local.get(pref, function(obj) {
      if (Object.keys(obj).length === 0) {
        resolve('undefined');
        return;
      } else {
        resolve(obj[pref]);
      }
    });
  });
}

getPref('verbose')
  .then(function(value) {
	if (value !== true && !is_chrome) {
    //Firefox pollutes browser window, disable logging
    console.log = function(){};
  }
});

if (!is_chrome) {
  port = chrome.runtime.connect({
    name: "popup-to-extension"
  });
  port.onMessage.addListener(function(message) {
    console.log("Message from legacy add-on: ", message);
    process_message(message);
  });
}
sendMessage({
  'destination': 'extension',
  'message': 'popup active'
});


function process_message(data) {
  if (data.destination !== 'popup') return;
  if (data.message === 'app_not_installed') {
    document.getElementById("app_not_installed").removeAttribute('hidden');
  } else if (data.message === 'app_disabled') {
    document.getElementById("app_disabled").removeAttribute('hidden');
  } else if (data.message === 'show_menu') {
    document.getElementById("menu").removeAttribute('hidden');
  } else if (data.message === 'notarization_in_progress') {
    document.getElementById("notarization_in_progress").removeAttribute('hidden');
  } else if (data.message === 'waiting_for_click') {
    document.getElementById("waiting_for_click").removeAttribute('hidden');
  } else if (data.message === 'popup error') {
    console.log('got popup error with', data);
    var error_text = document.getElementById("popup_error")
    error_text.removeAttribute('hidden');
    error_text.textContent = data.data.text;
  } else {
    console.log('popup received unexpected message ' + data.message);
  }
}

function sendMessage(msg) {
  if (is_chrome) {
    chrome.runtime.sendMessage(msg);
  } else {
    port.postMessage(msg);
  }
}


chrome.runtime.onMessage.addListener(function(data) {
  process_message(data);
});


document.getElementById("notarize").addEventListener("click",
  function() {
    window.close();
    sendMessage({
      'destination': 'extension',
      'message': 'notarize'
    });
  });

document.getElementById("notarizeAfter").addEventListener("click",
  function() {
    window.close();
    sendMessage({
      'destination': 'extension',
      'message': 'notarizeAfter'
    });
  });

document.getElementById("manage").addEventListener("click",
  function() {
    window.close();
    sendMessage({
      'destination': 'extension',
      'message': 'manage'
    });
  });

document.getElementById("import").addEventListener("click",
  function() {
    window.close();
    sendMessage({
      destination: 'extension',
      message: 'file picker'
    });
  });

document.getElementById("donate_link").addEventListener("click",
  function() {
    window.close();
    sendMessage({
      destination: 'extension',
      message: 'donate link'
    });
  });

document.getElementById("about").addEventListener("click",
  function() {
    var prefix = is_chrome ? 'webextension/' : '';
    var url = chrome.extension.getURL(prefix + 'content/about.html');
    document.getElementById("menu").hidden = true;
    document.getElementById("aboutWindow").hidden = false;
  });



var app_not_installed = document.getElementById("app_not_installed");
app_not_installed.addEventListener("click", function(evt) {
  chrome.runtime.sendMessage({
    'destination': 'extension',
    'message': 'openInstallLink'
  });
  window.close();
});

var app_disabled = document.getElementById("app_disabled");
app_disabled.addEventListener("click", function(evt) {
  chrome.runtime.sendMessage({
    'destination': 'extension',
    'message': 'openChromeExtensions'
  });
  window.close();
});



setTimeout(function() {
  chrome.storage.local.get('testing', function(obj) {
    if (obj.testing == true) {
      document.getElementById('manage').click();
    }
  });
}, 100);
