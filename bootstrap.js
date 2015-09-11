//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/bootstrap.js
var bootstrapjs_exception;
var thisaddon;
var jsloaded = false;
try {

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/AddonManager.jsm");

var self = this;
var busy = false;

function include(addon, path) {
  Services.scriptloader.loadSubScript("chrome://pagesigner/content/"+path, self);
}

function $(node, childId) {
  if (node.getElementById) {
    return node.getElementById(childId);
  } else {
    return node.querySelector("#" + childId);
  }
}


function loadNormalIcon(){
	eachWindow(unloadFromWindow);
	busy = false;
	eachWindow(loadIntoWindow);
}

function loadBusyIcon(){
	eachWindow(unloadFromWindow);
	busy = true;
	eachWindow(loadIntoWindow);
}


function loadIntoWindow(window) {
  if (!window) return;
  
  let doc = window.document;
  let toolbox = $(doc, "navigator-toolbox");
  
  if (toolbox) { // navigator window
    // add to palette
    var button = doc.createElement("toolbarbutton");
    button.setAttribute("id", BUTTON_ID);
    button.setAttribute("label", "PageSigner");
    button.setAttribute("type", "menu");
    button.setAttribute("class", "toolbarbutton-1 chromeclass-toolbar-additional");
    button.setAttribute("tooltiptext", "PageSigner menu");
    
    if (busy === true){
		button.style.listStyleImage = "url(" + "chrome://pagesigner/content/icon_spin.gif" + ")";
		toolbox.palette.appendChild(button);
		let mpu = doc.createElement("menupopup");
		let mi1 = doc.createElement("menuitem");
		mi1.setAttribute("label", 'Please wait. Signing webpage...');
		mpu.appendChild(mi1);
		button.appendChild(mpu);
	}
	else {
    button.style.listStyleImage = "url(" + "chrome://pagesigner/content/icon16.png" + ")";
    button.addEventListener("command", main.action, false);
    toolbox.palette.appendChild(button);
    
    let sep1 = doc.createElement("menuseparator");
    let sep2 = doc.createElement("menuseparator");
    let sep3 = doc.createElement("menuseparator");
    let mpu = doc.createElement("menupopup");
    mpu.setAttribute("id","tlsnmpu");
     let mi1 = doc.createElement("menuitem");
	mi1.setAttribute("label", 'Notarize this page');
	mi1.setAttribute("class","menuitem-with-favicon menuitem-iconic bookmark-item");
	mi1.setAttribute("image", 'chrome://pagesigner/content/icon16.png');
	mi1.addEventListener("command",main.notarize, false)
	mpu.appendChild(mi1);
	mpu.appendChild(sep1);
	
	 let mi3 = doc.createElement("menuitem");
	mi3.setAttribute("label", 'Manage files');
	mi3.setAttribute("class","menuitem-with-favicon menuitem-iconic bookmark-item");
	mi3.setAttribute("image", 'chrome://pagesigner/content/manage.png');
	mi3.addEventListener("command",main.manage, false)
	mpu.appendChild(mi3);
	mpu.appendChild(sep3);
	
	 let mi2 = doc.createElement("menuitem");
	mi2.setAttribute("label", 'Import .pgsg file');
	mi2.setAttribute("class","menuitem-with-favicon menuitem-iconic bookmark-item");
	mi2.setAttribute("image", 'chrome://pagesigner/content/verify.png');
	mi2.addEventListener("command",main.verify, false)
	mpu.appendChild(mi2);
	mpu.appendChild(sep2);
	
	let mi4 = doc.createElement("menuitem");
	mi4.setAttribute("label", 'About');
	mi4.setAttribute("class","menuitem-with-favicon menuitem-iconic bookmark-item");
	mi4.setAttribute("image",'chrome://pagesigner/content/icon16.png');
	mi4.addEventListener("command",main.about, false)
	mpu.appendChild(mi4);
	button.appendChild(mpu);
	}
    
    
    // move to saved toolbar position
    let {toolbarId, nextItemId} = main.getPrefs(),
        toolbar = toolbarId && $(doc, toolbarId);
    if (toolbar) {
      let nextItem = $(doc, nextItemId);
      toolbar.insertItem(BUTTON_ID, nextItem &&
                         nextItem.parentNode.id == toolbarId &&
                         nextItem);
    }
    window.addEventListener("aftercustomization", afterCustomize, false);
  }
}

function afterCustomize(e) {
  let toolbox = e.target;
  let button = $(toolbox.parentNode, BUTTON_ID);
  let toolbarId, nextItemId;
  if (button) {
    let parent = button.parentNode,
    nextItem = button.nextSibling;
    if (parent) {
      toolbarId = parent.id;
      nextItemId = nextItem && nextItem.id;
    }
  }
  main.setPrefs(toolbarId, nextItemId);
}

function unloadFromWindow(window) {
  if (!window) return;
  let doc = window.document;
  let button = $(doc, BUTTON_ID) ||
    $($(doc, "navigator-toolbox").palette, BUTTON_ID);
  button && button.parentNode.removeChild(button);
  window.removeEventListener("aftercustomization", afterCustomize, false);
}

function eachWindow(callback) {
  let enumerator = Services.wm.getEnumerator("navigator:browser");
  while (enumerator.hasMoreElements()) {
	if (!jsloaded){
		loadjs();
	}
    let win = enumerator.getNext();
    if (win.document.readyState === "complete") {
      callback(win);
    } else {
      runOnLoad(win, callback);
    }
  }
}

function runOnLoad (window, callback) {
  window.addEventListener("load", function() {
	if (!jsloaded){
		loadjs();
	}
    window.removeEventListener("load", arguments.callee, false);
    callback(window);
  }, false);
}

function windowWatcher (subject, topic) {
  if (topic === "domwindowopened") {
    runOnLoad(subject, loadIntoWindow);
  }
}

function startup(data, reason) AddonManager.getAddonByID(data.id, function(addon) {
  thisaddon = addon;
  // existing windows
  eachWindow(loadIntoWindow);
  // new windows
  Services.ww.registerNotification(windowWatcher);
});

//we want to load js files only after browser started, so we wait for a window object
//to be exposed first and then loadjs get triggered
function loadjs(){
  jsloaded = true;
  var addon = thisaddon;
  include(addon, "socket.js");
  include(addon, "firefox/button.js");
  include(addon, "tlsn_utils.js");
  include(addon, "oracles.js");
  include(addon, "CryptoJS/components/core.js");
  include(addon, "CryptoJS/components/md5.js");
  include(addon, "CryptoJS/components/evpkdf.js");
  include(addon, "CryptoJS/components/enc-base64.js");
  include(addon, "CryptoJS/components/sha1.js");
  include(addon, "CryptoJS/components/sha256.js");
  include(addon, "CryptoJS/components/hmac.js");
  include(addon, "CryptoJS/components/cipher-core.js");
  include(addon, "CryptoJS/components/aes.js");
  include(addon, "CryptoJS/components/pad-nopadding.js");
  include(addon, "firefox/firefox_specific.js");
  include(addon, "main.js");
  include(addon, "jsbn.js");
  include(addon, "jsbn2.js");
  include(addon, "pako.js");
  include(addon, "tlsn.js");
  include(addon, "notification_bar.js");
  include(addon, "testing/testing.js");
  include(addon, "testing/manager_test.js");
  include(addon, "verifychain/buffer.js2");
  include(addon, "verifychain/asn1.js2");
  include(addon, "verifychain/jsrsasign-latest-all-min.js2");
  include(addon, "verifychain/rootcertslist.js");
  include(addon, "verifychain/rootcerts.js");
  include(addon, "verifychain/verifychain.js");
  include(addon, "testdriver.js");
}


function shutdown(data, reason) {
  gBrowser.removeProgressListener(myListener);
  Services.obs.removeObserver(httpRequestBlocker, "http-on-modify-request");
  Services.ww.unregisterNotification(windowWatcher);
  eachWindow(unloadFromWindow);
}
function install(data,reason) {}
function uninstall(data,reason) {}

} catch (e){
	bootstrapjs_exception = e;
}
