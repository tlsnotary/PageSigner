//from https://raw.githubusercontent.com/dgutov/bmreplace/67ad019be480fc6b5d458dc886a2fb5364e92171/bootstrap.js
var bootstrapjs_exception;
var thisaddon;
var jsloaded = false;
try {

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/AddonManager.jsm");

var self = this, icon;

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

var button;
var menupopup;
function loadIntoWindow(window) {
  if (!window) return;
  
  let doc = window.document;
  let toolbox = $(doc, "navigator-toolbox");
  
  if (toolbox) { // navigator window
    // add to palette
    button = doc.createElement("toolbarbutton");
    button.setAttribute("id", BUTTON_ID);
    button.setAttribute("label", "PageSigner");
    button.setAttribute("type", "menu");
    button.setAttribute("class", "toolbarbutton-1 chromeclass-toolbar-additional");
    button.setAttribute("tooltiptext", "PageSigner menu");
    button.style.listStyleImage = "url(" + icon + ")";
    button.addEventListener("command", main.action, false);
    toolbox.palette.appendChild(button);
    
    let sep1 = doc.createElement("menuseparator");
    let sep2 = doc.createElement("menuseparator");
    let mpu = doc.createElement("menupopup");
    mpu.setAttribute("id","tlsnmpu");
     let mi1 = doc.createElement("menuitem");
	mi1.setAttribute("label", 'Notarize this page');
	mi1.setAttribute("class","menuitem-with-favicon");
	mi1.setAttribute("image", 'chrome://pagesigner/content/icon.png');
	mi1.addEventListener("command",main.notarize, false)
	mpu.appendChild(mi1);
	mpu.appendChild(sep1);
	 let mi2 = doc.createElement("menuitem");
	mi2.setAttribute("label", 'Verify tlsn file');
	mi2.setAttribute("class","menuitem-with-favicon");
	mi2.setAttribute("image", 'chrome://pagesigner/content/verify.png');
	mi2.addEventListener("command",main.verify, false)
	mpu.appendChild(mi2);
	mpu.appendChild(sep2);
	 let mi3 = doc.createElement("menuitem");
	mi3.setAttribute("label", 'Manage files');
	mi3.setAttribute("class","menuitem-with-favicon");
	mi3.setAttribute("image", 'chrome://pagesigner/content/manage.png');
	mi3.addEventListener("command",main.manage, false)
	mpu.appendChild(mi3);
    
	button.appendChild(mpu);
    
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
  //icon = addon.getResourceURI("icon.png").spec;
  icon = "chrome://pagesigner/content/icon.png";
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
  include(addon, "button.js");
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
  include(addon, "main.js");
  include(addon, "jsbn.js");
  include(addon, "jsbn2.js");
  include(addon, "pako.js");
  include(addon, "tlsn.js");
  include(addon, "testdriver.js");
}


function shutdown(data, reason) {
  Services.ww.unregisterNotification(windowWatcher);
  eachWindow(unloadFromWindow);
}
function install(data,reason) {}
function uninstall(data,reason) {}

} catch (e){
	bootstrapjs_exception = e;
}
