const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
var testing = false;

var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch("");
prefs.setBoolPref("browser.tabs.warnOnCloseOtherTabs", false);	

var wslist = [];

function startTesting(){
	//var wslist_path = thisaddon.getResourceURI("content/websitelist.txt").path;
	return OS.File.read('/tmp/websitelist.txt', { encoding: "utf-8" }).then(
	  function onSuccess(text) {
		wslist = text.split('\n');        // text is a string
		openNextLink();
	  }
	);
}

function openNextLink(){
	while(true){
		var wslist_index = (Math.random() * wslist.length) << 0;
		if (!  (wslist[wslist_index].startsWith('#') ||
				wslist[wslist_index] === '')){
			break;
		}
	}
	var url = wslist[wslist_index];
	console.log('test: opening new tab', url, wslist.length, wslist_index);
	//main.js needs some time to open tlsn tab first
	setTimeout(function(){
		var auditeeBrowser = gBrowser.addTab(url);
		gBrowser.addProgressListener(tlsnLoadListener);
		gBrowser.removeAllTabsBut(auditeeBrowser);
	}, 20*1000); //dont violate rate-limiting of 15 connections per minute.
    return;
    //remove tabs ~ every 5th run. We dont want tabs immediately closed so we could examine html while the test is running
    if ((Math.random()*5 << 0) === 4){
		gBrowser.removeAllTabsBut(auditeeBrowser);
	}
}


//wait for the page to become secure before we press AUDIT
var tlsnLoadListener = {
	QueryInterface: XPCOMUtils.generateQI(["nsIWebProgressListener",
										   "nsISupportsWeakReference"]),

	onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {},
	onLocationChange: function(aProgress, aRequest, aURI) {},
	onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) {},
	onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {},
	onSecurityChange: function(aWebProgress, aRequest, aState)
	 {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
			gBrowser.removeProgressListener(this);
			//begin recording as soon as the page turns into https
			startNotarizing(openNextLink);
        }    
    }
}
