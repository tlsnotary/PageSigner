const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/PopupNotifications.jsm");
Cu.import('resource://gre/modules/Services.jsm');
Cu.import("resource://gre/modules/osfile.jsm")
var dict_of_status = {};
var dict_of_httpchannels = {};
var win = Cc['@mozilla.org/appshell/window-mediator;1']
	.getService(Ci.nsIWindowMediator).getMostRecentWindow('navigator:browser');
var gBrowser = win.gBrowser;
var block_urls = []; //an array of urls (filesystem paths) for which all http requests must be blocked
//navigator must be exposed for jsbn.js
var navigator = win.navigator;
var setTimeout = win.setTimeout;
var clearTimeout = win.clearTimeout;
var setInterval = win.setInterval;
var clearInterval = win.clearInterval;
var alert = win.alert;
var btoa = win.btoa;
var atob = win.atob;
var JSON = win.JSON;


function getPref(prefname, type){
	var branch = Services.prefs.getBranch("extensions.pagesigner.");
	if (branch.prefHasUserValue(prefname)){
		if (type === 'bool'){
			return branch.getBoolPref(prefname);
		}
		else if (type === 'string'){
			return branch.getCharPref(prefname);	
		}
	}
	return 'not found';
}


function setPref(prefname, type, value){
	var branch = Services.prefs.getBranch("extensions.pagesigner.");
	if (type === 'bool'){
		branch.setBoolPref(prefname, value);
	}
	else if (type === 'string'){
		branch.getCharPref(prefname, value);	
	}
}


function import_reliable_sites(){
	OS.File.read(OS.Path.join(OS.Constants.Path.profileDir,"extensions","pagesigner@tlsnotary","content","pubkeys.txt"), { encoding: "utf-8" }).
	then(function onSuccess(text) {
		parse_reliable_sites(text); 
	});
}



function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status in a lookup table indexed by the url.
    gBrowser.addProgressListener(myListener);
	Services.obs.addObserver(httpRequestBlocker, "http-on-modify-request", false);
}


function getHeaders(){
	var audited_browser = gBrowser.selectedBrowser;
    var tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    var sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
		alert('"ERROR You can only audit pages which start with https://');
		return false;
    }
    //XXX this check is not needed anymore
    if (dict_of_status[sanitized_url] != "secure"){
		alert("The page does not have a valid SSL certificate. \
			Refresh the page and then try to notarize it again");
		return false;
    }
    
    //passed tests, secure, grab headers, update status bar and start audit:
    var x = sanitized_url.split('/');
    x.splice(0,3);
    var tab_url = x.join('/');
	
    var httpChannel = dict_of_httpchannels[sanitized_url];
	var headers = "";
	headers += httpChannel.requestMethod + " /" + tab_url + " HTTP/1.1" + "\r\n";
	httpChannel.visitRequestHeaders(function(header,value){
                                  headers += header +": " + value + "\r\n";});
    if (httpChannel.requestMethod == "GET"){
		headers += "\r\n";
	}       
    if (httpChannel.requestMethod == "POST"){
		//for POST, extra "\r\n" is already included in uploaddata (see below) to separate http header from http body 
		var uploadChannel = httpChannel.QueryInterface(Ci.nsIUploadChannel);
		var uploadChannelStream = uploadChannel.uploadStream;
		uploadChannelStream.QueryInterface(Ci.nsISeekableStream);                 
		uploadChannelStream.seek(0,0);                               
		var stream = Cc['@mozilla.org/scriptableinputstream;1'].createInstance(Ci.nsIScriptableInputStream);
		stream.init(uploadChannelStream);
		var uploaddata = stream.read(stream.available());
		stream.close();
		//FF's uploaddata contains Content-Type and Content-Length headers + '\r\n\r\n' + http body
		headers += uploaddata;
	}
	return headers;
}


function browser_specific_init(){
	//sometimes gBrowser is not available
	if (gBrowser === null || typeof(gBrowser) === "undefined"){
	   gBrowser = win.gBrowser;
	   setTimeout(browser_specific_init, 100);
	   return;
	}
	init();
}


function openManager(){
	var t = gBrowser.addTab("chrome://pagesigner/content/manager.xhtml");
	gBrowser.selectedTab = t;
}


function savePGSGFile(existing_file){
    var nsIFilePicker = Ci.nsIFilePicker;
	var fp = Cc["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
	fp.init(window, "Save PageSigner file As", nsIFilePicker.modeSave);
	//don't set the display directory; leave as default
	fp.defaultExtension = "pgsg";
	fp.defaultString = existing_file.name;
	var rv = fp.show();
	if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
		var path = fp.file.path;
		//write the file
		let promise = OS.File.copy(existing_file.path, fp.file.path);
		promise.then(function(){
			log("File write OK");
		},
		function (e){
			log("Caught error writing file: "+e);
		}
		);
   }
}


function showAboutInfo(){
window.openDialog("chrome://pagesigner/content/about.xul","","chrome, dialog, modal").focus();
}


//create the final html that prover and verifier will see in the tab and return 
//its path.
function create_final_html(html_with_headers, session_dir){
	var rv = html_with_headers.split('\r\n\r\n');
	var headers = rv[0];
	var html = rv[1]; 
	var path_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	var raw_response = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	path_html.initWithPath(session_dir);
	path_html.append('html.html');
	 //see "Byte order mark"
	return OS.File.writeAtomic(path_html.path, ba2ua([0xef, 0xbb, 0xbf]))
	.then(function(){
		return OS.File.writeAtomic(path_html.path, ba2ua(str2ba(html)));
	})
	.then(function(){
		raw_response.initWithPath(session_dir);
		raw_response.append('raw.txt');
		return OS.File.writeAtomic(raw_response.path, ba2ua([0xef, 0xbb, 0xbf]));
	})
	.then(function(){
		return OS.File.writeAtomic(raw_response.path, ba2ua(str2ba(html_with_headers)));
	});
}


//extracts modulus from PEM certificate
function getModulus(cert){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	const nsASN1Tree = "@mozilla.org/security/nsASN1Tree;1";
	const nsIASN1Tree = Ci.nsIASN1Tree;
	var hexmodulus = "";
	
	var certDumpTree = Cc[nsASN1Tree].createInstance(nsIASN1Tree);
	certDumpTree.loadASN1Structure(cert_obj.ASN1Structure);
	var modulus_str = certDumpTree.getDisplayData(12);
	if (! modulus_str.startsWith( "Modulus (" ) ){
		//most likely an ECC certificate
		alert ("Unfortunately this website is not compatible with PageSigner. (could not parse RSA certificate)");
		return;
	}
	var lines = modulus_str.split('\n');
	var line = "";
	for (var i = 1; i<lines.length; ++i){
		line = lines[i];
		//an empty line is where the pubkey part ends
		if (line === "") {break;}
		//remove all whitespaces (g is a global flag)
		hexmodulus += line.replace(/\s/g, '');
	}
	return hex2ba(hexmodulus);
}


//verify the certificate against Firefox's certdb
function verifyCert(cert){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	let a = {}, b = {};
	let retval = certdb.verifyCertNow(cert_obj, nsIX509Cert.CERT_USAGE_SSLServerWithStepUp, nsIX509CertDB.FLAG_LOCAL_ONLY, a, b);
	if (retval === 0){ 		//success
		return true;
	}
	else {
		return false;
	}
}


function dumpSecurityInfo(channel,urldata) {
    // Do we have a valid channel argument?
    if (! channel instanceof  Ci.nsIChannel) {
        log("No channel available\n");
        return;
    }
    var secInfo = channel.securityInfo;
    // Print general connection security state
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
        secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
        // Check security state flags
	latest_tab_sec_state = "uninitialised";
        if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) == Ci.nsIWebProgressListener.STATE_IS_SECURE)
            latest_tab_sec_state = "secure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) == Ci.nsIWebProgressListener.STATE_IS_INSECURE)
            latest_tab_sec_state = "insecure";
        else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) == Ci.nsIWebProgressListener.STATE_IS_BROKEN)
            latest_tab_sec_state = "unknown";
	
	//remove hashes - they are not URLs but are used for internal page mark-up
	sanitized_url = urldata.split("#")[0];
	dict_of_status[sanitized_url] = latest_tab_sec_state;
	dict_of_httpchannels[sanitized_url]  = channel.QueryInterface(Ci.nsIHttpChannel);
    }
    else {
        log("\tNo security info available for this channel\n");
    }
}


//blocks http request coming from block_tab
var httpRequestBlocker = {
	observe: function (httpChannel, aTopic, aData) {
		try{
			if (aTopic !== "http-on-modify-request") return;
			if (!(httpChannel instanceof Ci.nsIHttpChannel)) return;    
			var notificationCallbacks;
			if (httpChannel.notificationCallbacks) {
				notificationCallbacks = httpChannel.notificationCallbacks;
			}
			else if (httpChannel.loadGroup && httpChannel.loadGroup.notificationCallbacks) {
				notificationCallbacks = httpChannel.loadGroup.notificationCallbacks;        
			}
			else return;
			var path = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow).top.location.pathname;
		} catch (e){ 
			return; //xhr dont have any interface
		}
		for(var i=0; i < block_urls.length; i++){
			if (block_urls[i] === path){
				log('found matching tab, ignoring request');
				httpChannel.cancel(Components.results.NS_BINDING_ABORTED);
			}
		}
	}
};


var	myListener =
{
    QueryInterface: function(aIID)
    {
        if (aIID.equals(Ci.nsIWebProgressListener) ||
           aIID.equals(Ci.nsISupportsWeakReference) ||
           aIID.equals(Ci.nsISupports))
            return this;
        throw Components.results.NS_NOINTERFACE;
    },
    onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) { },
    onLocationChange: function(aProgress, aRequest, aURI) { },
    onProgressChange: function(aWebProgress, aRequest, curSelf, maxSelf, curTot, maxTot) { },
    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) { },
    onSecurityChange: function(aWebProgress, aRequest, aState) 
    {
        // check if the state is secure or not
        if(aState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
        {
            // this is a secure page, check if aRequest is a channel,
            // since only channels have security information
            if (aRequest instanceof Ci.nsIChannel)
            {
                dumpSecurityInfo(aRequest,gBrowser.selectedBrowser.contentWindow.location.href);          
            }
        }    
    }
};


function install_notification(t, commonName, raw_path){
	t.addEventListener("load", function load(){
		log('in load event');
		var box = gBrowser.getNotificationBox();
		var priority = box.PRIORITY_INFO_HIGH;
		var message = 'PageSigner successfully verified that the webpage below was received from '+commonName;
		var icon = 'chrome://pagesigner/content/icon16.png';
		var buttons = [{
			label: 'View raw HTML with HTTP headers',
			accessKey: '',
			callback: function(){
				var nt = gBrowser.addTab(raw_path);
				gBrowser.selectedTab = nt;
				//throwing an error prevents notification from closing
				throw new Error('prevent notification close');
			}
		}];
		setTimeout(function(){
			//without timeout, notifbar fails to show
			box.appendNotification(message, 'pgsg-notif', icon, priority, buttons);
		}, 1000);
		t.removeEventListener("load", load, false);
	}, false);
}


function makeSessionDir(server, is_imported){
	if (typeof(is_imported) === "undefined"){
		is_imported = false;
	}
	var localDir = getPGSGdir();
	var time = getTime();
	var imported_str = "";
	if (is_imported){
		imported_str = "-IMPORTED";
	}
	localDir.append(time+'-'+server+imported_str); 
	localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);
	return localDir.path;
}


function writePgsg(pgsg, session_dir, commonName){
	var path_pgsg = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	path_pgsg.initWithPath(session_dir);
	path_pgsg.append(commonName+'.pgsg');
	return OS.File.writeAtomic(path_pgsg.path, pgsg);
}


function openTabs(sdir, commonName){
	var final_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	final_html.initWithPath(sdir);
	final_html.append('html.html');
	if (! final_html.exists() ){
		//not yet written
		setTimeout(function(){
			openTabs(sdir, commonName);
		}, 1000);
		return;
	}
	var raw = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	raw.initWithPath(sdir);
	raw.append('raw.txt');
	var t = gBrowser.addTab(final_html.path);
	block_urls.push(final_html.path);
	gBrowser.selectedTab = t;
	install_notification(t, commonName, raw.path);
}


function getCommonName(cert){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	return cert_obj.commonName;
}


function readFile(path){
	return OS.File.read(path);
}
