const {classes: Cc, interfaces: Ci, utils: Cu} = Components;
Cu.import("resource://gre/modules/PopupNotifications.jsm");
Cu.import('resource://gre/modules/Services.jsm');
Cu.import("resource://gre/modules/osfile.jsm");
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
var is_chrome = false;
var fsRootPath; //path to pagesigner folder in FF profile dir


function getPref(prefname, type){
	return new Promise(function(resolve, reject) {
		var branch = Services.prefs.getBranch("extensions.pagesigner.");
		if (branch.prefHasUserValue(prefname)){
			if (type === 'bool'){
				resolve(branch.getBoolPref(prefname));
			}
			else if (type === 'string'){
				resolve(branch.getCharPref(prefname));	
			}
		}
		resolve('not found');
	});
}


function setPref(prefname, type, value){
	return new Promise(function(resolve, reject) {
		var branch = Services.prefs.getBranch("extensions.pagesigner.");
		if (type === 'bool'){
			branch.setBoolPref(prefname, value);
		}
		else if (type === 'string'){
			branch.setCharPref(prefname, value);	
		}
		resolve();
	});
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
	return new Promise(function(resolve, reject) {

	var audited_browser = gBrowser.selectedBrowser;
    var tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    var sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
		reject('"ERROR You can only notarize pages which start with https://');
		return;
    }
    //XXX this check is not needed anymore
    if (dict_of_status[sanitized_url] != "secure"){
		reject("Please refresh the page and then try to notarize it again");
		return;
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
	var server = headers.split('\r\n')[1].split(':')[1].replace(/ /g,'');
	resolve({'headers':headers, 'server':server});
	});
}


function browser_specific_init(){
	var os = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime).OS;
	if (os === "WINNT") os_win = true;
	
	getPref('valid_hashes', 'string')
	.then(function(vh){
		if (vh != 'not found'){
			valid_hashes = JSON.parse(vh);
		}
	});
	fsRootPath = OS.Path.join(OS.Constants.Path.profileDir, "pagesigner");
	OS.File.makeDir(fsRootPath); //noop if exists
	
	//sometimes gBrowser is not available
	if (gBrowser === null || typeof(gBrowser) === "undefined"){
	   gBrowser = win.gBrowser;
	   setTimeout(browser_specific_init, 100);
	   return;
	}
	init();
}


var idiv;
var listener;
var d;
function openManager(){
	//if manager is open, focus it
	var tabs = gBrowser.tabs;
	for(var i=0; i < tabs.length; i++){
		var url = gBrowser.getBrowserForTab(tabs[i]).contentWindow.location.href;
		if (url.search('/pagesigner/manager.html') > -1){
			gBrowser.selectedTab = tabs[i];
			return;
		}
	}
	
	//copy the manager file to local filesystem for security + takes care of some odd behaviour
	//when trying to add eventListener to chrome:// resources
	var contentDir = OS.Path.join(OS.Constants.Path.profileDir,"extensions","pagesigner@tlsnotary","content");
	var html = OS.Path.join(contentDir, "manager.html");
	var js   = OS.Path.join(contentDir, "manager.js");
	var css  = OS.Path.join(contentDir, "manager.css");
	var check  = OS.Path.join(contentDir, "check.png");
	var cross  = OS.Path.join(contentDir, "cross.png");

	var dest_html = OS.Path.join(fsRootPath, "manager.html");
	var dest_js = OS.Path.join(fsRootPath, "manager.js");
	var dest_css = OS.Path.join(fsRootPath, "manager.css");
	var dest_check  = OS.Path.join(fsRootPath, "check.png");
	var dest_cross  = OS.Path.join(fsRootPath, "cross.png");

	OS.File.copy(html, dest_html)
	.then(function(){
		return OS.File.copy(js, dest_js, {noOverwrite:true});
	})
	.then(function(){
		OS.File.copy(css, dest_css, {noOverwrite:true});
	})
	.then(function(){
		OS.File.copy(check, dest_check, {noOverwrite:true});
	})
	.then(function(){
		OS.File.copy(cross, dest_cross, {noOverwrite:true});
	})
	.catch(function(e){
		console.log('files exist');
		//exception is expected if file exists
	})
	.then(function(){
		var uri = dest_html;
		var t = gBrowser.addTab(uri);
		gBrowser.selectedTab = t;
		
		var readyListener = function(e){
			//will trigger on reload (sometimes triggers twice but this should not affect us)
			d = gBrowser.getBrowserForTab(e.target).contentWindow.document;
			
			var install_listener = function(d){
				listener = d.getElementById('manager2extension');
				idiv = d.getElementById('extension2manager');
				if (!listener){ //maybe the DOM hasnt yet loaded
					setTimeout(function(){
						install_listener(d);
					}, 100);
					return;
				}
				
				var onEvent = function(){
					console.log('in click event');
					if (listener.textContent === '') return;//spurious click
					var data = JSON.parse(listener.textContent);
					listener.textContent = '';
					if (data.destination !== 'extension') return;
					if (data.message === 'refresh'){
						populateTable();
					}
					else if (data.message === 'export'){
						var path = OS.Path.join(fsRootPath, data.args.dir, 'pgsg.pgsg');
						 console.log('saving full path', path);
						savePGSGFile(path, data.args.file);
					}
					else if (data.message === 'delete'){
						OS.File.removeDir(OS.Path.join(fsRootPath, data.args.dir))
						.then(function(){
							populateTable();
						});
					}
					else if (data.message === 'rename'){
						var path = OS.Path.join(fsRootPath, data.args.dir, "meta");
						//to update dir's modtime, we remove the file and recreate it
						OS.File.remove(path)
						.then(function(){
							return OS.File.open(path, {create:true});
						})
						.then(function(){				
							return OS.File.writeAtomic(path, ba2ua(str2ba(data.args.newname)));
						})
						.then(function(){
							populateTable();
						});
					}
					else if (data.message === 'viewhtml'){
						var path = OS.Path.join(fsRootPath, data.args.dir, 'html.html');
						gBrowser.selectedTab = gBrowser.addTab(path);
					}
					else if (data.message === 'viewraw'){
						var path = OS.Path.join(fsRootPath, data.args.dir, 'raw.txt');
						gBrowser.selectedTab = gBrowser.addTab(path);
					}
				};
				listener.addEventListener('click', onEvent);
				onEvent(); //maybe the page asked for refresh before listener installed
			};
			
			install_listener(d);
		};
			
		t.addEventListener('load', readyListener);
	});
}


function getDirContents(dirName){
	return new Promise(function(resolve, reject) {
		var subdirs = [];
		if (dirName === '/') dirName = '';
		var path = OS.Path.join(fsRootPath, dirName);
		var iterator = new OS.File.DirectoryIterator(path);
		var p = iterator.forEach(
			function (entry) {
				//entry is not path
				subdirs.push(entry);
		});
		p.then(function(){
			iterator.close();
			resolve(subdirs);
		})
		.catch(function(e){
			console.log('error', e);
		});
	});
}


function getDirEntry(dirName){
	return new Promise(function(resolve, reject) {
		var path = OS.Path.join(fsRootPath, dirName);
		console.log('point1', path);
		OS.File.stat(path)
		.then(function(stat){
			resolve(stat);
		});
	});
}


function getName(obj){
	//XXX this is not x-platform
	return obj.path.split('/').pop();
}


function getFullPath(obj){
	return obj.path;
}


function getFileContent(dirname, filename){
	return new Promise(function(resolve, reject) {
		var path = OS.Path.join(fsRootPath, dirname, filename);
		OS.File.read(path)
		.then(function (data){
			resolve(ua2ba(data));
		}).
		catch(function(e){
			console.log('resolving with error', e);
			//must resolve even on error
			resolve(e);
		});
	});
}

function isDirectory(obj){
	return obj.isDir;
}


function getModTime(dirEntry){
	return new Promise(function(resolve, reject) {
		var promise = OS.File.stat(dirEntry.path);
		promise
		.then(function(info){
			resolve(info.lastModificationDate.getTime());
		});
	});
}


function sendMessage(data){
	if (typeof(idiv) === "undefined") return;
	if (!idiv) return;
	try{ //idiv may be a dead object. The only way to find out is by accessing its property
		var json = JSON.stringify(data)
		idiv.textContent = json;
		idiv.click();
	}
	catch (e){
		return;
	}
}


function savePGSGFile(existing_path, name){
    var nsIFilePicker = Ci.nsIFilePicker;
	var fp = Cc["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
	fp.init(window, "Save PageSigner file As", nsIFilePicker.modeSave);
	//don't set the display directory; leave as default
	fp.defaultExtension = "pgsg";
	fp.defaultString = name + ".pgsg";
	var rv = fp.show();
	if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
		var path = fp.file.path;
		//write the file
		let promise = OS.File.copy(existing_path, fp.file.path);
		promise.then(function(){
			console.log("File write OK");
		},
		function (e){
			console.log("Caught error writing file: "+e);
		}
		);
   }
}




function showAboutInfo(){
	window.openDialog("chrome://pagesigner/content/firefox/about.xul","","chrome, dialog, modal", gBrowser).focus();
}


//create the final html that prover and verifier will see in the tab and return 
//its path.
function create_final_html(html_with_headers, session_dir){
	var rv = html_with_headers.split('\r\n\r\n');
	var headers = rv[0];
	var html = rv.splice(1).join('\r\n\r\n'); 
		
	var path_html = OS.Path.join(session_dir, 'html.html');
	var raw_response = OS.Path.join(session_dir, 'raw.txt');
	 //see "Byte order mark"
	return OS.File.writeAtomic(path_html, ba2ua([].concat([0xef, 0xbb, 0xbf], str2ba(html))))
	.then(function(){
		return OS.File.writeAtomic(raw_response, ba2ua([].concat([0xef, 0xbb, 0xbf], str2ba(html_with_headers))));
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
function verifyCert(chain){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(chain[0]));
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
        console.log("No channel available\n");
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
        console.log("\tNo security info available for this channel\n");
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
			else {
				console.log('no notificationCallbacks');
				return;
			}
			var path = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow).top.location.pathname;
		} catch (e){
			console.log('no interface');
			return; //xhr dont have any interface
		}
		if (block_urls.indexOf(path) > -1){
			console.log('found matching tab, blocking request', path);
			httpChannel.cancel(Components.results.NS_BINDING_ABORTED);
			return;
		}
		console.log('not blocking request', path);
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
		console.log('in load event');
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
	return new Promise(function(resolve, reject) {
		if (typeof(is_imported) === "undefined"){
			is_imported = false;
		}
		var localDir = OS.Path.join(OS.Constants.Path.profileDir, "pagesigner");
		var time = getTime();
		var imported_str = "";
		if (is_imported){
			imported_str = "-IMPORTED";
		}
		var newdir = OS.Path.join(localDir, time+'-'+server+imported_str);
		OS.File.makeDir(newdir);
		resolve(newdir);
	});
}


function writePgsg(pgsg, session_dir, commonName){
	//* is illegal in a Windows filename; remove
	var name = commonName.replace(/\*\./g,""); 	
	//var f = OS.File.open(OS.Path.join(session_dir, 'pgsg.pgsg'), {create:true});
	return OS.File.writeAtomic(OS.Path.join(session_dir, 'pgsg.pgsg'), ba2ua(pgsg))
	.then(function(){
		return OS.File.writeAtomic(OS.Path.join(session_dir, 'meta'), ba2ua(str2ba(name)));
	});
}


function openTabs(sdir, commonName){
	var html_path = OS.Path.join(sdir, 'html.html');
	var raw_path = OS.Path.join(sdir, 'raw.txt');
	try{
		OS.File.stat(html_path);
	}
	catch(e){
		//file hasnt been written yet, sleep a while
		setTimeout(function(){
			openTabs(sdir, commonName);
		}, 1000);
		return;
	}
	
	block_urls.push(html_path);
	var t = gBrowser.addTab(html_path);
	gBrowser.selectedTab = t;
	install_notification(t, commonName, raw_path);
}


function getCommonName(cert){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	return cert_obj.commonName;
}


function Socket(name, port){
	this.name = name;
	this.port = port;
	this.sckt = null;
	this.is_open = false;
	this.buffer = [];
}
Socket.prototype.connect = function(){
	//TCPSocket doesnt like to be wrapped in a Promise. We work around by making the
	//promise resolve when .is_open is triggered
	var TCPSocket = Components.classes["@mozilla.org/tcp-socket;1"].createInstance(Components.interfaces.nsIDOMTCPSocket);
	this.sckt = TCPSocket.open(this.name, this.port, {binaryType:"arraybuffer"});
	var that = this; //inside .ondata/open etc this is lost
	this.sckt.ondata = function(event){ 
		//transform ArrayBuffer into number array
		var view = new DataView(event.data);
		var int_array = [];
		for(var i=0; i < view.byteLength; i++){
			int_array.push(view.getUint8(i));
		}
		console.log('ondata got bytes:', view.byteLength);
		that.buffer = [].concat(that.buffer, int_array);
	};
	this.sckt.onopen = function() {
		that.is_open = true;
		console.log('onopen');
	};
	
	return new Promise(function(resolve, reject) {
		var timer;
		var startTime = new Date().getTime();
		var check = function(){
			var now = new Date().getTime();
			if (( (now - startTime) / 1000) >= 20){
				clearInterval(timer);
				reject('socket timed out');
				return;
			}
			if (!that.is_open){
				console.log('Another timeout');
				return;
			}
			clearInterval(timer);
			console.log('promise resolved');
			resolve('ready');
		};
		timer = setInterval(check, 100);
	});
	
};
Socket.prototype.send = function(data_in){
	//Transform number array into ArrayBuffer
	var sock = this.sckt;
	var ab = new ArrayBuffer(data_in.length);
	var dv = new DataView(ab);
	for(var i=0; i < data_in.length; i++){
		dv.setUint8(i, data_in[i]);
	}
	sock.send(ab, 0, ab.byteLength);
}
Socket.prototype.recv = function(is_handshake){
	if (typeof(is_handshake) === "undefined"){
		is_handshake = false;
	}
	var that = this;
	return new Promise(function(resolve, reject) {
		console.log('in recv promise');
		var timer;
		var startTime = new Date().getTime();
		var tmp_buf = [];
		
		var complete_records = [];
		var buf = [];
		//keep checking until either timeout or enough data gathered
		var check_recv = function(){
			var now = new Date().getTime();
			if (( (now - startTime) / 1000) >= 20){
				clearInterval(timer);
				console.log('rejecting');
				reject('socket timed out');
				return;
			}
			if (that.buffer.length === 0){
				console.log('Another timeout in recv');
				return;
			}
			buf = [].concat(buf, that.buffer);
			that.buffer = [];
			var rv = check_complete_records(buf);
			complete_records = [].concat(complete_records, rv.comprecs);
			if (! rv.is_complete){
				console.log("check_complete_records failed");
				buf = rv.incomprecs;
				return;
			}
			//else
			clearInterval(timer);
			console.log('promise resolved');
			resolve(complete_records);
		};
		timer = setInterval(check_recv, 100);
	});
};
Socket.prototype.close = function(){
	this.sckt.close();
};


function get_xhr(){
	return Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
}



function updateCache(hash){
	if (valid_hashes.indexOf(hash.toString()) < 0){
		valid_hashes.push(hash.toString());
		setPref('valid_hashes', 'string', JSON.stringify(valid_hashes));
	}
}
