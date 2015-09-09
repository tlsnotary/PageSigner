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
var manager_path; //manager.html which was copied into profile's pagesigner dir

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
	import_resource('pubkeys.txt')
	.then(function(ba) {
		parse_reliable_sites(ba2str(ba)); 
	});
}


//converts an array of file names into a string with correct slashes
function toFilePath(pathArray){
	if (typeof(pathArray) === 'string') return pathArray;
	var expanded = '';
	for(var i=0; i < pathArray.length; i++){
		expanded = OS.Path.join(pathArray, dirName[i]);
	}
	return expanded;
}


//reads from addon content folder but also can read an arbitrary file://
function import_resource(filename, isFileURI){
	if (typeof(isFileURI) === 'undefined'){
		isFileURI = false;
	}
	return new Promise(function(resolve, reject) {
		var path = 'content';
		if (typeof(filename) === 'string'){
			path += '/'+filename;
		}
		else {
			for (var i=0; i < filename.length; i++){
				path += '/'+filename[i];
			}
		}

		path = isFileURI ? filename : thisaddon.getResourceURI(path).spec;
		var xhr = get_xhr();
		xhr.responseType = "arraybuffer";
		xhr.onreadystatechange = function(){
			if (xhr.readyState != 4)
				return;

			if (xhr.response) {
				resolve(ab2ba(xhr.response));
			}
		};
		xhr.open('get', path, true);
		xhr.send();
		
		/*
		OS.File.read(OS.Path.fromFileURI(thisaddon.getResourceURI(path).spec))
		.then(function onSuccess(ba) {
			//returns Uint8Array which is compatible with our internal byte array	
			resolve(ba); 
		});
		*/
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
    var resource_url = x.join('/');
	
    var httpChannel = dict_of_httpchannels[sanitized_url];
	var headers = httpChannel.requestMethod + " /" + resource_url + " HTTP/1.1" + "\r\n";
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
	var host = headers.split('\r\n')[1].split(':')[1].replace(/ /g,'');
	var port = 443;
	if (tab_url_full.split(':').length === 3){
		//the port is explicitely provided in URL
		port = parseInt(tab_url_full.split(':')[2].split('/')[0]);
	}
	resolve({'headers':headers, 'server':host, 'port':port});
	});
}


function browser_specific_init(){
	//sometimes gBrowser is not available
	if (gBrowser === null || typeof(gBrowser) === "undefined"){
	   gBrowser = win.gBrowser;
	   setTimeout(browser_specific_init, 100);
	   return;
	}
	
	var os = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime).OS;
	if (os === "WINNT") os_win = true;
	
	getPref('valid_hashes', 'string')
	.then(function(vh){
		if (vh != 'not found'){
			valid_hashes = JSON.parse(vh);
		}
	});
	
	fsRootPath = OS.Path.join(OS.Constants.Path.profileDir, "pagesigner");
	manager_path = OS.Path.toFileURI(OS.Path.join(fsRootPath, "manager.html"));
		
	//copy the manager file to local filesystem for security + takes care of some odd behaviour
	//when trying to add eventListener to chrome:// resources
	var html = OS.Path.fromFileURI(thisaddon.getResourceURI('content/manager.html').spec);
	var js   = OS.Path.fromFileURI(thisaddon.getResourceURI('content/manager.js2').spec);
	var css  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/manager.css').spec);
	var check  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/check.png').spec);
	var cross  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/cross.png').spec);
	var swalcss  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/sweetalert.css').spec);
	var swaljs  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/sweetalert.min.js2').spec);
	var icon  = OS.Path.fromFileURI(thisaddon.getResourceURI('content/icon16.png').spec);

	var dest_html = OS.Path.join(fsRootPath, "manager.html");
	var dest_js = OS.Path.join(fsRootPath, "manager.js2");
	var dest_css = OS.Path.join(fsRootPath, "manager.css");
	var dest_check  = OS.Path.join(fsRootPath, "check.png");
	var dest_cross  = OS.Path.join(fsRootPath, "cross.png");
	var dest_swalcss  = OS.Path.join(fsRootPath, "sweetalert.css");
	var dest_swaljs  = OS.Path.join(fsRootPath, "sweetalert.min.js2");
	var dest_icon  = OS.Path.join(fsRootPath, "icon16.png");

	OS.File.makeDir(fsRootPath, {ignoreExisting:true})
	.then(function(){
		OS.File.copy(html, dest_html);
	})
	.then(function(){
		return OS.File.copy(js, dest_js);
	})
	.then(function(){
		OS.File.copy(css, dest_css);
	})
	.then(function(){
		OS.File.copy(check, dest_check);
	})
	.then(function(){
		OS.File.copy(cross, dest_cross);
	})
	.then(function(){
		OS.File.copy(swalcss, dest_swalcss);
	})
	.then(function(){
		OS.File.copy(swaljs, dest_swaljs);
	})
	.then(function(){
		OS.File.copy(icon, dest_icon);
	});
	
	init();
}

var idiv, listener, managerDocument; //these must be global otherwise we'll get no events
function openManager(is_loading){
	if (typeof(is_loading) === 'undefined'){
		is_loading = false;
	}
	var t;
	var was_manager_open = false;
	var tabs = gBrowser.tabs;
	for(var i=0; i < tabs.length; i++){
		var url = gBrowser.getBrowserForTab(tabs[i]).contentWindow.location.href;
		if (url == manager_path){
			t = tabs[i];
			if (! is_loading){
				//on Win7 i was getting 'load' event even when I clicked another tab
				//we want to select the tab only if manager was called from the menu
				gBrowser.selectedTab = t;
			}
			was_manager_open = true;
		}
	}
	if (was_manager_open && (gBrowser.getBrowserForTab(t).contentWindow.document === managerDocument)){
		console.log('ignoring the same managerDocument in tab');
		return;
	}
	
	var promise;
	if (was_manager_open && !is_loading){
		//this may be a dangling manager from previous browser session
		//if so, then reload it
		if (gBrowser.getBrowserForTab(t).contentWindow.document !== managerDocument){
			console.log('detected a dangling manager tab');
			promise = Promise.resolve();
		}
		else {
			console.log('focusing existing manager');
			return;
		}
	}
	else if (was_manager_open && is_loading){
		
		console.log('reloading existing manager');
		promise = Promise.resolve();
	}
	else if (!was_manager_open){
		promise = new Promise(function(resolve, reject) {
			console.log('opening a new manager');
			t = gBrowser.addTab(manager_path);
			gBrowser.selectedTab = t;
			function check_uri(){
				if (gBrowser.getBrowserForTab(t).contentWindow.location.href !== manager_path){
					console.log('data tab href not ready, waiting');
					setTimeout(function(){check_uri();}, 100);
				}
				else {
					resolve();
				}
			};
			check_uri();
		});
	}
	
	promise
	.then(function(){
		//DOM may not be available immediately
		managerDocument = gBrowser.getBrowserForTab(t).contentWindow.document;
		return new Promise(function(resolve, reject) {
			function wait_for_DOM(){
				listener = managerDocument.getElementById('manager2extension');
				idiv = managerDocument.getElementById('extension2manager');
				if (listener && idiv){
					resolve();
				}
				else {
					console.log('manager DOM not ready yet, waiting');
					setTimeout(function(){wait_for_DOM()}, 100);
				}
			}
			wait_for_DOM();
		});
	})
	.then(function(){
		function onEvent(){
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
				//to update dir's modtime, we remove the file and recreate it
				writeFile(data.args.dir, "meta", str2ba(data.args.newname), true)
				.then(function(){
					populateTable();
				});
			}
			else if (data.message === 'viewdata'){
				var dir = OS.Path.join(fsRootPath, data.args.dir);
				openTabs(dir);
			}
			else if (data.message === 'viewraw'){
				var path = OS.Path.join(fsRootPath, data.args.dir, 'raw.txt');
				gBrowser.selectedTab = gBrowser.addTab(path);
			}
		};
		listener.addEventListener('click', onEvent);
		onEvent(); //maybe the page asked for refresh before listener installed
		
		//add tab event listener which will trigger when user reloads the tab ie with F5
		function onLoadEvent(e){
			console.log('in tab load event handler');
			openManager(true);
		};
		if (!was_manager_open){
			//installed only once on first tab load
			t.addEventListener('load', onLoadEvent);
		}
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
	var delimiter = os_win ? '\\' : '/'; 
	return obj.path.split(delimiter).pop();
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
	var copyFile = function(src, dst){
		OS.File.copy(src, dst)
		.then(function(){
			console.log("File write OK");
		},
		function (e){
			console.log("Caught error writing file: "+e);
		});
	};
	
	if (testing){
		var dldir = Cc["@mozilla.org/file/directory_service;1"].
           getService(Ci.nsIProperties).get("DfltDwnld", Ci.nsIFile).path;
        var dst = OS.Path.join(dldir, 'pagesigner.tmp.dir', name + '.pgsg');
		copyFile(existing_path, dst);
		return;
	}
	
    var nsIFilePicker = Ci.nsIFilePicker;
	var fp = Cc["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
	fp.init(window, "Save PageSigner file As", nsIFilePicker.modeSave);
	//don't set the display directory; leave as default
	fp.defaultExtension = "pgsg";
	fp.defaultString = name + ".pgsg";
	var rv = fp.show();
	if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
		copyFile(existing_path, fp.file.path);
	}
}




function showAboutInfo(){
	window.openDialog("chrome://pagesigner/content/firefox/about.xul","","chrome, dialog, modal", gBrowser).focus();
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
				return;
			}
			var path = notificationCallbacks.getInterface(Components.interfaces.nsIDOMWindow).top.location.pathname;
		} catch (e){
			return; //xhr dont have any interface
		}
		if (block_urls.indexOf(path) > -1){
			httpChannel.cancel(Components.results.NS_BINDING_ABORTED);
			return;
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
		OS.File.makeDir(newdir)
		.then(function(){
			resolve(newdir);
		});
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


function writeFile(dirName, fileName, data, is_update){
	if(typeof(is_update) === "undefined"){
		is_update = false;
	}
	return new Promise(function(resolve, reject) {
		var path = OS.Path.join(fsRootPath, dirName, fileName);
		var promise = is_update ? OS.File.remove(path) : Promise.resolve();
		promise
		.then(function(){
			return OS.File.open(path, {create:true});
		})
		.then(function(f){
			return f.close();
		})
		.then(function(){				
			return OS.File.writeAtomic(path, ba2ua(data));
		})
		.then(function(){
			resolve();
		})
		.catch(function(e){
			console.log('caught error in writeFile', e);
			alert('error in writeFile');
		})
	});
}


function openTabs(sdir){	
	var raw_path = OS.Path.join(sdir, 'raw.txt');
	try{
		OS.File.stat(raw_path);
	}
	catch(e){
		//file hasnt been written yet, sleep a while
		setTimeout(function(){
			openTabs(sdir);
		}, 1000);
		return;
	}
	
	var commonName;
	var dataFileURI;
	var t;
	getFileContent(sdir, "metaDomainName")
	.then(function(data_ba){
		commonName = ba2str(data_ba);
		return getFileContent(sdir, "metaDataFilename")
	})
	.then(function(data){
		var name = ba2str(data);
		var data_path = OS.Path.join(fsRootPath, sdir, name);
		dataFileURI = OS.Path.toFileURI(data_path);
		block_urls.push(data_path);
		t = gBrowser.addTab(data_path);
		gBrowser.selectedTab = t;
		//resolve when URI is ours
		console.log('opening data tab');
		return new Promise(function(resolve, reject) {
			function check_uri(){
				if (gBrowser.getBrowserForTab(t).contentWindow.location.href !== dataFileURI){
					console.log('data tab href not ready, waiting');
					setTimeout(function(){check_uri();}, 100);
				}
				else {
					resolve();
				}
			};
			check_uri();
		});
	})
	.then(function(){
		//reload the tab and check URI
		console.log('reloading data tab');
		//set a token on old document object
		gBrowser.getBrowserForTab(t).contentWindow.document['pagesigner-before-reload'] = true;
		gBrowser.getBrowserForTab(t).reloadWithFlags(Ci.nsIWebNavigation.LOAD_FLAGS_BYPASS_CACHE);
		//after reload FF marks previous document as [dead Object],
		return new Promise(function(resolve, reject) {
			function check_new_document(){
				var doc = gBrowser.getBrowserForTab(t).contentWindow.document;
				if (doc.hasOwnProperty('pagesigner-before-reload')){
					console.log('data tab href not ready, waiting');
					setTimeout(function(){check_new_document();}, 100);
				}
				else {
					resolve();
				}
			};
			check_new_document();
		});
	})
	.then(function(){
		viewTabDocument = gBrowser.getBrowserForTab(t).contentWindow.document;
		//even though .document is immediately available, its .body property may not be
		return new Promise(function(resolve, reject) {
			function wait_for_body(){
				if (viewTabDocument.body === null){
					console.log('body not available, waiting');
					setTimeout(function(){wait_for_body()}, 100);
				}
				else {
					console.log('viewTabDocument is ', viewTabDocument);
					console.log('body is ', viewTabDocument.body);
					install_bar();
					viewTabDocument.getElementById("domainName").textContent = commonName;
					viewTabDocument['pagesigner-session-dir'] = sdir;
					console.log('injected stuff into viewTabDocument');
				}
			};
			wait_for_body();
		});
	});
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


function sendAlert(alertData){
	var p = Cc["@mozilla.org/embedcomp/prompt-service;1"].getService(Ci.nsIPromptService);
	p.alert(null, alertData.title, alertData.text);
}
