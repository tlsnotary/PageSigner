var testing = false;
var tabs = {};
var appId = "oclohfdjoojomkfddjclanpogcnjhemd"; //id of the helper app
var is_chrome = true;
var fsRootPath; //path to local storage root, e.g. filesystem:chrome-extension://abcdabcd/persistent


function getPref(pref, type){
	return new Promise(function(resolve, reject) {
		chrome.storage.local.get(pref, function(obj){
			if (Object.keys(obj).length === 0){
				resolve('undefined');
				return;
			}
			else {
				resolve(obj[pref]);
			}
		});
	});
}


function setPref(pref, type, value){
	return new Promise(function(resolve, reject) {
		var obj = {};
		obj[pref] = value;
		chrome.storage.local.set(obj, function(){
			resolve();
		});
	});
}


function import_reliable_sites(){
	import_resource('pubkeys.txt')
	.then(function(text_ba){
		parse_reliable_sites(ba2str(text_ba));
	});
}


function import_resource(filename){
	return new Promise(function(resolve, reject) {
		var xhr = new XMLHttpRequest();
		xhr.responseType = "arraybuffer";
		xhr.onreadystatechange = function(){
			if (xhr.readyState != 4)
				return;

			if (xhr.response) {
				resolve(ab2ba(xhr.response));
			}
		};
		xhr.open('get', chrome.extension.getURL('content/'+toFilePath(filename)), true);
		xhr.send();
	});
}


//converts an array of file names into a string with correct slashes
function toFilePath(pathArray){
	if (typeof(pathArray) === 'string') return pathArray;
	var expanded = '';
	for(var i=0; i < pathArray.length; i++){
		expanded += pathArray[i];
		//not trailing slash for last element
		if (i < (pathArray.length-1) ){
			expanded += '/';
		}
	}
	return expanded;
}


function startListening(){
	chrome.webRequest.onSendHeaders.addListener(
        function(details) {
		  if (details.type === "main_frame"){
				tabs[details.tabId] = details;
			}
        },
        {urls: ["<all_urls>"]},
        ["requestHeaders"]);
}


function getHeaders(){
	return new Promise(function(resolve, reject) {
	chrome.tabs.query({active: true}, function(t){
		if (! t[0].url.startsWith('https://')){
			reject('You can only notarize pages which start with https://');
			return;
		}
		if (!tabs.hasOwnProperty(t[0].id)) {
			reject('Please refresh the page and then try to notarize it again');
			return;
		}
		var tab = tabs[t[0].id];
		var x = tab.url.split('/');
		var host = x[2].split(':')[0];
		x.splice(0,3);
		var resource_url = x.join('/');	
		var headers = tab.method + " /" + resource_url + " HTTP/1.1" + "\r\n";
		headers += "Host: " + host + "\r\n";
		for (var i = 0; i < tab.requestHeaders.length; i++){
			var h = tab.requestHeaders[i];
			headers += h.name + ": " + h.value + "\r\n";
		}
		if (tab.method == "GET"){
			headers += "\r\n";
		}
		var port = 443;
        if (tab.url.split(':').length === 3){
			//the port is explicitely provided in URL
			port = parseInt(tab.url.split(':')[2].split('/')[0]);
        }
		resolve({'headers':headers, 'server':host, 'port':port});
	});
	});
}


function loadBusyIcon(){
	chrome.browserAction.setIcon({path:"content/icon_spin.gif"});
	chrome.browserAction.setPopup({popup:"content/chrome/popup_pleasewait.html"});
}


function loadNormalIcon(){
	chrome.browserAction.setIcon({path:"icon.png"});
	chrome.browserAction.setPopup({popup:"content/chrome/popup.html"});
}


function browser_specific_init(){
	window.webkitRequestFileSystem(window.PERSISTENT, 50*1024*1024, function(fs){
		fsRootPath = fs.root.toURL();
	});
	getPref('valid_hashes')
	.then(function(hashes){
		if (hashes !== 'undefined'){
			valid_hashes = hashes;
		}
	});
	chrome.runtime.getPlatformInfo(function(p){
		if(p.os === "win"){
			os_win = true;
		}
	});
	//put icon into downloads dir. This is the icon for injected notification
	chrome.downloads.setShelfEnabled(false);
	setTimeout(function(){chrome.downloads.setShelfEnabled(true);}, 2000);
	chrome.downloads.download({url:chrome.extension.getURL("content/icon16.png"),
		conflictAction:'overwrite',
		 filename:'pagesigner.tmp.dir/icon16.png'});
	
	chrome.runtime.onMessage.addListener(function(data){
		if (data.destination !== 'extension') return;
		console.log('ext got msg', data);
		if (data.message === 'rename'){
			renamePGSG(data.args.dir, data.args.newname);
		}
		else if (data.message === 'delete'){
			deletePGSG(data.args.dir);
		}
		else if (data.message === 'import'){
			verify_tlsn_and_show_data(data.args.data, true);
		}
		else if (data.message === 'export'){
			chrome.downloads.download({url:fsRootPath+data.args.dir+'/pgsg.pgsg',
				 'saveAs':true, filename:data.args.file+'.pgsg'});
		}
		else if (data.message === 'notarize'){
			startNotarizing();
		}
		else if (data.message === 'manage'){
			openManager();
		}
		else if (data.message === 'refresh'){
			populateTable();
		}
		else if (data.message === 'openLink1'){
			chrome.tabs.create({url:'https://www.tlsnotary.org'});
		}
		else if (data.message === 'openLink2'){
			chrome.tabs.create({url:'https://www.tlsnotary.org/pagesigner/faq'});
		}
		else if (data.message === 'openLink3'){
			chrome.tabs.create({url:'bitcoin:35q65MQPVSi9TYMKxNYmpSyhWj7FkzTjzQ'});
		}
		else if (data.message === 'viewdata'){
			openTabs(fsRootPath+data.args.dir);
		}
		else if (data.message === 'viewraw'){
			chrome.tabs.create({url:fsRootPath+data.args.dir+'/raw.txt'});
		}
		else if (data.message === 'openInstallLink'){
			chrome.tabs.create({url:'https://chrome.google.com/webstore/detail/pagesigner-helper-app/oclohfdjoojomkfddjclanpogcnjhemd'});
		}
	});
	chrome.management.get(appId, function(a){
		if (typeof(a) === "undefined"){
			chrome.browserAction.setPopup({popup:"content/chrome/popup_installapp.html"});
		}
		else {
			chrome.browserAction.setPopup({popup:"content/chrome/popup.html"});
		}
	});
	
	chrome.management.onEnabled.addListener(function(app){
		if (app.id !== appId) return;
		chrome.browserAction.setPopup({popup:"content/chrome/popup.html"});
	});
	chrome.management.onDisabled.addListener(function(app){
		if (app.id !== appId) return;
		chrome.browserAction.setPopup({popup:"content/chrome/popup_installapp.html"});
	});
	
	init();
}





function makeSessionDir(server, is_imported){
	return new Promise(function(resolve, reject) {

		if (typeof(is_imported) === "undefined"){
			is_imported = false;
		}
		var time = getTime();
		var imported_str = "";
		if (is_imported){
			imported_str = "-IMPORTED";
		}
		var server_sanitized = server;
		if (server.search(/\*/) > -1){
			var parts = server.split('.');
			server_sanitized = parts[parts.length-2]+'.'+parts[parts.length-1];
		}
		var name = time+'-'+server_sanitized+imported_str;
		window.webkitRequestFileSystem(window.PERSISTENT, 5*1024*1024, function(fs){
			fs.root.getDirectory(name, {create: true}, function (dir){
				resolve(dir.toURL());
			});
		});
	});
}


//we remove the file and re-create it because if we simply update the file
//the dir's modification time won't change
function removeFile(dirName, fileName){
	return new Promise(function(resolve, reject) {
		window.webkitRequestFileSystem(window.PERSISTENT, 5*1024*1024, function(fs){
			fs.root.getDirectory(dirName, {}, function (dir){				
				dir.getFile(fileName, {}, function (f){
					f.remove(function(){
						resolve();
					});
				});
			});
		});
	});
}


function writeFile(dirName, fileName, data, is_update){
	if (data.length === 0) return;
	if(typeof(is_update) === "undefined"){
		is_update = false;
	}
	var remove_promise = Promise.resolve();
	if (is_update) remove_promise = removeFile(dirName, fileName);
	return remove_promise
	.then(function(){
		return new Promise(function(resolve, reject) {
			window.webkitRequestFileSystem(window.PERSISTENT, 5*1024*1024, function(fs){
				fs.root.getDirectory(dirName, {}, function (dir){	
					dir.getFile(fileName, {create:true, exclusive:true}, function (f){
						f.createWriter(function(fw) {
							fw.onwriteend = function() {
								resolve();	
							};							
							fw.write(new Blob([ba2ua(data)]));
						});
					});
				});
			});
		});
	});
}


function openTabs(sdir){
	//Because Chrome tabs crash when opening html from filesystem:chrome-extension:// URI
	//we first download the file to /Downloads and then open
	var uid = Math.random().toString(36).slice(-10);
	chrome.downloads.setShelfEnabled(false);
	setTimeout(function(){chrome.downloads.setShelfEnabled(true);}, 1000);
	var dirname = sdir.split('/').pop();
	var commonName;
	getFileContent(dirname, "metaDomainName")
	.then(function(data_ba){
		commonName = ba2str(data_ba);
		return getFileContent(dirname, "metaDataFilename");
	})
	.then(function(data){
		var name = ba2str(data);
		chrome.downloads.download({url:sdir + '/' + name, filename:'pagesigner.tmp.dir/'+uid+name},
		function(id){
			chrome.downloads.onChanged.addListener(function downloadCompleted(delta){
				if (delta.id != id) return;
				if (typeof(delta.state) === "undefined") return;
				if (delta.state.current !== 'complete') return;
				chrome.downloads.onChanged.removeListener(downloadCompleted);
				onComplete(id); //download completed
			});
			
			var onComplete = function(id){
				chrome.downloads.search({id:id}, function(items){
					var item = items[0];
					var path = 'file://' + item.filename;
					if (os_win) path = 'file:///'+fixWinPath(item.filename);
					chrome.tabs.query({url: 'chrome-extension://*/content/chrome/file_picker.html'}, 
					function(t){
						//we want to find the file import tab and reuse it
						if (t.length === 1){
							chrome.tabs.update(t[0].id, {url:path}, function(t){
								chrome.tabs.onUpdated.addListener(function tabUpdated(tabId, info, tab){
									if (tabId != t.id) return;
									//dont wait for tab to load, reload immediately
									chrome.tabs.onUpdated.removeListener(tabUpdated);
									block_and_reload(t.id, path);
								})
							});
						}
						//otherwise we are not importing - just open a new tab
						else {
								chrome.tabs.create({url:path}, function(t){
								block_and_reload(t.id, path);
							});
						}
					});
				});
			};
			
			var block_and_reload = function(id, path){
				//Blocking listener means it will process each request serially, not in parallel.
				//There is a Chrome bug that when the listener is not blocking
				//and a flood of requests happen, some of those requests don't end up in the
				//listener and thus are allowed to go through.
				chrome.webRequest.onBeforeRequest.addListener(function(x){
					if (x.url.startsWith('file://')) return; //dont block the actual file we are opening
					console.log('blocking', x.url);
					return {cancel:true};
				}, {tabId:id, urls: ["<all_urls>"]}, ["blocking"]);
				chrome.tabs.reload(id, {bypassCache:true}, function(){
					//this callback triggers too early sometimes. Wait to make sure page reloaded
					setTimeout(function(){
						chrome.tabs.insertCSS(id, {file: 'content/chrome/injectbar.css'}, function(a){
							chrome.tabs.executeScript(id, {file: 'content/chrome/injectbar.js'}, function(a){
									chrome.tabs.executeScript(id, {code: 
									'document.getElementById("domainName").textContent="' + commonName.toString() + '";' + 
									'var sdir ="' + dirname.toString() + '";'});
							});
						});
					}, 500);
				});
			};
		});
	});
}


function Socket(name, port){
	this.name = name;
	this.port = port;
	this.uid = Math.random().toString(36).slice(-10);
}
Socket.prototype.connect = function(){
	var that = this;
	var is_open = false;
	var uid = this.uid;
	return new Promise(function(resolve, reject) {
		chrome.runtime.sendMessage(appId,
			{'command':'connect', 
			'args':{'name':that.name, 'port':that.port},
			'uid':uid},
			function(response){
			console.log('in connect response', response);
			if (response.retval === 'success'){
				is_open = true;
				resolve('ready');
			}
			reject(response.retval);
			
		});
		//dont wait too loong
		var timer;
		var startTime = new Date().getTime();
		var check = function(){
			var now = new Date().getTime();
			if (( (now - startTime) / 1000) >= 20){
				clearInterval(timer);
				reject('connect: socket timed out');
				return;
			}
			if (!is_open){
				console.log('connect: Another timeout');
				return;
			}
			clearInterval(timer);
			console.log('connect: promise resolved');
			resolve('ready');
		};
		timer = setInterval(check, 100);
	});
};
Socket.prototype.send = function(data_in){
	//Transform number array into ArrayBuffer
	var ab = new ArrayBuffer(data_in.length);
	var dv = new DataView(ab);
	for(var i=0; i < data_in.length; i++){
		dv.setUint8(i, data_in[i]);
	}
	chrome.runtime.sendMessage(appId, 
		{'command':'send',
		 'args':{'data':data_in},
		 'uid':this.uid});
};
Socket.prototype.recv = function(){
	var uid = this.uid;
	return new Promise(function(resolve, reject) {
		var startTime = new Date().getTime();
		var complete_records = [];
		var buf = [];		
		var cancelled = false;
		var timer = setTimeout(function(){
			reject('recv: socket timed out');
			cancelled = true;
		}, 20*1000);
		
		var check = function(){
			if (cancelled) return;
			chrome.runtime.sendMessage(appId, {'command':'recv', 'uid':uid}, function(response){
				if (cancelled) return;
				if (response.data.length > 0){
					buf = [].concat(buf, response.data);
					var rv = check_complete_records(buf);
					complete_records = [].concat(complete_records, rv.comprecs);
					if (! rv.is_complete){
						console.log("check_complete_records failed");
						buf = rv.incomprecs;
						setTimeout(check, 100);
						return;
					}
					clearTimeout(timer);
					console.log('recv promise resolved');
					resolve(complete_records);
					return;
				}
				console.log('Another timeout in recv');
				setTimeout(check, 100);
			});
		};
		check();
	});
};	
Socket.prototype.close = function(){
	chrome.runtime.sendMessage(appId, {'command':'close'});
};


function get_xhr(){
	return new XMLHttpRequest();
}

function openManager(){
	var url = chrome.extension.getURL('content/manager.html');
	//re-focus tab if manager already open
	chrome.tabs.query({}, function(tabs){
		for(var i=0; i < tabs.length; i++){
			if (tabs[i].url.startsWith(url)){
				chrome.tabs.update(tabs[i].id, {active:true});
				return;
			}	
		}	
		chrome.tabs.create({url:url});
	});
}
	
	
function deletePGSG(dir){
	window.webkitRequestFileSystem(window.PERSISTENT, 50*1024*1024, function(fs){
		fs.root.getDirectory(dir, {}, function(dirEntry){
			dirEntry.removeRecursively(function() {
			  console.log('Directory removed.');
				populateTable();
			});
		});
	});
}


function renamePGSG(dir, newname){
	writeFile(dir, 'meta', str2ba(newname), true)
	.then(function(){
		populateTable();
	});
}


function sendMessage(data){
	chrome.runtime.sendMessage({'destination':'manager',
									'data':data});
}


function updateCache(hash){
	if (!(hash.toString() in valid_hashes)){
		valid_hashes.push(hash.toString());
		chrome.storage.local.set({'valid_hashes':valid_hashes});
	}
}


function getModTime(obj){
	return new Promise(function(resolve, reject) {
		obj.getMetadata(function(m){
			var t = m.modificationTime.getTime();
			resolve(t);
		});
	});
}


function isDirectory(obj){
	return obj.isDirectory;
}

function getName(obj){
	return obj.name;
}


function getFullPath(obj){
	return obj.toURL();
}


function getDirEntry(dirName){
	return new Promise(function(resolve, reject) {
		return new Promise(function(resolve, reject) {
			window.webkitRequestFileSystem(window.PERSISTENT, 50*1024*1024, function(fs){
				resolve(fs.root);
			})
		})
		.then(function(rootDirEntry){
			rootDirEntry.getDirectory(dirName, {}, function(dirEntry){
				resolve(dirEntry);
			});
		});
	});
}






function getDirContents(dirName){
	return new Promise(function(resolve, reject) {
		return new Promise(function(resolve, reject) {
			window.webkitRequestFileSystem(window.PERSISTENT, 50*1024*1024, function(fs){
				resolve(fs.root);
			})
		})
		.then(function(rootDirEntry){
			return new Promise(function(resolve, reject) {
				rootDirEntry.getDirectory(dirName, {}, function(dirEntry){
					return resolve(dirEntry);
				});
			});
		})
		.then(function(dirEntry){
			var dirReader = dirEntry.createReader();
			var entries = [];
			
			var readEntries = function() {
				dirReader.readEntries (function(results) {
					if (results.length) {
						//extend entries array
						entries.push.apply(entries, results);
						readEntries();
						return;
					}
					//else finished reading
					resolve(entries);
				});
			};
			readEntries();
		});
	});
}


function getFileContent(dirname, filename){
	return new Promise(function(resolve, reject) {
		var handleError = function(e){
			reject(e);
		};
		
		window.webkitRequestFileSystem(window.PERSISTENT, 5*1024*1024, function(fs){
			fs.root.getDirectory(dirname, {}, function (dirEntry){
				dirEntry.getFile(filename, {}, function(fileEntry){
					fileEntry.file(function(file){
						var reader = new FileReader();
						reader.onloadend = function(e) {
							resolve(ab2ba(this.result));
						};
						reader.readAsArrayBuffer(file);
					});
				}, handleError);
			}, handleError);
		});
	});
}


function sendAlert(alertData){
	chrome.tabs.query({active: true}, function(tabs) {
		if (!tabs[0].url.startsWith("http")){
			//we cannot inject out alert into not http & https URLs, use the ugly alert
			alert("You can only notarize pages which start with https://");
			return;
		}
		chrome.tabs.executeScript(tabs[0].id, {file:"content/sweetalert.min.js"}, function(){
			chrome.tabs.insertCSS(tabs[0].id, {file:"content/sweetalert.css"}, function(){
				chrome.tabs.executeScript(tabs[0].id, {code:"swal("+ JSON.stringify(alertData) +")"});
			});
		});
		
		
		//chrome.tabs.sendMessage(tabs[0].id, {destination:'sweetalert', args:alertData})
	});
}


//Used only for testing - empty the filesystem
function emptyRootDir(){
	window.webkitRequestFileSystem(window.PERSISTENT, 5*1024*1024, function(fs){
		var r = fs.root.createReader();
		r.readEntries(function(results){
			for(var i=0; i < results.length; i++){
				if (!results[i].isDirectory) continue;
				results[i].removeRecursively(function(){});
			}
		});
	});
}


