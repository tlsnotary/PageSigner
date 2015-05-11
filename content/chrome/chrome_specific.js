var testing = false;
var tabs = {};
var appId = "oclohfdjoojomkfddjclanpogcnjhemd"; //id of the helper app
var dl_dir_path = ''; //path to download/pagesigner dir
var is_chrome = true;
var fsRootPath; //path to local storage root, e.g. filesystem:chrome-extension://abcdabcd/persistent


function getPref(value, type){
	return new Promise(function(resolve, reject) {
		chrome.storage.local.get(value, function(items){
			if (!items.hasOwnProperty('first')) resolve("undefined");
			resolve(items[value]);
		});
	});
}


function setPref(pref, type, value){
	return new Promise(function(resolve, reject) {
		chrome.storage.local.set({pref:value}, function(){
			resolve();
		});
	});
}


function import_reliable_sites(){
	var xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function(){
		if (xhr.readyState != 4)
			return;

		if (xhr.responseText) {
			parse_reliable_sites(xhr.responseText);
		}
	};
	xhr.open('get', chrome.extension.getURL('content/pubkeys.txt'), true);
	xhr.send();
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
		var host = x[2];
		x.splice(0,3);
		var tab_url = x.join('/');	
		var headers = '';
		headers += tab.method + " /" + tab_url + " HTTP/1.1" + "\r\n";
		headers += "Host: " + host + "\r\n";
		for (var i = 0; i < tab.requestHeaders.length; i++){
			var h = tab.requestHeaders[i];
			headers += h.name + ": " + h.value + "\r\n";
		}
		if (tab.method == "GET"){
			headers += "\r\n";
		}
		resolve({'headers':headers, 'server':host});
	});
	});
}


function loadBusyIcon(){
	chrome.browserAction.setIcon({path:"content/icon_spin.gif"});
	chrome.browserAction.setPopup({popup:"content/chrome/popup_pleasewait.html"});
}


function loadNormalIcon(){
	chrome.browserAction.setIcon({path:"content/icon128.png"});
	chrome.browserAction.setPopup({popup:"content/chrome/popup.html"});
}


function browser_specific_init(){
	window.webkitRequestFileSystem(window.PERSISTENT, 50*1024*1024, function(fs){
		fsRootPath = fs.root.toURL();
	});
	chrome.storage.local.get('valid_hashes', function(items){
		if (!items.hasOwnProperty('first')) return;
		valid_hashes = items.valid_hashes;
	});
	chrome.runtime.getPlatformInfo(function(p){
		if(p.os === "win"){
			os_win = true;
		}
	}); 
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
			verify_tlsn_and_show_html(data.args.data, true);
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
		else if (data.message === 'viewhtml'){
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


function create_final_html(html_with_headers, session_dir){
	return new Promise(function(resolve, reject) {
		var rv = html_with_headers.split('\r\n\r\n');
		var headers = rv[0];
		var html = rv.splice(1).join('\r\n\r\n'); 
		var dirname = session_dir.split('/').pop();
		writeFile(dirname, 'html.html', ba2ua([].concat([0xef, 0xbb, 0xbf], str2ba(html))))
		.then(function(){
			return writeFile(dirname, 'raw.txt', html_with_headers);
		})
		.then(function(){
			resolve();
		});
	});
}


function getModulus(cert){
	  var c = Certificate.decode(new Buffer(cert), 'der');
		var pk = c.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data;
		var pkba = ua2ba(pk);
		//expected modulus length 256, 384, 512
		var modlen = 256;
		if (pkba.length > 384) modlen = 384;
		if (pkba.length > 512) modlen = 512;
		var modulus = pkba.slice(pkba.length - modlen - 5, pkba.length -5);
		return modulus;
}


function verifyCert(chain){
	return verifyCertChain(chain);
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
							fw.write(new Blob([data]));
						});
					});
				});
			});
		});
	});
}


function writePgsg(pgsg, session_dir, commonName){
	return new Promise(function(resolve, reject) {
		var dirname = session_dir.split('/').pop();
		var name = commonName.replace(/\*\./g,""); 	
		writeFile(dirname, 'pgsg.pgsg', ba2ua(pgsg))
		.then(function(){
			return writeFile(dirname, 'meta', name);
		})
		.then(function(){
			resolve();
		});
	});
}


function openTabs(sdir, commonName){
	//Because Chrome tabs crash when opening html from filesystem:chrome-extension:// URI
	//we first download the file to /Downloads and then open
	var uid = Math.random().toString(36).slice(-10);
	chrome.downloads.setShelfEnabled(false);
	setTimeout(function(){chrome.downloads.setShelfEnabled(true);}, 1000);
	chrome.downloads.download({url:sdir + '/html.html', filename:'pagesigner.tmp.dir/'+uid+'.html'},
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
								if (tab.status != "complete") return;
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
			chrome.webRequest.handlerBehaviorChanged(); //flush in-memory cache
			chrome.webRequest.onBeforeRequest.addListener(function(x){
				console.log('blocking', x.url);
				return {cancel:true};
			}, {tabId:id, urls: ["<all_urls>"]});
			chrome.tabs.reload(id, {bypassCache:true});
			if (typeof(commonName) === "undefined"){
				//view command from manager. No need for notifications et.al
				return;
			}
			var notif_msg = 'PageSigner verified that this page was received from '+commonName+'\r\nTip: right-click on the page if you want to see raw HTML';
			chrome.notifications.create('', {type:'basic', 
											title:'',
											message:notif_msg,
											 iconUrl:'content/icon128.png',
											 priority:2});
			chrome.contextMenus.create({type:'normal',
										title:'View this page from ' + commonName + ' as raw HTML',
										documentUrlPatterns:[path],
										onclick:function(info){
											chrome.tabs.create({url:sdir + '/raw.txt'});
										}});
		};
		
	});
}


function getCommonName(cert){
	var c = Certificate.decode(new Buffer(cert), 'der');
	var fields = c.tbsCertificate.subject.value;
	for (var i=0; i < fields.length; i++){
		if (fields[i][0].type.toString() !== [2,5,4,3].toString()) continue;
		//first 2 bytes are DER-like metadata
		return ba2str(fields[i][0].value.slice(2));
	}
	return 'unknown';
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
	writeFile(dir, 'meta', newname, true)
	.then(function(){
		populateTable();
	});
}


function sendMessage(data){
	if (is_chrome){
		chrome.runtime.sendMessage({'destination':'manager',
									'data':data});
	}
	else {
		
	}
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


