var script_exception;
try {	
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
var random_uid; //we get a new uid for each notarized page
var reliable_sites = []; //read from content/pubkeys.txt
var previous_session_start_time; // used to make sure user doesnt exceed rate limiting
var verbose = false; //trigger littering of the browser console
var chosen_notary;


function openManager(){
	var t = gBrowser.addTab("chrome://pagesigner/content/manager.xhtml");
	gBrowser.selectedTab = t;
	
}

function savePGSGFile(existing_file){
    var nsIFilePicker = Ci.nsIFilePicker;
	var fp = Cc["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
	fp.init(window, "Save your notification file", nsIFilePicker.modeSave);
	//don't set the display directory; leave as default
	var rv = fp.show();
	if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
		var path = fp.file.path;
		//write the file
		let promise = OS.File.copy(existing_file, fp.file.path);
		promise.then(function(){
			log("File write OK");
		},
		function (e){
			log("Caught error writing file: "+e);
		}
		);
   }
}




function init(){
	//sometimes gBrowser is not available
	if (gBrowser === null || typeof(gBrowser) === "undefined"){
		gBrowser = win.gBrowser;
		setTimeout(init, 100);
		return;
	}
	
	var branch = Services.prefs.getBranch("extensions.pagesigner.");
	if (branch.prefHasUserValue('verbose')){
		if (branch.getBoolPref('verbose') === true){
			verbose = true;	
		}
	}
	
	//check if user wants to use a fallback
	branch = Services.prefs.getBranch("extensions.pagesigner.");
	if (branch.prefHasUserValue('fallback')){
		oracles_intact = true;
		//TODO this should be configurable, e.g. choice from list
		//or set in prefs
		chosen_notary = pagesigner_servers[1];
	}
	else {
		chosen_notary = oracles[Math.random()*(oracles.length) << 0];
		var oracle_hash = ba2hex(sha256(JSON.stringify(chosen_notary)));
		branch = Services.prefs.getBranch("extensions.pagesigner.verifiedOracles.");
		var was_oracle_verified = false;
		if (branch.prefHasUserValue(oracle_hash)){
			if (branch.getBoolPref(oracle_hash) === true){
				was_oracle_verified = true;	
			}
		}
		if (! was_oracle_verified){
			//async check oracles and if the check fails, sets a global var
			//which prevents notarization session from running
			log('oracle not verified');
			var main_pubkey = {pubkey:''};
			check_oracle(chosen_notary.main, 'main', main_pubkey).
			then(function(){
				check_oracle(chosen_notary.sig, 'sig',  main_pubkey);
			}).
			then(function success(){
				branch.setBoolPref(oracle_hash, true);
				oracles_intact = true;
			}).
			catch(function(err){
				log('caught error', err);
				//query for a new oracle
				//TODO fetch backup oracles list
			});
		}
		else {
			oracles_intact = true;
		}
	}
	import_reliable_sites();
	startListening();
}


function import_reliable_sites(){
	var pubkey_path = thisaddon.getResourceURI("content/pubkeys.txt").path;
	OS.File.read(pubkey_path, { encoding: "utf-8" }).then(
	  function onSuccess(text) {
		var lines = text.split('\n');
		var name = "";
		var expires = "";
		var modulus = [];
		var i = -1;
		var x;
		var mod_str;
		var line;
		while (true){
			i += 1;
			if (i >= lines.length){
				break;
			}
			x = lines[i];
			if (x.startsWith('#')){
				continue;
			}
			else if (x.startsWith('Name=')){
				name = x.slice('Name='.length);
			}
			else if (x.startsWith('Expires=')){
				expires = x.slice('Expires='.length);
			}
			else if (x.startsWith('Modulus=')){
				mod_str = '';
				while (true){
					i += 1;
					if (i >= lines.length){
						break;
					}
					line = lines[i];
					if (line === ''){
						break;
					}
					mod_str += line;
				}
				modulus = [];
				var bytes = mod_str.split(' ');
				for (var j=0; j < bytes.length; j++){
					if (bytes[j] === ''){
						continue;
					}
					modulus.push( hex2ba(bytes[j])[0] );
				}
				//Don't use pubkeys which expire less than 3 months from now
				var ex = expires.split('/');
				var extime = new Date(parseInt(ex[2]), parseInt(ex[0])-1, parseInt(ex[1]) ).getTime();
				var now = new Date().getTime();
				if ( (extime - now) < 1000*60*60*24*90){
					continue;
				}
				reliable_sites.push( {'name':name, 'expires':expires, 'modulus':modulus} );		
			}
		}
	  }
	);
}


function startListening(){
//from now on, we will check the security status of all loaded tabs
//and store the security status in a lookup table indexed by the url.
    gBrowser.addProgressListener(myListener);
	Services.obs.addObserver(httpRequestBlocker, "http-on-modify-request", false);
}


//callback is used in testing to signal when this page's n10n finished
function startNotarizing(callback){
	if (! oracles_intact){
		alert('Cannot notarize because something is wrong with PageSigner server. Please try again later');
		return;
	}
    var audited_browser = gBrowser.selectedBrowser;
    var tab_url_full = audited_browser.contentWindow.location.href;
    
    //remove hashes - they are not URLs but are used for internal page mark-up
    sanitized_url = tab_url_full.split("#")[0];
    
    if (!sanitized_url.startsWith("https://")){
		alert('"ERROR You can only audit pages which start with https://');
		return;
    }
    //XXX this check is not needed anymore
    if (dict_of_status[sanitized_url] != "secure"){
	alert("The page does not have a valid SSL certificate. Refresh the page and then try to notarize it again");
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
	
	eachWindow(unloadFromWindow);
	icon =  "chrome://pagesigner/content/icon_spin.gif";
	eachWindow(loadIntoWindow);
	  
	var modulus;
	var certsha256;
	get_certificate(server).then(function(cert){
		log('got certificate');
		var cert_obj = getCertObject(cert);
		if (! verifyCert(cert_obj)){
			alert("This website cannot be audited by PageSigner because it presented an untrusted certificate");
			return;
		}
		modulus = getModulus(cert_obj);
		certsha256 = sha256(cert);
		random_uid = Math.random().toString(36).slice(-10);
		previous_session_start_time = new Date().getTime();
		//loop prepare_pms 10 times until succeeds
		return new Promise(function(resolve, reject) {
			var tries = 0;
			var loop = function(resolve, reject){
				tries += 1;
				prepare_pms(modulus).then(function(args){
					resolve(args);
				}).catch(function(error){
					log('caught error', error);
					if (error.startsWith('Timed out')){
						reject(error);
						return;
					}
					if (error != 'PMS trial failed'){
						reject('in prepare_pms: caught error ' + error);
						return;
					}
					if (tries == 10){
						reject('Could not prepare PMS after 10 tries');
						return;
					}
					//else PMS trial failed
					loop(resolve, reject);
				});
			};
			loop(resolve, reject);
		});
	})
	.then(function(args){
		return start_audit(modulus, certsha256, server, headers, args[0], args[1], args[2]);
		
	})
	.then(function(args2){
		return save_session_and_open_html(args2, server);
	})
	.then(function(){
		//testing only
		if (testing){
			callback();
		}
		eachWindow(unloadFromWindow);
		icon = "chrome://pagesigner/content/icon.png";
		eachWindow(loadIntoWindow);
	})
	.catch(function(err){
	 //TODO need to get a decent stack trace
	 	eachWindow(unloadFromWindow);
		icon =  "chrome://pagesigner/content/icon.png";
		eachWindow(loadIntoWindow);
		log('There was an error: ' + err);
		if (err.startsWith('Timed out waiting for notary server to respond') &&
			((new Date().getTime() - previous_session_start_time) < 60*1000) ){
			alert ('You are signing pages way too fast. Please retry in 60 seconds.');
		}
		else {
			alert('There was an error: ' + err);
		}
	});
}


//create the final html that prover and verifier will see in the tab and return 
//its path.
function create_final_html(html_with_headers, server_name, is_imported){
	if (typeof(is_imported) === "undefined"){
		is_imported = false;
	}
	var rv = html_with_headers.split('\r\n\r\n');
	var headers = rv[0];
	var html = rv[1]; 
	var localDir = getPGSGdir();
	var time = getTime();
	var imported_str = "";
	if (is_imported){
		imported_str = "-IMPORTED";
	}
	localDir.append(time+'-'+server_name+imported_str); 
	localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);

	var path_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	var raw_response = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
	path_html.initWithPath(localDir.path);
	path_html.append('html.html');
	 //see "Byte order mark"
	return OS.File.writeAtomic(path_html.path, ba2ua([0xef, 0xbb, 0xbf]))
	.then(function(){
		return OS.File.writeAtomic(path_html.path, ba2ua(str2ba(html)));
	})
	.then(function(){
		raw_response.initWithPath(localDir.path);
		raw_response.append('raw.txt');
		return OS.File.writeAtomic(raw_response.path, ba2ua([0xef, 0xbb, 0xbf]));
	})
	.then(function(){
		return OS.File.writeAtomic(raw_response.path, ba2ua(str2ba(html_with_headers)));
	})
	.then(function(){
		return localDir;
	});
}

function save_session_and_open_html(args, server){
	assert (args.length === 18, "wrong args length");
	var cipher_suite = args[0];
	var client_random = args[1];
	var server_random = args[2];
	var pms1 = args[3];
	var pms2 = args[4];
	var server_cert_length = args[5];
	var server_cert = args[6];
	var tlsver = args[7];
	var initial_tlsver = args[8];
	var fullresp_length = args[9];
	var fullresp = args[10];
	var IV_after_finished_length = args[11];
	var IV_after_finished = args[12];
	var waxwing_webnotary_modulus_length = args[13];
	var signature = args[14];
	var commit_hash = args[15];
	var waxwing_webnotary_modulus = args[16];
	var html_with_headers = args[17];

	var commonName = getCertObject(server_cert).commonName;
	var localDir;
	create_final_html(html_with_headers, commonName)
	.then(function(dir){
		localDir = dir;
		var path_pgsg = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
		path_pgsg.initWithPath(localDir.path);
		path_pgsg.append(commonName+'.pgsg');
		return OS.File.writeAtomic(path_pgsg.path, ba2ua([].concat(
			str2ba('tlsnotary notarization file\n\n'),
			[0x00, 0x01],
			bi2ba(cipher_suite, {'fixed':2}),
			client_random,
			server_random,
			pms1,
			pms2,
			bi2ba(server_cert_length, {'fixed':3}),
			server_cert,
			tlsver,
			initial_tlsver,
			bi2ba(fullresp_length, {'fixed':8}),
			fullresp,
			bi2ba(IV_after_finished_length, {'fixed':2}),
			IV_after_finished,
			bi2ba(waxwing_webnotary_modulus_length, {'fixed':2}),
			signature,
			commit_hash,
			waxwing_webnotary_modulus
		)));
	})
	.then(function(){
		var final_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
		final_html.initWithPath(localDir.path);
		final_html.append('html.html');
		var raw = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
		raw.initWithPath(localDir.path);
		raw.append('raw.txt');
		var t = gBrowser.addTab(final_html.path);
		block_urls.push(final_html.path);
		gBrowser.selectedTab = t;
		install_notification(t, commonName, raw.path);
	});
}

function verify_tlsn(imported_data, from_past){
var data = ua2ba(imported_data);
	var offset = 0;
	if (ba2str(data.slice(offset, offset+=29)) !== "tlsnotary notarization file\n\n"){
		throw('wrong header');
	}
	if(data.slice(offset, offset+=2).toString() !== [0x00, 0x01].toString()){
		throw('wrong version');
	}
	var cs = ba2int(data.slice(offset, offset+=2));
	var cr = data.slice(offset, offset+=32);
	var sr = data.slice(offset, offset+=32);
	var pms1 = data.slice(offset, offset+=24);
	var pms2 = data.slice(offset, offset+=24);
	var cert_len = ba2int(data.slice(offset, offset+=3));
	var cert = data.slice(offset, offset+=cert_len);
	var tlsver = data.slice(offset, offset+=2);
	var tlsver_initial = data.slice(offset, offset+=2);
	var response_len = ba2int(data.slice(offset, offset+=8));
	var response = data.slice(offset, offset+=response_len);
	var IV_len = ba2int(data.slice(offset, offset+=2));
	var IV = data.slice(offset, offset+=IV_len);
	var sig_len = ba2int(data.slice(offset, offset+=2));
	var sig = data.slice(offset, offset+=sig_len);
	var commit_hash = data.slice(offset, offset+=32);
	var notary_pubkey = data.slice(offset, offset+=sig_len);
	assert (data.length === offset, 'invalid .pgsg length');
	var cert_obj = getCertObject(cert);
	var commonName = cert_obj.commonName;
	//verify cert
	if (!verifyCert(cert_obj)){
		throw ('certificate verification failed');
	}
	var modulus = getModulus(cert_obj);
	//verify commit hash
	if (sha256(response).toString() !== commit_hash.toString()){
		throw ('commit hash mismatch');
	}
	//verify sig
	var signed_data = sha256([].concat(commit_hash, pms2, modulus));
	var signing_key;
	if (from_past){signing_key = notary_pubkey;}
	else {signing_key = chosen_notary.sig.modulus;}
	if (!verify_commithash_signature(signed_data, sig, signing_key)){
		throw ('notary signature verification failed');
	}
	
	//decrypt html and check MAC
	var s = new TLSNClientSession();
	s.__init__();
	s.unexpected_server_app_data_count = response.slice(0,1);
	s.chosen_cipher_suite = cs;
	s.client_random = cr;
	s.server_random = sr;
	s.auditee_secret = pms1.slice(2, 2+s.n_auditee_entropy);
	s.initial_tlsver = tlsver_initial;
	s.tlsver = tlsver;
	s.server_modulus = modulus;
	s.set_auditee_secret();
	s.auditor_secret = pms2.slice(0, s.n_auditor_entropy);
	s.set_auditor_secret();
	s.set_master_secret_half(); //#without arguments sets the whole MS
	s.do_key_expansion(); //#also resets encryption connection state
	s.store_server_app_data_records(response.slice(1));
	s.IV_after_finished = IV;
	s.server_connection_state.seq_no += 1;
	s.server_connection_state.IV = s.IV_after_finished;
	html_with_headers = decrypt_html(s);
	return [html_with_headers,commonName,imported_data, notary_pubkey];
}

function verify_tlsn_and_show_html(path, create){
	OS.File.read(path).then( function(imported_data){
		return verify_tlsn(imported_data);
	}).then(function (a){
	if (create){
		var localDir;
		var html_with_headers = a[0];
		var commonName = a[1];
		var imported_data = a[2];
		create_final_html(html_with_headers, commonName, true)
		.then(function(dir){
			localDir = dir;
			var path_pgsg = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
			path_pgsg.initWithPath(localDir.path);
			path_pgsg.append(commonName+'.pgsg');
			return OS.File.writeAtomic(path_pgsg.path, imported_data);
		})
		.then(function(){
			var final_html = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
			final_html.initWithPath(localDir.path);
			final_html.append('html.html');
			var raw = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
			raw.initWithPath(localDir.path);
			raw.append('raw.txt');
			block_urls.push(final_html.path);
			var t = gBrowser.addTab(final_html.path);
			gBrowser.selectedTab = t;
			install_notification(t, commonName, raw.path);
		});
	}
	}).catch( function(error){
		log("got error in vtsh: "+error);
	});
}

//cert is an array of numbers
//return a cert object 
function getCertObject(cert){
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert_obj = certdb.constructX509FromBase64(b64encode(cert));
	return cert_obj;
}


//extracts modulus from PEM certificate
function getModulus(cert_obj){
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
function verifyCert(cert_obj){
	const nsIX509Cert = Ci.nsIX509Cert;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
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
		var icon = 'chrome://pagesigner/content/icon.png';
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


function toggle_offline(){
	window.document.getElementById("goOfflineMenuitem").doCommand();
}

//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
init();


} catch (e){
	script_exception = e;
}
