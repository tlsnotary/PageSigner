var mustVerifyCert = true; //set to false during debugging to be able to work with self-signed certs
var portPopup;
var portManager = null;
var notarization_in_progress = false;
var waiting_for_click = false; 
var appId = null; //Chrome uses to send message to external Chrome app. Firefox uses it's own id
var popupError = null; //set to non-null when there is some error message that must be shown
//via the popup
var tabid = 0; //a signal that this is the main window when querying with .getViews()


function sendToPopup(data) {
  if (is_chrome) {
    chrome.runtime.sendMessage(data);
  } else {
    console.log('will postMessage ', data);
    portPopup.postMessage(data);
  }
}


function openChromeExtensions(){
  chrome.tabs.query({url: 'chrome://extensions/*'},
  function(tabs) {
    if (tabs.length == 0) {
      chrome.tabs.create({url: 'chrome://extensions'});
      return;
    }
    chrome.tabs.update(tabs[0].id, {active: true});
  });
}


//Pagesigner's popup has been clicked 
async function popupProcess(){
  if (notarization_in_progress) {
    sendToPopup({
      'destination': 'popup',
      'message': 'notarization_in_progress'
    });
    return;
  }
  if (waiting_for_click) {
    sendToPopup({
      'destination': 'popup',
      'message': 'waiting_for_click'
    });
    return;
  }
  if (!is_chrome) {
    if (popupError) {
      sendToPopup({
        'destination': 'popup',
        'message': 'popup error',
        'data': popupError
      });
      popupError = null;
      loadNormalIcon();
    } else {
      sendToPopup({
        'destination': 'popup',
        'message': 'show_menu'
      });
    }
    return;
  }
  //else{} the checks below are only for Chrome
  //probe a non-existent port, if reject()ed with undefined, then the helper app is not running
  try{
    await new Socket('127.0.0.1', -1).connect();
  }
  catch(error){
    if (error === undefined){
      chrome.runtime.sendMessage({
        'destination': 'popup',
        'message': 'app_not_installed'
      });
      return;
    }
  }
  if (popupError) {
    chrome.runtime.sendMessage({
      'destination': 'popup',
      'message': 'popup error',
      'data': popupError
    });
    popupError = null;
    loadNormalIcon();
  } else {
    chrome.runtime.sendMessage({
      'destination': 'popup',
      'message': 'show_menu'
    });
  }
}


function openFilePicker(){
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/viewer.html#filepicker');
  //Chrome doesnt provide a straightforward was to associate a tab id with a window
  //as a workaround, get all views
  var myTabs = [];
  for (let win of chrome.extension.getViews()){
    if (win.is_file_picker){
      //re-focus an already opened file picker
      chrome.tabs.update(win.tabid, {active: true});
      return;
    }
    myTabs.push(win.tabid)
  }
  console.log(myTabs)

  chrome.tabs.create({url: url},
  async function(t){

    function check(){

      console.log('checking if file picker is ready...')
      setTimeout(async function(){
        var myViews = chrome.extension.getViews();
        //sometimes the View for the newly opened tab may not yet be available 
        //so we must wait a little longer
        var isViewReady = false;
        for (let win of myViews){
          if (myTabs.includes(win.tabid)) continue;
          //found a new tab
          if (typeof(win.showFilePicker) == 'undefined') {
            //viewer.js hasnt yet been loaded into the DOM
            check();
            return;
          }
          isViewReady = true;
          win.showFilePicker()
          win.tabid = t.id;
          var is_testing = await getPref('testing')
          if (is_testing) win.prepare_testing()
        }
        if (! isViewReady){
          check();
        }
      }, 10)

    }
    check();

  })
}


function openManager() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/manager.html');
  //re-focus tab if manager already open
  for (let win of chrome.extension.getViews()){
    if (! win.is_manager) continue;
    chrome.tabs.update(win.tabid, {active: true});
    return;
  }

  chrome.tabs.create({url: url},
  function(t) {

    function check(){
      console.log('checking if manager tab is ready...')
      setTimeout(async function(){
        var isViewReady = false;
        for (let win of chrome.extension.getViews()){
           //sometimes the View for the newly opened tab may not yet be available 
          //so we must wait a little longer
          if (! win.is_manager) continue;
          //found manager window
          isViewReady = true
          win.tabid = t.id
          var is_testing = await getPref('testing')
          if (is_testing){
            win.prepare_testing()
          }
        }
        if (!isViewReady){
          check();
        }
      }, 10)
    }
    check()
  });
}


async function prepareNotarizing(after_click) {
  if (!oracles_intact) {
    sendAlert({
      title: 'PageSigner error',
      text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
    });
    return;
  }

  var clickTimeout = null;

  var active_tab = await new Promise(function(resolve, reject) {
    chrome.tabs.query({active: true}, function(t) {
      resolve(t[0]);
    });
  });

  if (! active_tab.url.startsWith('https://')) {
    sendAlert({
      'title': 'PageSigner error',
      'text': 'You can only notarize pages which start with https://'
    });
    return;
  }

  if (after_click){
    let prefix = is_chrome ? 'webextension/' : '';
    let url = chrome.extension.getURL(prefix + 'content/arrow24.png');
    chrome.browserAction.setIcon({path: url});
    waiting_for_click = true;
    clickTimeout = setTimeout(function() {
      loadNormalIcon();
      waiting_for_click = false;
      sendAlert({
        title: 'PageSigner error.',
        text: 'You haven\'t clicked any https:// links in 30 seconds. Please try again. If this error persists it may mean that the website you are trying to notarize is not compatible with PageSigner.'
      });
    }, 30 * 1000);
  }

  var oBR_details; 
  var oBR_handler = function(details){
    console.log('in onBeforeRequest', details)
    chrome.webRequest.onBeforeRequest.removeListener(oBR_handler);
    oBR_details = details;
  }
  chrome.webRequest.onBeforeRequest.addListener(
    oBR_handler, {
      urls: ["<all_urls>"],
      tabId: active_tab.id,
      types: ["main_frame", "xmlhttprequest"]
      //types: ["main_frame", "sub_frame", "stylesheet", "script", 
      //"image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]
    }, ["requestBody"]);

  var oBSH_details;
  var oBSH_handler = function(details){
      console.log('in onBeforeSendHeaders', details)
      chrome.webRequest.onBeforeSendHeaders.removeListener(oBSH_handler);
      oBSH_details = details; 
      console.log(oBR_details, oBSH_details)
  }
  chrome.webRequest.onBeforeSendHeaders.addListener(
    oBSH_handler, {
      urls: ['<all_urls>'],
      tabId: active_tab.id,
      types: ["main_frame", "xmlhttprequest"]
    }, ["requestHeaders", "extraHeaders"]);


  //wait for the request to pass oBR and oBHS and reach onSendHeaders
  await new Promise(function(resolve, reject) { 
    var oSH_handler = function(details){
      console.log('in onSendHeaders')
      chrome.webRequest.onSendHeaders.removeListener(oSH_handler);
      resolve(details);
    }
    chrome.webRequest.onSendHeaders.addListener(
      oSH_handler, {
        urls: ['<all_urls>'],
        tabId: active_tab.id,
        types: ["main_frame", "xmlhttprequest"]
      })

    //if not Notarize After Click mode,
    //reload current tab in order to trigger the HTTP request
    if (!waiting_for_click) chrome.tabs.reload(active_tab.id);
    //otherwise just wait for the user to click smth and trigger onBeforeRequest
  })

  if (waiting_for_click) {
    clearTimeout(clickTimeout);
    waiting_for_click = false;
  }

  if (oBR_details.url !== oBSH_details.url) return;
  if (oBR_details.requestId !== oBSH_details.requestId) return;
  if (oBR_details.method == 'POST') {
    //POST payload is only available from onBeforeRequest
    oBSH_details['requestBody'] = oBR_details.requestBody;
  }
  var rv = getHeaders(oBSH_details);
  startNotarizing(rv.headers, rv.server, rv.port)
}


function getHeaders(obj) {
  var x = obj.url.split('/');
  var host = x[2].split(':')[0];
  x.splice(0, 3);
  var resource_url = x.join('/');
  var headers = obj.method + " /" + resource_url + " HTTP/1.1" + "\r\n";
  headers += "Host: " + host + "\r\n";
  for (let h of obj.requestHeaders) {
    //we dont want any "br" encoding
    if (h.name == "Accept-Encoding") {
      //h.value = 'gzip, deflate'
      h.value = ''
    }
    headers += h.name + ": " + h.value + "\r\n";
  }
  if (obj.method == "GET") {
    headers += "\r\n";
  } 
  else if (obj.method == 'POST') {
    if (obj.requestBody.raw != undefined) {
      var content = ba2str(ab2ba(obj.requestBody.raw[0].bytes))
    }
    else{
      var keys = Object.keys(obj.requestBody.formData);
      var content = '';
      for (var key of keys) {
        content += key + '=' + obj.requestBody.formData[key] + '&';
      }
      //get rid of the last &
      content = content.slice(0,-1)
      //Chrome doesn't expose Content-Length which chokes nginx
      headers += 'Content-Length: ' + parseInt(content.length) + '\r\n\r\n';
      headers += content;
    }
  }
  var port = 443;
  if (obj.url.split(':').length === 3) {
    //the port is explicitely provided in URL
    port = parseInt(obj.url.split(':')[2].split('/')[0]);
  }
  return {
    'headers': headers,
    'server': host,
    'port': port
  };
}


async function getPGSG(sid){
  var blob = await getSessionBlob(sid);
  return blob.pgsg;
}


async function process_message(data) {
  if (data.destination !== 'extension') return;
  console.log('ext got msg', data);
  switch (data.message){
    case 'rename':
      await renameSession(data.args.dir, data.args.newname);
      var dataarray = await getAllSessions();
      sendSessions(dataarray);
      break;
    case 'delete':
      await deleteSession(data.args.dir);
      var dataarray = await getAllSessions();
      sendSessions(dataarray);
      break;
    case 'import':
      verify_pgsg_and_show_data(data.args.data, true);
      break;
    case 'export':
      let pgsg = await getPGSG(data.args.dir)
      let value = await getSession(data.args.dir)
      sendToManager({'pgsg':JSON.stringify(pgsg), 'name':value.sessionName}, 'export')
      break;
    case 'notarize':
      prepareNotarizing(false);
      break;
    case 'notarizeAfter':
      prepareNotarizing(true);
      break;
    case 'manage':
      openManager();
      break;
    case 'refresh':
      var dataarray = await getAllSessions();
      sendSessions(dataarray);
      break;
    case 'openLink1':
      chrome.tabs.create({url: 'https://www.tlsnotary.org'});
      break;
    case 'donate link':
      chrome.tabs.create({url: 'https://www.tlsnotary.org/#Donate'});
      break;
    case 'viewdata':
      openTab(data.args.dir);
      break;
    case 'viewraw':
      viewRaw(data.args.dir);
      break;
    case 'file picker':
      openFilePicker();
      break;
    case 'openInstallLink':
      chrome.tabs.create({
        url: 'https://chrome.google.com/webstore/detail/pagesigner-helper-app/oclohfdjoojomkfddjclanpogcnjhemd'});
      break;
    case 'openChromeExtensions':
      openChromeExtensions();
      break;
    case 'popup active':
      popupProcess()
      break
  }   
}


//perform browser-specific init first
async function main() {
  if (is_chrome) {
    appId = "oclohfdjoojomkfddjclanpogcnjhemd"; //id of the helper app
    chrome.runtime.onMessage.addListener(function(data) {
      process_message(data);
    });
  } else {
    appId = chrome.runtime.id;
    //console.log('installing listener');
    //Temporary kludge for FF53 to use Ports for communication
    chrome.runtime.onConnect.addListener(function(port) {
      console.log('chrome.runtime.onConnect.addListener with port', port);
      if (port.name == 'popup-to-extension') {
        portPopup = port;
        console.log('in extension port connection from', port.name);
        port.onMessage.addListener(function(data) {
          console.log('in port listener, got', data);
          process_message(data);
        });
      } else if (port.name == 'filepicker-to-extension') {
        port.onMessage.addListener(function(data) {
          console.log('in filepicker-to-extension got data', data);
          if (data.destination !== 'extension') return;
          if (data.message !== 'import') return;
          verify_pgsg_and_show_data(data.args.data, true);
        });
      } else if (port.name == 'notification-to-extension') {
        port.onMessage.addListener(function(data) {
          console.log('in notification-to-extension got data', data);
          if (data.destination !== 'extension') return;
          if (data.message !== 'viewraw') return;
          process_message(data);
        });
      } else if (port.name == 'manager-to-extension') {
        portManager = port;
        port.onMessage.addListener(function(data) {
          console.log('in manager-to-extension got data', data);
          if (data.destination !== 'extension') return;
          process_message(data);
        });
      }
    });
  }
  init();
}


async function init() {
  await init_db();
  var alreadyConverted = await getPref('alreadyConverted');
  if (alreadyConverted != true){
    //will be run only once when Pagesigner 2.1.0 is released
    //converts db's binary pgsgs into json 
    await addNewPreference('alreadyConverted', false)
    await convert_db();
    await setPref('alreadyConverted', true);
  }
  await parse_certs();
  var is_verbose = await getPref('verbose');
  if (is_verbose !== true && !is_chrome) {
		//Firefox pollutes browser window, disable logging
    console.log = function(){};
  }
  chosen_notary = oracles[Math.random() * (oracles.length) << 0];
  var oracle_hash = ba2hex( await sha256( str2ba( JSON.stringify(chosen_notary) ) ) );
  var vo = await getPref('verifiedOracles')
  if (vo.includes(oracle_hash)) {
    oracles_intact = true;
    browser_init_finished = true;
  } else {
    //asynchronously check oracles and if the check fails, sets a global var
    //which prevents notarization session from running
    console.log('oracle not verified');
    return check_oracle(chosen_notary)
    .then(async function success() {
      vo.push(oracle_hash)
      await setPref('verifiedOracles', vo);
      oracles_intact = true;
      browser_init_finished = true;
    })
    .catch(function(err) {
      console.log('caught error', err);
      //query for a new oracle
      //TODO fetch backup oracles list
    });
  }
}


//we can import chrome:// and file:// URL
async function import_resource(filename) {
  var prefix = is_chrome ? 'webextension/' : '';
  var path = chrome.extension.getURL(prefix + 'content/' + filename);
  var resp = await fetch(path)
  var data = await resp.text()
  return data;
}


async function startNotarizing(headers, server, port) {
  loadBusyIcon();
  try{
    let rv = await start_audit(server, port, headers);
    let sessionId = await save_session(rv);
    await showData(sessionId);
  }
  catch (err){
    console.log('There was an error: ' + err);
    if (err === "Server sent alert 2,40") {
      sendAlert({
        title: 'PageSigner error',
        text: 'Pagesigner is not compatible with this website'
      });
    } else {
      sendAlert({
        title: 'PageSigner error',
        text: err
      });
    }
  }
  loadNormalIcon();
}




async function save_session(args) {  

  assert(args.length === 11, "wrong args length");
  var idx = -1;
  var server_certchain = args[idx+=1]
  var rsa_sig = args[idx+=1]
  var client_random = args[idx+=1]
  var server_random = args[idx+=1]
  var ec_pubkey_server = args[idx+=1]
  var server_write_key = args[idx+=1]
  var server_write_IV = args[idx+=1]
  var server_response = args[idx+=1]
  var cleartext = args[idx+=1]
  var notary_signature = args[idx+=1]
  var time = args[idx+=1]

  var pgsg_json = {}
  pgsg_json["title"] = "PageSigner notarization file"
  pgsg_json["version"] = 4
  pgsg_json["certificate chain"] = {}
  for (let [idx, cert] of server_certchain.entries()) {
    let key = 'cert'+idx.toString()
    pgsg_json["certificate chain"][key] = b64encode(cert)
  }
  pgsg_json["server RSA signature over EC pubkey"] = b64encode(rsa_sig)
  pgsg_json['client random'] = b64encode(client_random)
  pgsg_json['server random'] = b64encode(server_random)
  pgsg_json["server EC pubkey"] = b64encode(ec_pubkey_server)
  pgsg_json["server write key"] = b64encode(server_write_key)
  pgsg_json["server write IV"] = b64encode(server_write_IV)
  pgsg_json["server response"] = b64encode(server_response)
  pgsg_json["notary signature"] = b64encode(notary_signature)
  pgsg_json["notarization time"] = b64encode(time)
  pgsg_json["notary name"] = chosen_notary.name
  var pgsg = pgsg_json

  var commonName = getCommonName(server_certchain[0]);
  var creationTime = getTime();
  await createNewSession (creationTime, commonName, chosen_notary.name, cleartext, pgsg, false);
  return creationTime; //creationTime is also a session ID
}


async function showData (sid){
  await openTab(sid);
  var allSessions = await getAllSessions(); 
  sendSessions(allSessions); //refresh manager
}


//convert an old binary-formatted pgsg into a json formatted one
function convertPgsg(data){
  if (ba2str(data.slice(0,1)) == '{') {
    //data is in json already nothing to convert
    return data
  }
  var o = 0; //offset
  if (ba2str(data.slice(o, o += 29)) !== "tlsnotary notarization file\n\n") {
    throw ('wrong header');
  }
  if (data.slice(o, o += 2).toString() !== [0x00, 0x03].toString()) {
    throw ('wrong version');
  }
  var client_random = data.slice(o, o += 32)
  var server_random = data.slice(o, o += 32)
  var chain_serialized_len = ba2int(data.slice(o, o += 3));
  var chain_serialized = data.slice(o, o += chain_serialized_len);
  var rsa_siglen = ba2int(data.slice(o, o += 2));
  var rsa_sig = data.slice(o, o += rsa_siglen);
  var ec_pubkey_server = data.slice(o, o += 65)
  var ec_pubkey_client = data.slice(o, o += 65);
  var server_reply_len = ba2int(data.slice(o, o += 4));
  var server_response = data.slice(o, o += server_reply_len);
  var notary_signature_len = ba2int(data.slice(o, o += 1));
  var notary_signature = data.slice(o, o += notary_signature_len);
  var ec_privkey = data.slice(o, o += 32);
  var time = data.slice(o, o += 4);
  assert(data.length === o, 'invalid .pgsg length');

  o = 0;
  var chain = [];
  while (o < chain_serialized.length) {
    var len = ba2int(chain_serialized.slice(o, o += 3));
    var cert = chain_serialized.slice(o, o += len);
    chain.push(cert);
  }

  var pgsg_json = {}
  pgsg_json["title"] = "PageSigner notarization file"
  pgsg_json["version"] = 3
  pgsg_json["client random"] = b64encode(client_random)
  pgsg_json["server random"] = b64encode(server_random)
  pgsg_json["certificate chain"] = {}
  for (let [idx, cert] of chain.entries()) {
    let key = 'cert'+idx.toString()
    pgsg_json["certificate chain"][key] = b64encode(cert)
  }
  pgsg_json["server RSA signature over EC pubkey"] = b64encode(rsa_sig)
  pgsg_json["server EC pubkey"] = b64encode(ec_pubkey_server)
  pgsg_json["client EC pubkey"] = b64encode(ec_pubkey_client)
  pgsg_json["server response"] = b64encode(server_response)
  pgsg_json["notary signature"] = b64encode(notary_signature)
  pgsg_json["client EC privkey"] = b64encode(ec_privkey)
  pgsg_json["notarization time"] = b64encode(time)
  pgsg_json["notary name"] = "tlsnotarygroup8"
  var pgsg = str2ba(JSON.stringify(pgsg_json))
  return pgsg
}


async function verifyPgsg(json){
  if (json['version'] == 3){
    return await verifyPgsgV3(json);
  }
  else if (json['version'] == 4){
    return await verifyPgsgV4(json);
  }
  else {
    throw ('Unrecognized version of the imported pgsg file.')
  }
}


//pgsg is in json
async function verifyPgsgV4(json) {
  var server_write_key = b64decode(json['server write key'])
  var server_write_IV = b64decode(json['server write IV'])
  var chain = []
  var certNumber = Object.keys(json['certificate chain']).length
  for (var i=0; i<certNumber; i++){
    let key = 'cert' + i.toString()
    chain.push(b64decode(json['certificate chain'][key]))
  }
  var rsa_sig = b64decode(json['server RSA signature over EC pubkey'])
  var client_random = b64decode(json['client random'])
  var server_random = b64decode(json['server random'])
  var ec_pubkey_server = b64decode(json['server EC pubkey']) 
  var server_response = b64decode(json['server response'])
  var notary_signature = b64decode(json['notary signature'])
  var time = b64decode(json['notarization time'])
  var notaryName = json["notary name"]
  var notary;
  if (notaryName == oracle.name){
    notary = oracle;
  }
  else{
    var rv = await verifyOldOracle(notaryName);
    if (rv.result == true){
      notary = rv.oracle;
    }
    else{
      throw('unrecognized oracle in the imported file')
    }
  }
  
  var seconds = ba2int(time)
  var date = new Date(seconds*1000)
  var commonName = getCommonName(chain[0]);
  var vcrv = await verifyChain(chain, date); 
  if (vcrv[0] != true) {
    throw ('certificate verification failed');
  }
  var rv = await verifyECParamsSig(chain[0], ec_pubkey_server, rsa_sig, client_random, server_random)
  if (rv != true){
    throw ('EC parameters signature verification failed');
  }

  var commit_hash = await sha256(server_response)
  //check notary server signature
  var signed_data_ba = await sha256([].concat(ec_pubkey_server, server_write_key, server_write_IV, commit_hash, time))
  assert(await verifyNotarySig(notary_signature, notary.pubkeyPEM, signed_data_ba) == true)
  //aesgcm decrypt the data
  var cleartext = await decrypt_tls_response (server_response, server_write_key, server_write_IV)
  var dechunked = dechunk_http(ba2str(cleartext))
  var ungzipped = gunzip_http(dechunked)
  return [ungzipped, commonName, notaryName];
}




//pgsg is in json
async function verifyPgsgV3(json) {
  var client_random = b64decode(json['client random'])
  var server_random = b64decode(json['server random'])
  var chain = []
  var certNumber = Object.keys(json['certificate chain']).length
  for (var i=0; i<certNumber; i++){
    let key = 'cert' + i.toString()
    chain.push(b64decode(json['certificate chain'][key]))
  }
  var rsa_sig = b64decode(json['server RSA signature over EC pubkey'])
  var ec_pubkey_server = b64decode(json['server EC pubkey']) 
  var ec_pubkey_client = b64decode(json['client EC pubkey'])
  var server_response = b64decode(json['server response'])
  var notary_signature = b64decode(json['notary signature'])
  var ec_privkey = b64decode(json['client EC privkey'])
  var time = b64decode(json['notarization time'])
  var notaryName = json["notary name"]
  var notary;
  if (notaryName == oracle.name){
    notary = oracle;
  }
  else{
    var rv = await verifyOldOracle(notaryName);
    if (rv.result == true){
      notary = rv.oracle;
    }
    else{
      throw('unrecognized oracle in the imported file')
    }
  }
  
  var seconds = ba2int(time)
  var date = new Date(seconds*1000)
  var commonName = getCommonName(chain[0]);
  var vcrv = await verifyChain(chain, date); 
  if (vcrv[0] != true) {
    throw ('certificate verification failed');
  }
  var rv = await verifyECParamsSig(chain[0], ec_pubkey_server, rsa_sig, client_random, server_random)
  if (rv != true){
    throw ('EC parameters signature verification failed');
  }

  //calculate pre-master secre
  var ECpubkey_CryptoKey = await crypto.subtle.importKey(
    "raw",
     ba2ab(ec_pubkey_server),
    {name: 'ECDH', namedCurve:'P-256'},
    true,
    []);

  var ECprivkey_CryptoKey = await crypto.subtle.importKey(
    "jwk",
    {
    "crv":"P-256",
    "d": b64urlencode(ec_privkey),
    "ext":true,
    "key_ops":["deriveKey","deriveBits"],
    "kty":"EC",
    "x": b64urlencode(ec_pubkey_client.slice(1,33)),
    "y": b64urlencode(ec_pubkey_client.slice(33,65))
    },
    {   
    name: "ECDH",
    namedCurve: "P-256",
    },
    true, 
    ["deriveBits"]
  )

  var keys = await getExpandedKeys (ECpubkey_CryptoKey, ECprivkey_CryptoKey,
     client_random, server_random)
  var server_write_key = keys[1]
  var server_write_IV = keys[3]
  console.log('server_write_key, server_write_IV', server_write_key, server_write_IV)
  
  var commit_hash = await sha256(server_response)
  //check notary server signature
  var signed_data_ba = await sha256([].concat(ec_privkey, ec_pubkey_server, commit_hash, time))
  assert(await verifyNotarySig(notary_signature, notary.pubkeyPEM, signed_data_ba) == true)
  //aesgcm decrypt the data
  var cleartext = await decrypt_tls_response (server_response, server_write_key, server_write_IV)
  var dechunked = dechunk_http(ba2str(cleartext))
  var ungzipped = gunzip_http(dechunked)
  return [ungzipped, commonName, notaryName];
}


//imported_data is ba
async function verify_pgsg_and_show_data(imported_data, create) {
  try {
    //convert old binary format (if any) to json
    imported_data = convertPgsg(imported_data)
    var json = JSON.parse(ba2str(imported_data))
    var a = await verifyPgsg(json);
  } catch (e) {
    sendAlert({
      title: 'PageSigner failed to import file',
      text: 'The error was: ' + e
    });
    return;
  }
  if (!create) return;
  var cleartext = a[0];
  var commonName = a[1];
  var notaryName = a[2]
  var creationTime = getTime();
  await createNewSession (creationTime, commonName, notaryName, cleartext, json, true)
  await openTab(creationTime);
  var allSessions = await getAllSessions();
  sendSessions(allSessions); //refresh manager
}


async function openTab(sid) {
  var data = await getSession(sid);
  var blob = await getSessionBlob(sid);
  if (data === null) {throw('failed to get index', sid)}
  var commonName = data.serverName
  var cleartext = blob.cleartext

  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/viewer.html');
  await chrome.webRequest.handlerBehaviorChanged(); //flush the in-memory cache

  //reuse tab if viewer was already open because we were importing file
  //this tab must be still active
  var active_tab = await new Promise(function(resolve, reject) {
    chrome.tabs.query({active: true}, function(t) {
      resolve(t[0]);
    });
  })
  //check if there is a file picker among our views
  var isImportTab = false;
  var myViews = chrome.extension.getViews()
  for (let win of myViews){
    if (win.tabid == active_tab.id && win.is_file_picker)
      isImportTab = true;
  }

  //open a new tab and store the tabid inside a Window object
  if (!isImportTab){
    var myTabs = []
    var myViews = chrome.extension.getViews();
    for (let win of myViews ){
      myTabs.push(win.tabid)
    }

    var newtab = await new Promise(function(resolve, reject) {
      chrome.tabs.create({url: url},
      function(t) {
        resolve(t)})
    });

    await new Promise(function(resolve, reject) {

      function check(){
        console.log('checking if tab is ready...')
        setTimeout(async function(){
          var myViews = chrome.extension.getViews();
          //sometimes the View for the newly opened tab may not yet be available 
          //so we must wait a little longer
          var isViewReady = false;
          for (let win of myViews){
            if (myTabs.includes(win.tabid)) continue;
            //found a new viewer tab
            if (typeof(win.main) == 'undefined') {
              //viewer.js hasnt yet been loaded into the DOM
              check();
              return;
            }
            isViewReady = true;
            win.tabid = newtab.id;
            resolve();
          }
          if (! isViewReady){
            check();
          }
        }, 10)
      }
      check();

    });
  }

  //the tab is either an already opened import tab or a fully-loaded new viewer tab
  //We already checked that the new viewer's tab DOM was loaded. Proceed to send the data
  chrome.runtime.sendMessage({
    destination: 'viewer',
    data: cleartext,
    sessionId: sid,
    type: 'unknown',
    serverName: commonName
  });
}


async function viewRaw(sid) {
  var data = await getSession(sid)
  var blob = await getSessionBlob(sid)
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/viewer.html');
  //remember my Views which are already open
  var myTabs = []
  var myViews = chrome.extension.getViews();
  for (let win of myViews ){
    myTabs.push(win.tabid)
  }
  //open my tab
  var newtab = await new Promise(function(resolve, reject) {
    chrome.tabs.create({url: url},
    function(t) {
      resolve(t)})
  });
  //check that my tab's view is available and its DOM loaded
  await new Promise(function(resolve, reject) {

    function check(){
      console.log('checking if raw viewer tab is ready...')
      setTimeout(async function(){
        var myViews = chrome.extension.getViews();
        //sometimes the View for the newly opened tab may not yet be available 
        //so we must wait a little longer
        var isViewReady = false;
        for (let win of myViews){
          if (myTabs.includes(win.tabid)) continue;
          //found a new viewer tab
          if (typeof(win.main) == 'undefined') {
            //viewer.js hasnt yet been loaded into the DOM
            check();
            return;
          }
          isViewReady = true;
          win.tabid = newtab.id;
          resolve();
        }
        if (! isViewReady){
          check();
        }
      }, 10)
    }
    check();

  });
  chrome.runtime.sendMessage({
    destination: 'viewer',
    data: blob.cleartext,
    type: 'raw',
    sessionId: sid,
    serverName: data.serverName
  });

}


function sendSessions(sessions) {
  var rows = []
  for (let session of sessions){
    var verifier;
    if (session.notaryName == undefined){
      verifier = 'tlsnotarygroup8'
    }
    else {
      verifier = session.notaryName;
    }
    rows.push({
      'sessionName': session.sessionName,
      'serverName': session.serverName,
      'is_imported': session.is_imported,
      'verifier': verifier,
      'creationTime': session.creationTime,
    });
  }
  sendToManager(rows);
}


function sendToManager(data, command) {
  console.log('sending sendToManager ', data);
  if (is_chrome) {
    if (!command) command = 'payload'; //commands can be: payload, export
    assert(['payload', 'export'].includes(command))
    chrome.runtime.sendMessage({
      'destination': 'manager',
      'command': command,
      'payload': data
    });
  } else {
    console.log('will use portManager ', portManager);
    //the manager may not have loaded yet
    function do_send() {
      console.log('do_send.count', do_send.count);
      do_send.count++;
      if (do_send.count > 30) return;
      if (!portManager) { //null if manager was never active
        setTimeout(do_send, 100);
      } else {
        portManager.postMessage({
          'destination': 'manager',
          'payload': data
        });
      }
    }
    do_send.count = 0;
    do_send();
  }
}


function sendAlert(alertData) {
  var prefix = is_chrome ? 'webextension/' : '';
  //for some pages we cant inject js/css, use the ugly alert
  function uglyAlert(alertData) {
    var url = chrome.extension.getURL(prefix + 'content/icon_error.png');
    chrome.browserAction.setIcon({
      path: url
    });
    popupError = alertData;
  }

  chrome.tabs.query({active: true},
  function(tabs) {
    if (chrome.extension.lastError) {
      uglyAlert(alertData);
      return;
    }
    chrome.tabs.executeScript(tabs[0].id, {file: (prefix + 'content/sweetalert.min.js')},
    function() {
      if (chrome.extension.lastError) {
        uglyAlert(alertData);
        return;
      }
      chrome.tabs.insertCSS(tabs[0].id, {file: (prefix + 'content/sweetalert.css')},
      function() {
        if (chrome.extension.lastError) {
          uglyAlert(alertData);
          return;
        }
        chrome.tabs.executeScript(tabs[0].id, {code: "swal(" + JSON.stringify(alertData) + ")"});
        if (chrome.extension.lastError) {
          uglyAlert(alertData);
          return;
        }
      });
    });
  });
}


function loadBusyIcon() {
  notarization_in_progress = true

  var context=document.createElement('canvas').getContext('2d');
  var start = new Date();
  var lines = 16,
  cW = 40,
  cH = 40;

  var interval = setInterval(function() {
    if (!notarization_in_progress) {
      clearInterval(interval)
      return;
    }
    var rotation = parseInt(((new Date() - start) / 1000) * lines) / lines;
    context.save();
    context.clearRect(0, 0, cW, cH);
    context.translate(cW / 2, cH / 2);
    context.rotate(Math.PI * 2 * rotation);
    for (var i = 0; i < lines; i++) {
      context.beginPath();
      context.rotate(Math.PI * 2 / lines);
      context.moveTo(cW / 10, 0);
      context.lineTo(cW / 4, 0);
      context.lineWidth = cW / 30;
      context.strokeStyle = 'rgba(0, 0, 0,' + i / lines + ')';
      context.stroke();
    }

  var imageData = context.getImageData(10, 10, 19, 19);
    chrome.browserAction.setIcon({
      imageData: imageData
    });

  context.restore();
  }, 1000 / 15);

}


function loadNormalIcon() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/icon.png');
  chrome.browserAction.setIcon({path: url});
  notarization_in_progress = false;
}


//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
if (typeof(window) != 'undefined') {
  //only run main() in browser environment
  main();
}

if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    save_session,
    verifyPgsg
  }
}