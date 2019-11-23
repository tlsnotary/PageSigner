var chosen_notary;
var browser_init_finished = false; //signal to test script when it can start
var mustVerifyCert = true; //set to false during debugging to be able to work with self-signed certs
var portPopup;
var portManager = null;
var notarization_in_progress = false;
var waiting_for_click = false; 
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
var appId = null; //Chrome uses to send message to external Chrome app. Firefox uses it's own id
var popupError = null; //set to non-null when there is some error message that must be shown
//via the popup
var testing = false;
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
function popupProcess(){
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
  chrome.management.get(appId, function(info) {
    if (!info) {
      chrome.runtime.sendMessage({
        'destination': 'popup',
        'message': 'app_not_installed'
      });
      return;
    }
    if (info.enabled === false) {
      chrome.runtime.sendMessage({
        'destination': 'popup',
        'message': 'app_disabled'
      });
      return;
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
  });
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
    setTimeout(async function(){
      var myViews = chrome.extension.getViews();
      for (let win of myViews){
        if (myTabs.includes(win.tabid)) continue;
        //found a new tab
        win.showFilePicker()
        win.tabid = t.id;
        var is_testing = await getPref('testing')
        if (is_testing) win.prepare_testing()
      }
    }, 100)
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
    setTimeout(async function(){
      for (let win of chrome.extension.getViews()){
        if (! win.is_manager) continue;
        //found manager window
        win.tabid = t.id
        var is_testing = await getPref('testing')
        if (is_testing){
          win.prepare_testing()
        }
      }
    }, 100)
  });
}


async function prepareNotarizing(after_click) {
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
      verify_tlsn_and_show_data(data.args.data, true);
      break;
    case 'export':
      let pgsg = await getPGSG(data.args.dir)
      let value = await getSession(data.args.dir)
      sendToManager({'pgsg':pgsg, 'name':value.sessionName}, 'export')
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
          verify_tlsn_and_show_data(data.args.data, true);
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
  if (!oracles_intact) {
    //NotarizeAfterClick already changed the icon at this point, revert to normal
    loadNormalIcon();
    sendAlert({
      title: 'PageSigner error',
      text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
    });
    return;
  }
  loadBusyIcon();
  try{
    let rv = await start_audit(server, port, headers)
    await save_session_and_open_data(rv, server)
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


async function save_session_and_open_data(args, server) {  
  assert(args.length === 11, "wrong args length");
  var idx = -1;
  var client_random = args[idx+=1]
  var server_random= args[idx+=1]
  var server_certchain = args[idx+=1]
  var rsa_sig = args[idx+=1]
  var ec_pubkey_server = args[idx+=1]
  var ec_pubkey_client = args[idx+=1]
  var server_reply = args[idx+=1]
  var cleartext = args[idx+=1]
  var notary_signature = args[idx+=1]
  var ec_privkey = args[idx+=1]
  var time = args[idx+=1]

  var server_chain_serialized = []; //3-byte length prefix followed by cert
  for (let cert of server_certchain) {
    server_chain_serialized = [].concat(server_chain_serialized,
      bi2ba(cert.length, {'fixed': 3}), cert);
  }

  var pgsg = [].concat(
    str2ba('tlsnotary notarization file\n\n'), [0x00, 0x03],
    client_random,
    server_random,
    bi2ba(server_chain_serialized.length, {'fixed': 3}),
    server_chain_serialized,
    bi2ba(rsa_sig.length, {'fixed': 2}),
    rsa_sig,
    ec_pubkey_server,
    ec_pubkey_client,
    bi2ba(server_reply.length, {'fixed': 4}),
    server_reply,
    bi2ba(notary_signature.length, {'fixed': 1}),
    notary_signature,
    ec_privkey,
    time
  );

  var commonName = getCommonName(server_certchain[0]);
  var creationTime = getTime();
  await createNewSession (creationTime, commonName, cleartext, pgsg, false)
  await openTab(creationTime);
  var allSessions = await getAllSessions(); 
  sendSessions(allSessions); //refresh manager
}



//imported_data is an array of ints
async function verify_tlsn(data) {
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
  var server_reply = data.slice(o, o += server_reply_len);
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

  var commonName = getCommonName(chain[0]);
  var vcrv = await verifyChain(chain); 
  if (vcrv[0] != true) {
    throw ('certificate verification failed');
  }
  var rv = await verifyECParamsSig(chain[0], ec_pubkey_server, rsa_sig, client_random, server_random)
  if (rv != true){
    throw ('EC parameters signature verification failed');
  }

  //calculate pre-master secre
  var ECpubkey_CryptoKey = await window.crypto.subtle.importKey(
    "raw",
     ba2ab(ec_pubkey_server),
    {name: 'ECDH', namedCurve:'P-256'},
    true,
    []);

  var ECprivkey_CryptoKey = await window.crypto.subtle.importKey(
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
  
  //calculate commit_hash from server_reply
  var commit_hash = await sha256(server_reply)
  //check notary server signature
  var signed_data_ba = await sha256([].concat(ec_privkey, ec_pubkey_server, commit_hash, time))
  assert(await verifyNotarySig(notary_signature, chosen_notary.pubkeyPEM, signed_data_ba) == true)
  //aesgcm decrypt the data
  var cleartext = await decrypt_tls_response (server_reply, server_write_key, server_write_IV)
  var dechunked = dechunk_http(ba2str(cleartext))
  var ungzipped = gunzip_http(dechunked)
  return [ungzipped, commonName];
}


//imported_data is an array of numbers
async function verify_tlsn_and_show_data(imported_data, create) {
  try {
    var a = await verify_tlsn(imported_data);
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
  var creationTime = getTime();
  await createNewSession (creationTime, commonName, cleartext, imported_data, true)
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
      setTimeout(async function(){
        var myViews = chrome.extension.getViews();
        for (let win of myViews){
          if (myTabs.includes(win.tabid)) continue;
          //found a new viewer tab
          win.tabid = newtab.id;
          resolve();
        }
      }, 100)
    });
  }

  //give the tab some time to load
  setTimeout(function() {
    chrome.runtime.sendMessage({
      destination: 'viewer',
      data: cleartext,
      sessionId: sid,
      type: 'unknown',
      serverName: commonName
    });
  }, 100);
}


async function viewRaw(sid) {
  var data = await getSession(sid)
  var blob = await getSessionBlob(sid)
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/viewer.html');
  chrome.tabs.create({url: url},
  function(t) {
    setTimeout(function() {
      chrome.runtime.sendMessage({
        destination: 'viewer',
        data: blob.cleartext,
        type: 'raw',
        sessionId: sid,
        serverName: data.serverName
      });
    }, 100);
  });
}


function sendSessions(sessions) {
  var rows = []
  for (let session of sessions){
    rows.push({
      'sessionName': session.sessionName,
      'serverName': session.serverName,
      'is_imported': session.is_imported,
      'verifier': 'tlsnotarygroup8',
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
main();