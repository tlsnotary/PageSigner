/* global chrome, browser */

import {parse_certs, verifyChain, getCommonName, getAltNames} from
  './verifychain.js';
import {ba2str, b64decode, concatTA, int2ba, sha256, b64encode, verifySig,
  assert, ba2int, xor, eq, wait, AESECBencrypt, wildcardTest, pubkeyPEM2raw,
  import_resource} from './utils.js';
import {getPref, getSessionBlob, getSession, getAllSessions, saveNewSession,
  init_db, addNewPreference, setPref, renameSession, deleteSession}
  from './indexeddb.js';
import {globals} from './globals.js';
import {Socket} from './Socket.js';
import {TLS, getExpandedKeys, decrypt_tls_responseV6} from './TLS.js';
import {verifyNotary, getURLFetcherDoc} from './oracles.js';
import {TLSNotarySession} from './TLSNotarySession.js';
import {TLSprobe} from './TLSprobe.js';
import {ProgressMonitor} from './ProgressMonitor.js';
import {FirstTimeSetup} from './FirstTimeSetup.js';

export class Main{
  constructor(){
    this.messageListener;
    this.notarization_in_progress = false;
    this.isFirstTimeSetupNeeded = false;
    this.waiting_for_click = false;
    // popupError will be  set to non-null when there is some error message that must be shown
    // via the popup
    this.popupError = null;
    // tabid set to 0 is a sign that this is the main window when querying with .getViews()
    this.tabid = 0;
    // pendingAction is Firefox only: the action which must be taken as soon as the user allows
    // access to the website (either notarize or notarizeAfter)
    this.pendingAction = null;
    // trustedOracle is an object {'IP':<IP address>, 'pubkeyPEM':<pubkey in PEM format>}
    // describing the oracle server which was verified and can be used for notarization.
    this.trustedOracle = null;
    if (typeof(window) != 'undefined') {
      this.is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
      this.is_firefox = window.navigator.userAgent.match('Firefox') ? true : false;
      this.is_edge = window.navigator.userAgent.match('Edg') ? true : false;
      this.is_opera = window.navigator.userAgent.match('OPR') ? true : false;
      // pm is the only instance of ProgressMonitor that is reused between
      // notarization sesions
      this.pm = new ProgressMonitor();
    }
    // trustedOracleReady will be set to true after we performed AWS HTTP queries
    // and verified that an oracle is trusted (we verify only once)
    this.trustedOracleReady = false;
  }

  async main() {
    // perform browser-specific init first
    if (this.is_edge || this.is_firefox || this.is_opera){
      globals.usePythonBackend = true;
    }
    if (this.is_firefox){
    // Firefox asks user for permission to access the current website.
    // Listen when the permission was given and run the pending action.
    // This way user doesnt have to click notarize->allow->notarize
      const listener = function(permissions){
        if (permissions.origins.length != 1) {
        // unknown permission granted
          return;
        }
        if (this.pendingAction == 'notarize'){
          this.prepareNotarizing(false);
        }
        else if (this.pendingAction == 'notarizeAfter'){
          this.prepareNotarizing(true);
        }
      };
      browser.permissions.onAdded.addListener(listener);
    }

    // browser-agnostic init
    const that = this;
    this.messageListener = chrome.runtime.onMessage.addListener(function(data) {
      // processMessages is the main entrypoint for all extension's logic
      that.processMessages(data);
    });
    await init_db();

    // Some preferences may not exist if we are upgrading from
    // a previous PageSigner version. Create the preferences.
    if (await getPref('firstTimeInitCompletedv2') === null){
      await addNewPreference('firstTimeInitCompletedv2', false);
      await setPref('parsedCircuits', {});
    }
    if (await getPref('trustedOracle') === null){
      await addNewPreference('trustedOracle', {});
    }
    // check if we need to communicate with a new version of the notary server
    const notaryVersion = await getPref('notaryServerVersion');
    if (notaryVersion === null){
      await addNewPreference('notaryServerVersion', 16);
      await setPref('trustedOracle', {});
    } else if (notaryVersion < 16) {
      // the notary server was upgraded
      await setPref('notaryServerVersion', 16);
      await setPref('trustedOracle', {});
    }

    const text = await import_resource('core/third-party/certs.txt');
    await parse_certs(text);
    if (globals.useNotaryNoSandbox){
      const obj = await this.queryNotaryNoSandbox(globals.defaultNotaryIP);
      this.trustedOracle = obj;
      this.trustedOracleReady = true;
      await setPref('trustedOracle', obj);
      return;
    }
    this.trustedOracle = await getPref('trustedOracle');
    if (Object.keys(this.trustedOracle).length !== 0){
      if (await this.pingNotary(this.trustedOracle.IP) !== true) {
        await this.tryBackupNotary(this.trustedOracle.IP);
      }
      else {
        this.trustedOracleReady = true;
      }
      return;
    }
    // on first launch trustedOracle is not set, verify the default one asynchronously
    if (await this.pingNotary(globals.defaultNotaryIP) !== true){
      await this.tryBackupNotary(globals.defaultNotaryIP);
      return;
    }
    // notary is online
    const URLFetcherDoc = await getURLFetcherDoc(globals.defaultNotaryIP, globals.defaultNotaryPort);
    const trustedPubkeyPEM = await verifyNotary(URLFetcherDoc);
    assert(trustedPubkeyPEM != undefined);
    // verification was successful
    const obj = {
      'IP': globals.defaultNotaryIP,
      'pubkeyPEM': trustedPubkeyPEM,
      'URLFetcherDoc': URLFetcherDoc
    };
    await setPref('trustedOracle', obj);
    that.trustedOracle = obj;
    that.trustedOracleReady = true;
  }

  async queryNotaryNoSandbox(IP){
    // just fetch the pubkey and trust it
    const resp = await fetch('http://'+IP+':' + globals.defaultNotaryPort + '/getPubKey', {
      method: 'POST',
      mode: 'cors',
      cache: 'no-store',
    });
    const trustedPubkeyPEM = await resp.text();
    return {
      'IP': IP,
      'pubkeyPEM': trustedPubkeyPEM,
    };
  }

  // pingNotary returns true if notary's IP address is reachable
  async pingNotary(IP){
    // ping the notary, it should respond with 404 not found
    const fProm = fetch('http://'+IP+':'+ globals.defaultNotaryPort + '/ping', {
      mode: 'no-cors'
    });
    const out = await Promise.race([fProm, wait(5000)])
      // eslint-disable-next-line no-unused-vars
      .catch(err => {
        // fetch got 404; do nothing, just prevent exception from propagating
      });
    if (out === 'wait'){
      console.log('Notary is unreachable at IP: ', IP);
      return false;
    }
    return true;
  }

  // tryBackupNotary tries to use a backup notary. It checks that the backup notary
  // is not the same as failedNotaryIP
  async tryBackupNotary(failedNotaryIP){
    const resp = await fetch(globals.backupUrl);
    const backupIP = await resp.text();
    if (backupIP === failedNotaryIP){
      throw('Notary is unreachable. Please let the Pagesigner devs know about this.');
    }
    if (this.pingNotary(backupIP) !== true){
      console.log('Backup notary is unreachable.');
      throw('Notary is unreachable. Please let the Pagesigner devs know about this.');
    }
    const URLFetcherDoc = await getURLFetcherDoc(backupIP, globals.defaultNotaryPort);
    const trustedPubkeyPEM = await verifyNotary(URLFetcherDoc);
    assert(trustedPubkeyPEM != undefined);
    const obj = {
      'IP': backupIP,
      'pubkeyPEM': trustedPubkeyPEM,
      'URLFetcherDoc': URLFetcherDoc
    };
    console.log('backup oracle verified');
    await setPref('trustedOracle', obj);
    this.trustedOracle = obj;
    this.trustedOracleReady = true;
  }


  openChromeExtensions(){
    chrome.tabs.query({url: 'chrome://extensions/*'},
      function(tabs) {
        if (tabs.length == 0) {
          chrome.tabs.create({url: 'chrome://extensions'});
          return;
        }
        chrome.tabs.update(tabs[0].id, {active: true});
      });
  }


  // Pagesigner's popup has been clicked
  async popupProcess(){
    if (this.notarization_in_progress) {
      chrome.runtime.sendMessage({
        destination: 'popup',
        message: 'notarization_in_progress',
        firstTime: this.isFirstTimeSetupNeeded
      });
      return;
    }
    if (this.waiting_for_click) {
      chrome.runtime.sendMessage({
        destination: 'popup',
        message: 'waiting_for_click'
      });
      return;
    }
    // else{} the checks below are only for Chrome
    // probe a non-existent port, if reject()ed with undefined, then the helper app is not running
    try{
      const dummySock = new Socket('127.0.0.1', -1);
      dummySock.connectTimeout = 200; // 200 ms
      await dummySock.connect();
    }
    catch(error){
      if (error == undefined || error == 'connection error'){
        chrome.runtime.sendMessage({
          destination: 'popup',
          message: 'app_not_installed'
        });
        return;
      }
    }
    if (this.popupError) {
      chrome.runtime.sendMessage({
        destination: 'popup',
        message: 'popup error',
        data: this.popupError
      });
      this.popupError = null;
      this.loadDefaultIcon();
    } else {
      chrome.runtime.sendMessage({
        destination: 'popup',
        message: 'show_menu'
      });
    }
  }

  // checkIfTabOpened checks if a "tab" containing window[property] has signalled that it has
  // been loaded and its message listeners are ready
  // openTabs is an optional array of tab ids to skip when checking because they were already
  // opened BEFORE we initiated the opening of "tab"
  // we abort if tab doesn't open after 5 secs.
  checkIfTabOpened(tab, property, openTabs){
    // eslint-disable-next-line no-unused-vars
    openTabs = openTabs || [];
    let isTimeoutTriggered = false;
    setTimeout(function(){
      isTimeoutTriggered = true;
    }, 5 * 1000);

    // eslint-disable-next-line no-async-promise-executor
    return new Promise(async function(resolve) {
      function tryAgain(){
        console.log('checking if '+property+' is ready...');
        const views = chrome.extension.getViews();
        // sometimes the View for the newly opened tab may not yet be available
        // so we must wait a little longer
        for (const win of views){
          if (win[property] == undefined) continue;
          // found some viewer. Our viewer's tabid is null
          if (win.tabid != null) continue;
          if (win.isReady !== true) continue;
          // else is ready
          // save the tab id inside the window object
          win.tabid = tab.id;
          resolve(win);
          return true;
        }
      }
      while (tryAgain() !== true){
        if (isTimeoutTriggered){
          console.log('isTimeoutTriggered', isTimeoutTriggered);
          return;
        }
        await wait(10);
      }
    });
  }

  openFileChooser(){
    const myTabs = [];
    const views = chrome.extension.getViews();
    for (const win of views){
      if (win.isFileChooser){
        // re-focus if already opened
        chrome.tabs.update(win.tabid, {active: true});
        return;
      }
      myTabs.push(win.tabid);
    }
    const that = this;
    // #filechooser is in the URL only so that the user is not confused. We do not
    // create a separate filechooser.html because as soon as a file is chosen, the
    // same tab will be reused as a viewer.
    // Otherwise we would have to close filechooser tab and instantly open a
    // viewer tab with an unpleasant flicker.
    const url = chrome.extension.getURL('ui/html/viewer.html#filechooser');
    chrome.tabs.create({url: url}, async function(t){
      const win = await that.checkIfTabOpened(t, 'isViewer', myTabs);
      win.viewer.showFileChooser();
    });
  }


  openManager() {
    const url = chrome.extension.getURL('ui/html/manager.html');
    for (const win of chrome.extension.getViews()){
      if (win.isManager){
        // re-focus tab if manager already open
        console.log('will refocus manger tab', win.tabid);
        chrome.tabs.update(win.tabid, {active: true});
        return;
      }
    }
    const that = this;
    chrome.tabs.create({url: url}, function(t){
      that.checkIfTabOpened(t, 'is_manager');
    });
  }


  async prepareNotarization(after_click = false, isPreview = false) {
    if (!isPreview && !this.trustedOracleReady) {
      this.sendAlert({
        title: 'PageSigner error.',
        text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
      });
      return;
    }

    let clickTimeout = null;
    const that = this;

    const active_tab = await new Promise(function(resolve) {
      chrome.tabs.query({active: true}, function(t) {
        resolve(t[0]);
      });
    });

    if (! active_tab.url.startsWith('https://')) {
      this.sendAlert({
        'title': 'PageSigner error.',
        'text': 'You can only notarize pages which start with https://'
      });
      return;
    }

    if (after_click){
      const url = chrome.extension.getURL('ui/img/arrow24.png');
      chrome.browserAction.setIcon({path: url});
      this.waiting_for_click = true;
      clickTimeout = setTimeout(function() {
        that.waiting_for_click = false;
        that.loadDefaultIcon();
        that.sendAlert({
          title: 'PageSigner error.',
          text: 'You haven\'t clicked any https:// links in 30 seconds. Please try again. If this error persists it may mean that the website you are trying to notarize is not compatible with PageSigner.'
        });
      }, 30 * 1000);
    }

    let oBR_details;
    const oBR_handler = function(details){
      console.log('in onBeforeRequest', details);
      chrome.webRequest.onBeforeRequest.removeListener(oBR_handler);
      oBR_details = details;
    };
    chrome.webRequest.onBeforeRequest.addListener(
      oBR_handler, {
        urls: ['<all_urls>'],
        tabId: active_tab.id,
        types: ['main_frame', 'xmlhttprequest']
        // types: ["main_frame", "sub_frame", "stylesheet", "script",
        // "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]
      }, ['requestBody']);

    let oBSH_details;
    const oBSH_handler = function(details){
      console.log('in onBeforeSendHeaders', details);
      chrome.webRequest.onBeforeSendHeaders.removeListener(oBSH_handler);
      oBSH_details = details;
      console.log(oBR_details, oBSH_details);
    };
    const extraInfoSpec = ['requestHeaders'];
    if (this.is_chrome) extraInfoSpec.push('extraHeaders');
    chrome.webRequest.onBeforeSendHeaders.addListener(
      oBSH_handler, {
        urls: ['<all_urls>'],
        tabId: active_tab.id,
        types: ['main_frame', 'xmlhttprequest']
      }, extraInfoSpec);


    // wait for the request to pass oBR and oBHS and reach onSendHeaders
    await new Promise(function(resolve) {
      const oSH_handler = function(details){
        console.log('in onSendHeaders');
        chrome.webRequest.onSendHeaders.removeListener(oSH_handler);
        resolve(details);
      };
      chrome.webRequest.onSendHeaders.addListener(
        oSH_handler, {
          urls: ['<all_urls>'],
          tabId: active_tab.id,
          types: ['main_frame', 'xmlhttprequest']
        });

      // if not Notarize After Click mode,
      // reload current tab in order to trigger the HTTP request
      if (!that.waiting_for_click) chrome.tabs.reload(active_tab.id);
      // otherwise just wait for the user to click smth and trigger onBeforeRequest
    });

    if (this.waiting_for_click) {
      clearTimeout(clickTimeout);
      this.waiting_for_click = false;
    }

    if (oBR_details.url !== oBSH_details.url) return;
    if (oBR_details.requestId !== oBSH_details.requestId) return;
    if (oBR_details.method == 'POST') {
      // POST payload is only available from onBeforeRequest
      oBSH_details['requestBody'] = oBR_details.requestBody;
    }
    const rv = this.getHeaders(oBSH_details);
    this.startNotarization(rv.headers, rv.server, rv.port, isPreview)
      .catch(err => {
        console.log('Notarization aborted.', err);
        console.trace();
        let errmsg = err;
        if (typeof(err) === 'object'){
          errmsg = err.message;
          if (err.message == 'Failed to fetch'){
            errmsg = 'Unable to connect to the notary server. Please check your internet connection.';
          }
        }
        this.sendAlert({
          title: 'PageSigner error.',
          text: errmsg
        });
      })
      .finally(()=> {
        this.notarization_in_progress = false;
        this.loadDefaultIcon();
      });
  }


  getHeaders(obj) {
    console.log('headers are', obj);
    const x = obj.url.split('/');
    const host = x[2].split(':')[0];
    x.splice(0, 3);
    const resource_url = x.join('/');

    const http_version = globals.useHTTP11 ? ' HTTP/1.1':' HTTP/1.0';
    let headers = obj.method + ' /' + resource_url + http_version + '\r\n';
    // Chrome doesnt add Host header. Firefox does
    if (this.is_chrome){
      headers += 'Host: ' + host + '\r\n';
    }
    for (let h of obj.requestHeaders) {
      // we dont want any "br" encoding
      if (h.name == 'Accept-Encoding') {
        // h.value = 'gzip, deflate'
        h.value = 'identity;q=1, *;q=0';
      }
      headers += h.name + ': ' + h.value + '\r\n';
    }
    if (obj.method == 'GET') {
      headers += '\r\n';
    }
    else if (obj.method == 'POST') {
      let content;
      if (obj.requestBody.raw != undefined) {
        content = ba2str(new Uint8Array(obj.requestBody.raw[0].bytes));
      }
      else{
        const keys = Object.keys(obj.requestBody.formData);
        content = '';
        for (var key of keys) {
          content += key + '=' + obj.requestBody.formData[key] + '&';
        }
        // get rid of the last &
        content = content.slice(0, -1);
        // Chrome doesn't expose Content-Length which chokes nginx
        headers += 'Content-Length: ' + parseInt(content.length) + '\r\n\r\n';
        headers += content;
      }
    }
    let port = 443;
    if (obj.url.split(':').length === 3) {
      // the port is explicitely provided in URL
      port = parseInt(obj.url.split(':')[2].split('/')[0]);
    }
    return {
      'headers': headers,
      'server': host,
      'port': port
    };
  }


  async getPGSG(sid){
    const blob = await getSessionBlob(sid);
    return blob.pgsg;
  }




  // processMessages is the main entrypoint for all extension's logic
  async processMessages(data) {
    if (data.destination !== 'extension') return;
    console.log('ext got msg', data);
    switch (data.message){
    case 'rename':
      await renameSession(data.sid, data.newname);
      this.sendSessions(await getAllSessions());
      break;
    case 'delete':
      await deleteSession(data.sid);
      this.sendSessions(await getAllSessions());
      break;
    case 'import':
      // data is js array
      this.importPgsgAndShow(new Uint8Array(data.data));
      break;
    case 'export':
      this.sendToManager({'pgsg': JSON.stringify(await this.getPGSG(data.sid)),
        'name': (await getSession(data.sid)).sessionName}, 'export');
      break;
    case 'notarize':
      this.prepareNotarization(false);
      break;
    case 'notarizeAfter':
      this.prepareNotarization(true);
      break;
    case 'preview':
      this.prepareNotarization(false, true);
      break;
    case 'manage':
      this.openManager();
      break;
    case 'refresh':
      this.sendSessions(await getAllSessions());
      break;
    case 'openLink1':
      chrome.tabs.create({url: 'https://www.tlsnotary.org'});
      break;
    case 'showSession':
      this.showSession(data.sid);
      break;
    case 'showDetails':
      this.openDetails(data.sid);
      break;
    case 'showPreviewDetails':
      this.openPreviewDetails(data.serverName, data.request, data.response);
      break;
    case 'fileChooser':
      this.openFileChooser();
      break;
    case 'openChromeExtensions':
      this.openChromeExtensions();
      break;
    case 'popup active':
      this.popupProcess();
      break;
    case 'open python script':
      this.openPythonScript();
      break;
    case 'pendingAction':
      this.pendingAction = data.action;
      break;
    case 'useNotaryNoSandbox':
      this.useNotaryNoSandbox(data.IP);
      break;
    case 'removeNotary':
      await setPref('trustedOracle', {});
    }
  }

  // startNotarization starts a TLSNotary session, saves the session result
  // and displays it to the user. If we are in the preview mode, then we send
  // the request directly to the server and display the result.
  async startNotarization(headers, server, port, isPreview=false) {
    if (isPreview){
      await this.startPreview(headers, server, port);
      return;
    }
    this.notarization_in_progress = true;
    this.pm.init();
    this.isFirstTimeSetupNeeded = ! await getPref('firstTimeInitCompletedv2');
    chrome.runtime.sendMessage({
      destination: 'popup',
      message: 'notarization_in_progress',
      firstTime: this.isFirstTimeSetupNeeded
    });
    if (this.isFirstTimeSetupNeeded){
      const obj = await new FirstTimeSetup().start(this.pm);
      console.time('setPref');
      await setPref('parsedCircuits', obj);
      console.timeEnd('setPref');
      await setPref('firstTimeInitCompletedv2', true);
    }
    const circuits = await getPref('parsedCircuits');
    const session = new TLSNotarySession(
      server, port, headers, this.trustedOracle, globals.sessionOptions, circuits, this.pm);
    const obj = await session.start();
    obj['title'] = 'PageSigner notarization file';
    obj['version'] = 6;
    if (! globals.useNotaryNoSandbox){
      obj['URLFetcher attestation'] = this.trustedOracle.URLFetcherDoc;
    }
    const [host, request, response, date] = await this.verifyPgsgV6(obj);
    const serializedPgsg = this.serializePgsg(obj);
    await saveNewSession (date, host, request, response, serializedPgsg);
    // date uniquely identifies a session
    this.showSession(date);
  }

  // startPreview does not perfrom a TLSNotary session but simply fetches the
  // resource from the webserver and shows the user a preview of what the
  // notarization result will look like, were the user to initiate a notarization.
  // This is especially useful when the the user picks which headers/resources
  // to include in the notarization and wants to have a quick preview.
  async startPreview(headers, server, port) {
    const preview = new TLSprobe(server, port, headers, globals.sessionOptions);
    const response = await preview.start();
    console.log('response was: ', response);
    await this.openViewer(server, headers, response);
  }

  loadDefaultIcon(){
    const url = chrome.extension.getURL('ui/img/icon.png');
    chrome.browserAction.setIcon({path: url});
  }

  // opens a tab showing the session. sid is a unique session id
  // creation time is sid.
  async showSession (sid){
    const data = await getSession(sid);
    const blob = await getSessionBlob(sid);
    if (data === null) {throw('failed to get index', sid);}
    await this.openViewer(data.serverName, blob.request, blob.response, sid);
    this.sendSessions( await getAllSessions()); // refresh manager
  }

  openPythonScript(){
    const url = chrome.extension.getURL('pagesigner.py');
    chrome.tabs.create({url: url}, function(t){
      chrome.tabs.executeScript(t.id, {file: ('ui/python_script_header.js')});
    });
  }


  async verifyPgsg(json){
    if (json['version'] == 6){
      return await this.verifyPgsgV6(json);
    }
    else {
      throw ('Unrecognized version of the imported pgsg file.');
    }
  }


  // Serialize fields of json object
  serializePgsg(json){
    // b64encode every field
    const newjson = {};
    const keys = Object.keys(json);
    for (const key of keys){
      if (['title', 'version'].includes(key)){
        newjson[key] = json[key];
      }
      else if (key === 'certificates' || key === 'server response records'){
        // turn an array into obj with key as index i.e {"0": elem0, "1": elem1, ...}
        const obj = {};
        for (let i=0; i<json[key].length; i++){
          obj[i.toString()] = b64encode(json[key][i]);
        }
        newjson[key] = obj;
      }
      else {
        newjson[key] = b64encode(json[key]);
      }
    }
    return newjson;
  }

  deserializePgsg(json){
    // b64decode every field
    const newjson = {};
    const keys = Object.keys(json);
    for (const key of keys){
      if (['title', 'version'].includes(key)){
        newjson[key] = json[key];
      }
      else if (key === 'certificates' || key === 'server response records'){
        // turn an obj with key as index i.e {"0": elem0, "1": elem1, ...} into an array
        const objKeys = Object.keys(json[key]);
        const arr = [];
        for (let i=0; i < objKeys.length; i++){
          arr.push(b64decode(json[key][i]));
        }
        newjson[key] = arr;
      }
      else {
        newjson[key] = b64decode(json[key]);
      }
    }
    return newjson;
  }

  // verifyPgsgV6 verifies a decoded pgsg
  // obj is pgsg with values b64decoded and certificates deserialized into Certificate class
  async verifyPgsgV6(obj) {
    assert(obj['title'] === 'PageSigner notarization file');
    assert(obj['version'] === 6);

    // Step 1. Verify URLFetcher attestation doc and get notary's pubkey
    if (! globals.useNotaryNoSandbox){
      // by default we verify that the notary is indeed a properly sandboxed machine
      var URLFetcherDoc = obj['URLFetcher attestation'];
      var notaryPubkey = await verifyNotary(URLFetcherDoc);
    }
    else {
      notaryPubkey = this.trustedOracle.pubkeyPEM;
    }

    // Step 2. Verify certificate chain validity (at the time of notarization)
    // and extract Common Name from the leaf certificate
    const certs = obj['certificates'];
    const unix_time = obj['notarization time'];
    const date = new Date(ba2int(unix_time) * 1000); // to milliseconds
    const vcRV = await verifyChain(certs, date);
    assert (vcRV.result === true);
    // certificatePath contains certificates in a ascending order from leaf to root
    const certPath = vcRV.certificatePath;
    const commonName = getCommonName(certPath[0]);
    const altNames = getAltNames(certPath[0]);

    // Step 3. Verify that RSA signature over ephemeral EC key corresponds to the public key
    // from the leaf certificate
    const serverEcPubkey = obj['server pubkey for ECDHE'];
    const rsaSig = obj['server RSA sig'];
    const cr = obj['client random'];
    const sr = obj['server random'];
    const vepsRV = await TLS.verifyECParamsSig(certPath[0], serverEcPubkey, rsaSig, cr, sr);
    assert (vepsRV === true);

    // Step 4. Combine PMS shares and derive expanded keys.
    const P256prime = 2n**256n - 2n**224n + 2n**192n + 2n**96n - 1n;
    // we may need to reduce mod prime if the sum overflows the prime
    const pms = int2ba((ba2int(obj['notary PMS share']) + ba2int(obj['client PMS share'])) % P256prime, 32);
    const [cwk, swk, civ, siv] = await getExpandedKeys(pms, cr, sr);

    // Step 5. Check that expanded keys match key shares
    const clientCwkShare = obj['client client_write_key share'];
    const clientCivShare = obj['client client_write_iv share'];
    const clientSwkShare = obj['client server_write_key share'];
    const clientSivShare = obj['client server_write_iv share'];
    const notaryCwkShare = obj['notary client_write_key share'];
    const notaryCivShare = obj['notary client_write_iv share'];
    const notarySwkShare = obj['notary server_write_key share'];
    const notarySivShare = obj['notary server_write_iv share'];
    assert(eq( xor(notaryCwkShare, clientCwkShare), cwk));
    assert(eq( xor(notaryCivShare, clientCivShare), civ));
    assert(eq( xor(notarySwkShare, clientSwkShare), swk));
    assert(eq( xor(notarySivShare, clientSivShare), siv));

    // Step 6. Check session signature
    const commitHash = await TLSNotarySession.computeCommitHash(obj['server response records']);
    const keyShareHash = await sha256(concatTA(clientCwkShare, clientCivShare,
      clientSwkShare, clientSivShare));
    const pmsShareHash = await sha256(obj['client PMS share']);
    const tbs1 = concatTA(
      commitHash,
      keyShareHash,
      pmsShareHash,
      obj['client request ciphertext'],
      serverEcPubkey,
      obj['notary PMS share'],
      notaryCwkShare,
      notaryCivShare,
      notarySwkShare,
      notarySivShare,
      obj['notarization time']);

    assert(await verifySig(
      obj['ephemeral pubkey'],
      obj['session signature'],
      tbs1) === true,
    'Session signature verification failed.');

    // Step 7. Verify ephemeral key
    const tbs2 = concatTA(
      obj['ephemeral valid from'],
      obj['ephemeral valid until'],
      obj['ephemeral pubkey']);
    assert(await verifySig(
      pubkeyPEM2raw(notaryPubkey),
      obj['ephemeral signed by master key'],
      tbs2) === true,
    'Master key signature verification failed.');
    // notarization time must be within the time of ephemeral key validity
    assert(
      ba2int(obj['ephemeral valid from']) <
      ba2int(obj['notarization time']) <
      ba2int(obj['ephemeral valid until']));


    // Step 8. Decrypt client request and make sure that "Host" HTTP header corresponds to
    // Common Name from the leaf certificate.
    const ghashInputs = [];
    const blockCount = obj['client request ciphertext'].length/16;
    for (let i=0; i < blockCount; i++){
      ghashInputs.push(obj['client request ciphertext'].slice(i*16, (i+1)*16));
    }
    // aad is additional authenticated data
    const aad = ghashInputs[0];
    // TLS record seq number must be 1
    assert(eq(aad.slice(0, 8), int2ba(1, 8)));
    // TLS record type must be "application data"
    assert(eq(aad.slice(8, 11), new Uint8Array([23, 3, 3])));
    const recordLen = ba2int(aad.slice(11, 13));
    const plaintextBlocks = [];
    const ciphertext = ghashInputs.slice(1, ghashInputs.length-1);
    for (let i=0; i < ciphertext.length; i++){
      const explicitNonce = 2;
      const blockCounter = 2+i;
      const nonce = concatTA(civ, int2ba(explicitNonce, 8), int2ba(blockCounter, 4));
      const encCounter = await AESECBencrypt(cwk, nonce);
      plaintextBlocks.push(xor(ciphertext[i], encCounter));
    }
    const request = ba2str(concatTA(...plaintextBlocks).slice(0, recordLen));
    // \r\n\r\n separates HTTP headers from the body
    const allHeaders = request.slice(0, request.search('\r\n\r\n'));
    const headers = allHeaders.split('\r\n');
    let isFound = false;
    for (const h of headers){
      if(h.startsWith('Host: ') || h.startsWith('host: ')){
        if (isFound){
          throw('Error: multiple Host headers in request.');
        }
        var host = h.split(' ')[1];
        console.log(commonName, host);
        for (const name of [].concat([commonName], altNames)){
          if (wildcardTest(name, host)){
            isFound = true;
            break;
          }
        }
      }
    }
    assert(isFound, 'Host not found in certificate');

    // Step 9. Check authentication tags of server response and decrypt it.
    const responseRecords = await decrypt_tls_responseV6(
      obj['server response records'], swk, siv);
    const response = ba2str(concatTA(...responseRecords));
    return [host, request, response, date.toGMTString()];
  }

  async importPgsgAndShow(importedData) {
    console.log('importedData', importedData);
    try {
      var serializedPgsg = JSON.parse(ba2str(importedData));
      var pgsg = this.deserializePgsg(serializedPgsg);
      var [host, request, response, date] = await this.verifyPgsg(pgsg);
    } catch (e) {
      this.sendAlert({
        title: 'PageSigner failed to import file.',
        text: 'The error was: ' + e
      });
      return;
    }
    // check for duplicates
    for (const s of await getAllSessions()){
      if (s.creationTime === date) {
        console.log('duplicate session found');
        chrome.runtime.sendMessage({
          destination: 'fileChooser',
          message: 'duplicate',
          date: s.creationTime,
          name: s.sessionName
        });
        return;
      }
    }
    // save session to disk
    await saveNewSession (date, host, request, response, serializedPgsg, 'imported');
    this.showSession(date);
  }


  // openViewer opens a new browser tab (or reuses the import tab, if importing
  // happened), waits for the tab to fully load and sends data for the viewer
  // to display.
  async openViewer(serverName, request, response, sid) {
    let tabId = null;// the id of the tab that we will be sending to

    const url = chrome.extension.getURL('ui/html/viewer.html');
    await chrome.webRequest.handlerBehaviorChanged(); // flush the in-memory cache

    // reuse a tab if viewer was already open because we were importing file
    // this tab must be still active
    const active_tab = await new Promise(function(resolve) {
      chrome.tabs.query({active: true}, function(t) {
        resolve(t[0]);
      });
    });
    // check if there is a FileChooser among our views
    let isImportTab = false;
    const views = chrome.extension.getViews();
    for (const win of views){
      if (win.tabid == active_tab.id && win.isFileChooser){
        isImportTab = true;
        // this window is not a file picker anymore
        win.isFileChooser = false;
      }
    }
    tabId = active_tab.id;

    if (!isImportTab){
      const myTabs = [];
      for (const win of views ){
        myTabs.push(win.tabid);
      }
      const that = this;
      await new Promise(function(resolve) {
        chrome.tabs.create({url: url}, async function(t){
          tabId = t.id;
          await that.checkIfTabOpened(t, 'isViewer', myTabs);
          console.log('checkIfTabOpened resolved');
          resolve();
        });
      });
    }

    console.log('send to viewer');
    // the tab is either an already opened import tab or a fully-loaded new viewer tab.
    // if sid was not set, then this is a preview tab.
    // We already checked that the new viewer's tab DOM was loaded. Proceed to send the data
    chrome.runtime.sendMessage({
      destination: 'viewer',
      message: 'show',
      tabId: tabId,
      request: request,
      response: response,
      sessionId: sid,
      serverName: serverName
    });
  }

  openPreviewDetails(serverName, request, response){
    this.doOpenDetails(serverName, request, response);
  }

  async openDetails(sid){
    const data = await getSession(sid);
    const blob = await getSessionBlob(sid);
    this.doOpenDetails(data.serverName, blob.request, blob.response, sid);
  }

  async doOpenDetails(serverName, request, response, sid) {
    const url = chrome.extension.getURL('ui/html/detailsViewer.html');
    let tabId = null; // id of the tab to which we will send the data

    const myTabs = [];
    const myViews = chrome.extension.getViews();
    for (const win of myViews ){
      myTabs.push(win.tabid);
    }

    const that = this;
    await new Promise(function(resolve) {
      chrome.tabs.create({url: url}, async function(t){
        tabId = t.id;
        await that.checkIfTabOpened(t, 'isDetailsViewer', myTabs);
        resolve();
      });
    });

    chrome.runtime.sendMessage({
      destination: 'detailsViewer',
      message: 'show',
      tabId: tabId,
      request: request,
      response: response,
      sessionId: sid,
      serverName: serverName
    });
  }


  sendSessions(sessions) {
    const rows = [];
    for (const session of sessions){
      rows.push({
        'creationTime': session.creationTime,
        'sessionName': session.sessionName,
        'serverName': session.serverName,
        'isImported': session.isImported,
        'isEdited': session.isEdited,
        'version': session.version
      });
    }
    this.sendToManager(rows);
  }

  sendToManager(data, command) {
    console.log('sending sendToManager ', data);
    if (!command) command = 'payload'; // commands can be: payload, export
    assert(['payload', 'export'].includes(command));
    chrome.runtime.sendMessage({
      destination: 'manager',
      command: command,
      payload: data
    });
  }

  // for some pages we cant inject js/css, use the ugly alert
  uglyAlert(alertData) {
    const url = chrome.extension.getURL('ui/img/icon_error.png');
    chrome.browserAction.setIcon({
      path: url
    });
    this.popupError = alertData;
  }

  sendAlert(alertData) {
    const that = this;
    chrome.tabs.query({active: true},
      function(tabs) {
        if (chrome.extension.lastError) {
          that.uglyAlert(alertData);
          return;
        }
        chrome.tabs.executeScript(tabs[0].id, {file: ('ui/sweetalert.min.js')},
          function() {
            if (chrome.extension.lastError) {
              that.uglyAlert(alertData);
              return;
            }
            chrome.tabs.insertCSS(tabs[0].id, {file: ('ui/css/sweetalert.css')},
              function() {
                if (chrome.extension.lastError) {
                  that.uglyAlert(alertData);
                  return;
                }
                chrome.tabs.executeScript(tabs[0].id, {code: 'swal(' + JSON.stringify(alertData) + ')'});
                if (chrome.extension.lastError) {
                  that.uglyAlert(alertData);
                  return;
                }
              });
          });
      });
  }

  async useNotaryNoSandbox(IP){
    globals.defaultNotaryIP = IP;
    globals.useNotaryNoSandbox = true;
    await this.queryNotaryNoSandbox(IP);
  }
}

if (typeof(window) != 'undefined') {
  // only run main() in browser environment
  const m = new Main();
  m.main()
    .catch(err => {
      console.log('Error in main: ', err);
      m.sendAlert({
        title: 'PageSigner error.',
        text: err
      });
    });
}