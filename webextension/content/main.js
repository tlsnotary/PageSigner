var random_uid; //we get a new uid for each notarized page
var reliable_sites = []; //read from content/pubkeys.txt
var previous_session_start_time; // used to make sure user doesnt exceed rate limiting
var chosen_notary;
var tdict = {};
var valid_hashes = [];
var browser_init_finished = false; //signal to test script when it can start
var mustVerifyCert = true; //set to false during debugging to be able to work with self-signed certs
var portPopup;
var portManager = null;
var notarization_in_progress = false;
var waiting_for_click = false;
var clickTimeout = null;
var requestBody = null; //will contain POST request's body
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
var appId = null; //Chrome uses to send message to external Chrome app. Firefox uses it's own id
var popupError = null; //set to non-null when there is some error message that must be shown
//via the popup
var testing = false;

function getPref(pref) {
  return new Promise(function(resolve, reject) {
    chrome.storage.local.get(pref, function(obj) {
      if (Object.keys(obj).length === 0) {
        resolve('undefined');
        return;
      } else {
        resolve(obj[pref]);
      }
    });
  });
}

function setPref(pref, value) {
  return new Promise(function(resolve, reject) {
    var obj = {};
    obj[pref] = value;
    chrome.storage.local.set(obj, function() {
      resolve();
    });
  });
}

function sendToPopup(data) {
  if (is_chrome) {
    chrome.runtime.sendMessage(data);
  } else {
    console.log('will postMessage ', data);
    portPopup.postMessage(data);
  }
}


function openManager() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/manager.html');
  //re-focus tab if manager already open
  chrome.tabs.query({}, function(tabs) {
    for (var i = 0; i < tabs.length; i++) {
      if (tabs[i].url === url) {
        chrome.tabs.update(tabs[i].id, {
          active: true
        });
        return;
      }
    }
    chrome.tabs.create({
      url: url
    });
  });
}



function notarizeAfterClickSelected() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/arrow24.png');
  chrome.browserAction.setIcon({
    path: url
  });
  waiting_for_click = true;
  clickTimeout = setTimeout(function() {
    chrome.webRequest.onBeforeRequest.removeListener(onBeforeRequestListener);
    loadNormalIcon();
    waiting_for_click = false;
    sendAlert({
      title: 'PageSigner error.',
      text: 'You haven\'t clicked any https:// links in 30 seconds. Please try again. If this error persists it may mean that the website you are trying to notarize is not compatible with PageSigner.'
    });
  }, 30 * 1000);

  //get current tab ID and install listener only for that tab

  chrome.tabs.query({
    active: true
  }, function(t) {
    //Note that onBeforeRequest triggers first and only then onBeforeSendHeaders
    chrome.webRequest.onBeforeRequest.addListener(
      onBeforeRequestListener, {
        urls: ["<all_urls>"],
        tabId: t[0].id,
        types: ["main_frame", "xmlhttprequest"]
      }, ["requestBody", "blocking"]);
  });
}


function onBeforeRequestListener(details) {
  if (waiting_for_click) {
    clearTimeout(clickTimeout);
    waiting_for_click = false;
  }
  console.log('in onBeforeRequestListener got details', details);
  if (details.method == 'POST') {
    //POST payload is only available from onBeforeRequest
    requestBody = details.requestBody;
  }

  var url = details.url;

  //kludge: FF wont trigger onBeforeSendHeaders for 127.0.0.1 url
  //which we use during testing
  if (testing && !is_chrome) url = '<all_urls>';

  chrome.webRequest.onBeforeSendHeaders.addListener(
    onBeforeSendHeadersListener, {
      urls: [url],
      tabId: details.tabId,
      types: [details.type]
    }, ["requestHeaders", "blocking"]);


  chrome.webRequest.onBeforeRequest.removeListener(onBeforeRequestListener);
  return {
    'cancel': false
  };
}


function onBeforeSendHeadersListener(details) {
  console.log('in onBeforeSendHeadersListener got details', details);
  details['requestBody'] = requestBody;
  var rv = getHeaders(details);
  //we must return fast hence the async invocation
  setTimeout(function() {
    startNotarizing(rv.headers, rv.server, rv.port);
  }, 0);
  var jsRunner = {
    'code': 'window.stop()'
  };
  chrome.tabs.executeScript(details.tabId, jsRunner);
  chrome.webRequest.onBeforeSendHeaders.removeListener(onBeforeSendHeadersListener);
  return {
    'cancel': true
  };
}


function notarizeNowSelected() {

  chrome.tabs.query({
    active: true
  }, function(t) {
    if (!t[0].url.startsWith('https://')) {
      sendAlert({
        'title': 'PageSigner error',
        'text': 'You can only notarize pages which start with https://'
      });
      return;
    }

    //Note that onBeforeRequest triggers first and only then onBeforeSendHeaders
    chrome.webRequest.onBeforeRequest.addListener(
      onBeforeRequestListener, {
        urls: ["<all_urls>"],
        tabId: t[0].id,
        types: ["main_frame"]
      }, ["requestBody", "blocking"]);

    //reload current tab in order to trigger the HTTP request
    chrome.tabs.reload(t[0].id);
  });
}


function getHeaders(obj) {
  var x = obj.url.split('/');
  var host = x[2].split(':')[0];
  x.splice(0, 3);
  var resource_url = x.join('/');
  var headers = obj.method + " /" + resource_url + " HTTP/1.1" + "\r\n";
  headers += "Host: " + host + "\r\n";
  for (var i = 0; i < obj.requestHeaders.length; i++) {
    var h = obj.requestHeaders[i];
    headers += h.name + ": " + h.value + "\r\n";
  }
  if (obj.method == "GET") {
    headers += "\r\n";
  } else if (obj.method == 'POST') {
    var formData = obj.requestBody.formData;
    var keys = Object.keys(formData);
    var content = '';
    for (var i = 0; i < keys.length; i++) {
      content += keys[i] + '=' + formData[keys[i]];
      if (i + 1 < keys.length) {
        content += '&';
      }
    }
    //Chrome doesn't expose Content-Length which chokes nginx
    headers += 'Content-Length: ' + parseInt(content.length) + '\r\n\r\n';
    headers += content;
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




function renamePGSG(dir, newname) {
  console.log('about to rename');
  writeFile(dir, 'meta', newname)
    .then(function() {
      chrome.storage.local.get(null, function(i) {
        console.log(i)
      });
      populateTable();
    });
}


function deletePGSG(dir) {
  chrome.storage.local.remove(dir, function() {
    populateTable();
  });
  return;
}

function process_message(data) {
  if (data.destination !== 'extension') return;
  console.log('ext got msg', data);
  if (data.message === 'rename') {
    renamePGSG(data.args.dir, data.args.newname);
  } else if (data.message === 'delete') {
    deletePGSG(data.args.dir);
  } else if (data.message === 'import') {
    verify_tlsn_and_show_data(data.args.data, true);
  } else if (data.message === 'export') {
    //Not in use: manager is doing the exporting
  } else if (data.message === 'notarize') {
    notarizeNowSelected();
  } else if (data.message === 'notarizeAfter') {
    notarizeAfterClickSelected();
  } else if (data.message === 'manage') {
    openManager();
  } else if (data.message === 'refresh') {
    populateTable();
  } else if (data.message === 'openLink1') {
    chrome.tabs.create({
      url: 'https://www.tlsnotary.org'
    });
  } else if (data.message === 'donate link') {
    chrome.tabs.create({
      url: 'https://www.tlsnotary.org/#Donate'
    });
  } else if (data.message === 'viewdata') {
    openTabs(data.args.dir);
  } else if (data.message === 'viewraw') {
    viewRaw(data.args.dir);
  } else if (data.message === 'file picker') {
    var prefix = is_chrome ? 'webextension/' : '';
    var url = chrome.extension.getURL(prefix + 'content/file_picker.html');
    chrome.tabs.create({
      url: url
    }, function(t) {
      console.log('tabid of file picker is', t.id);
    });
  } else if (data.message === 'openInstallLink') {
    //Chrome only
    chrome.tabs.create({
      url: 'https://chrome.google.com/webstore/detail/pagesigner-helper-app/oclohfdjoojomkfddjclanpogcnjhemd'
    });
  } else if (data.message === 'openChromeExtensions') {
    //Chrome only
    chrome.tabs.query({
      url: 'chrome://extensions/*'
    }, function(tabs) {
      if (tabs.length === 0) {
        chrome.tabs.create({
          url: 'chrome://extensions'
        });
        return;
      }
      chrome.tabs.update(tabs[0].id, {
        active: true
      });
    });
  } else if (data.message === 'popup active') {
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
}


function browser_specific_init() {
  getPref('valid_hashes')
    .then(function(hashes) {
      if (hashes !== 'undefined') {
        valid_hashes = hashes;
      }
    });
  //console.log('is_chrome', is_chrome);
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



function init() {
  setPref('testing', false)
    .then(function() {
      return getPref('verbose');
    })
    .then(function(value) {
      if (value !== true && !is_chrome) {
		//Firefox pollutes browser window, disable logging
        console.log = function(){};
      }
      return getPref('fallback');
    })
    .then(function(value) {
      if (value === true) {
        //TODO this should be configurable, e.g. choice from list
        //or set in prefs
        chosen_notary = pagesigner_servers[1];
        oracles_intact = true;
      } else {
        chosen_notary = oracles[Math.random() * (oracles.length) << 0];
        var oracle_hash = ba2hex(sha256(JSON.stringify(chosen_notary)));
        var was_oracle_verified = false;
        getPref('verifiedOracles.' + oracle_hash)
          .then(function(value) {
            if (value === true) {
              oracles_intact = true;
            } else {
              //async check oracles and if the check fails, sets a global var
              //which prevents notarization session from running
              console.log('oracle not verified');
              check_oracle(chosen_notary)
                .then(function success() {
                  return setPref('verifiedOracles.' + oracle_hash, 'bool', true);
                })
                .then(function() {
                  oracles_intact = true;
                })
                .catch(function(err) {
                  console.log('caught error', err);
                  //query for a new oracle
                  //TODO fetch backup oracles list
                });
            }
          });
      }
      import_reliable_sites();
      browser_init_finished = true;
    });
}


function import_reliable_sites() {
  import_resource('pubkeys.txt')
    .then(function(text_ba) {
      parse_reliable_sites(ba2str(text_ba));
    });
}


//we can import chrome:// and file:// URL
function import_resource(filename) {

  return new Promise(function(resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.responseType = "arraybuffer";
    xhr.onreadystatechange = function() {
      if (xhr.readyState != 4)
        return;

      if (xhr.response) {
        resolve(ab2ba(xhr.response));
      }
    };
    var path;
    if (is_chrome) path = chrome.extension.getURL('webextension/content/' + filename);
    if (!is_chrome) path = chrome.extension.getURL('content/' + filename);
    xhr.open('get', path, true);
    xhr.send();
  });
}

function get_xhr() {
  return new XMLHttpRequest();
}

function parse_reliable_sites(text) {
  var lines = text.split('\n');
  var name = "";
  var expires = "";
  var modulus = [];
  var i = -1;
  var x;
  var mod_str;
  var line;
  while (true) {
    i += 1;
    if (i >= lines.length) {
      break;
    }
    x = lines[i];
    if (x.startsWith('#')) {
      continue;
    } else if (x.startsWith('Name=')) {
      name = x.slice('Name='.length);
    } else if (x.startsWith('Expires=')) {
      expires = x.slice('Expires='.length);
    } else if (x.startsWith('Modulus=')) {
      mod_str = '';
      while (true) {
        i += 1;
        if (i >= lines.length) {
          break;
        }
        line = lines[i];
        if (line === '') {
          break;
        }
        mod_str += line;
      }
      modulus = [];
      var bytes = mod_str.split(' ');
      for (var j = 0; j < bytes.length; j++) {
        if (bytes[j] === '') {
          continue;
        }
        modulus.push(hex2ba(bytes[j])[0]);
      }
      //Don't use pubkeys which expire less than 3 months from now
      var ex = expires.split('/');
      var extime = new Date(parseInt(ex[2]), parseInt(ex[0]) - 1, parseInt(ex[1])).getTime();
      var now = new Date().getTime();
      if ((extime - now) < 1000 * 60 * 60 * 24 * 90) {
        continue;
      }
      reliable_sites.push({
        'name': name,
        'port': 443,
        'expires': expires,
        'modulus': modulus
      });
    }
    console.log('reliable sites are: ', reliable_sites);
  }
}


function startNotarizing(headers, server, port) {
  if (!oracles_intact) {
    //NotarizeAfterClick already changed the icon at this point, revert to normal
    loadNormalIcon();
    sendAlert({
      title: 'PageSigner error',
      text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
    });
    return;
  }
  var modulus;
  var certsha256;
  var chain;
  loadBusyIcon();
  get_certificate(server, port)
    .then(function(certchain) {
      chain = certchain;
      if (mustVerifyCert && !verifyCert(chain)) {
        sendAlert({
          title: "PageSigner error",
          text: "This website cannot be audited by PageSigner because it presented an untrusted certificate"
        });
        return;
      }
      modulus = getModulus(chain[0]);
      certsha256 = sha256(chain[0]);
      random_uid = Math.random().toString(36).slice(-10);
      previous_session_start_time = new Date().getTime();
      //loop prepare_pms 10 times until succeeds
      return new Promise(function(resolve, reject) {
        var tries = 0;
        var loop = function(resolve, reject) {
          tries += 1;
          prepare_pms(modulus).then(function(args) {
            resolve(args);
          }).catch(function(error) {
            console.log('caught error', error);
            if (error.startsWith('Timed out')) {
              reject(error);
              return;
            }
            if (error != 'PMS trial failed') {
              reject('in prepare_pms: caught error ' + error);
              return;
            }
            if (tries == 10) {
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
    .then(function(args) {
      return start_audit(modulus, certsha256, server, port, headers, args[0], args[1], args[2]);
    })
    .then(function(args2) {
      loadNormalIcon();
      return save_session_and_open_data(args2, server);
    })
    .catch(function(err) {
      //TODO need to get a decent stack trace
      loadNormalIcon();
      console.log('There was an error: ' + err);
      if (err === "Server sent alert 2,40") {
        sendAlert({
          title: 'PageSigner error',
          text: 'Pagesigner is not compatible with this website because the website does not use RSA ciphersuites'
        });
      } else if (err.startsWith('Timed out waiting for notary server to respond') &&
        ((new Date().getTime() - previous_session_start_time) < 60 * 1000)) {
        sendAlert({
          title: 'PageSigner error',
          text: 'You are signing pages way too fast. Please retry in 60 seconds'
        });
      } else {
        sendAlert({
          title: 'PageSigner error',
          text: err
        });
      }
    });
}



function save_session_and_open_data(args, server) {
  assert(args.length === 18, "wrong args length");
  var cipher_suite = args[0];
  var client_random = args[1];
  var server_random = args[2];
  var pms1 = args[3];
  var pms2 = args[4];
  var server_certchain = args[5];
  var tlsver = args[6];
  var initial_tlsver = args[7];
  var fullresp_length = args[8];
  var fullresp = args[9];
  var IV_after_finished_length = args[10];
  var IV_after_finished = args[11];
  var notary_modulus_length = args[12];
  var signature = args[13];
  var commit_hash = args[14];
  var notary_modulus = args[15];
  var data_with_headers = args[16];
  var time = args[17];

  var server_chain_serialized = []; //3-byte length prefix followed by cert
  for (var i = 0; i < server_certchain.length; i++) {
    var cert = server_certchain[i];
    server_chain_serialized = [].concat(
      server_chain_serialized,
      bi2ba(cert.length, {
        'fixed': 3
      }),
      cert);
  }

  var pgsg = [].concat(
    str2ba('tlsnotary notarization file\n\n'), [0x00, 0x02],
    bi2ba(cipher_suite, {
      'fixed': 2
    }),
    client_random,
    server_random,
    pms1,
    pms2,
    bi2ba(server_chain_serialized.length, {
      'fixed': 3
    }),
    server_chain_serialized,
    tlsver,
    initial_tlsver,
    bi2ba(fullresp_length, {
      'fixed': 8
    }),
    fullresp,
    bi2ba(IV_after_finished_length, {
      'fixed': 2
    }),
    IV_after_finished,
    bi2ba(notary_modulus_length, {
      'fixed': 2
    }),
    signature,
    commit_hash,
    notary_modulus,
    time);

  var commonName = getCommonName(server_certchain[0]);
  var creationTime = getTime();
  var session_dir = makeSessionDir(commonName, creationTime);
  writeFile(session_dir, 'creationTime', creationTime)
    .then(function() {
      return writeDatafile(data_with_headers, session_dir)
    })
    .then(function() {
      return writePgsg(pgsg, session_dir, commonName);
    })
    .then(function() {
      return openTabs(session_dir);
    })
    .then(function() {
      updateCache(sha256(pgsg));
      populateTable(); //refresh manager
    });
}


//data_with_headers is a string
function writeDatafile(data_with_headers, session_dir) {
  return new Promise(function(resolve, reject) {
    var rv = data_with_headers.split('\r\n\r\n');
    var headers = rv[0];
    var data = rv.splice(1).join('\r\n\r\n');
    var dirname = session_dir.split('/').pop();
    var header_lines = headers.split('\r\n');
    var type = 'html';
    for (var i = 0; i < header_lines.length; i++) {
      if (header_lines[i].search(/content-type:\s*/i) > -1) {
        if (header_lines[i].search("html") > -1) {
          type = 'html';
          break;
        } else if (header_lines[i].search("xml") > -1) {
          type = 'xml';
          break;
        } else if (header_lines[i].search("json") > -1) {
          type = 'json';
          break;
        } else if (header_lines[i].search("pdf") > -1) {
          type = 'pdf';
          break;
        } else if (header_lines[i].search("zip") > -1) {
          type = 'zip';
          break;
        }
      }
    }
    if (type === "html") {
      //disabling for now because there are no issues displaying without the marker
      //html needs utf-8 byte order mark
      //data = ''.concat(String.fromCharCode(0xef, 0xbb, 0xbf), data);
    }
    writeFile(dirname, 'metaDataFilename', 'data.' + type).then(function() {
      return writeFile(dirname, 'data.' + type, data);
    }).then(function() {
      return writeFile(dirname, 'raw.txt', data_with_headers);
    }).then(function() {
      resolve();
    });

  });
}



function writePgsg(pgsg, session_dir, commonName) {
  return new Promise(function(resolve, reject) {

    var dirname = session_dir.split('/').pop();
    var name = commonName.replace(/\*\./g, "");
    writeFile(dirname, 'pgsg.pgsg', pgsg).then(function() {
      return writeFile(dirname, 'meta', name);
    }).then(function() {
      return writeFile(dirname, 'metaDomainName', commonName);
    }).then(function() {
      resolve();
    });
  });
}


function writeFile(dirName, fileName, data) {
  if (data.length === 0) return;
  if (!is_chrome) {
    //weird that even though chrome.storage.local.get is available in FF53
    //it is undefined
    chrome = browser;
  }

  return new Promise(function(resolve, reject) {
    //get the Object, append data and write it back
    chrome.storage.local.get(dirName, function(items) {
      var obj = {};
      if (Object.keys(items).length > 0) {
        obj = items[dirName];
      }
      obj[fileName] = data;
      obj['lastModified'] = new Date().toString();
      chrome.storage.local.set({
        [dirName]: obj
      }, function() {
        //lastError undefined on Chrome and null on Firefox
        //TODO check error
        //if (! chrome.runtime.lastError){
        //	console.log('error in storage.local.set: ', chrome.runtime.lastError.message);
        //	}
        console.log('in WriteFile wrote: ', dirName, obj);
        resolve();
      });
    });
  });
}


//imported_data is an array of numbers
function verify_tlsn(data, from_past) {
  var offset = 0;
  if (ba2str(data.slice(offset, offset += 29)) !== "tlsnotary notarization file\n\n") {
    throw ('wrong header');
  }
  if (data.slice(offset, offset += 2).toString() !== [0x00, 0x02].toString()) {
    throw ('wrong version');
  }
  var cs = ba2int(data.slice(offset, offset += 2));
  var cr = data.slice(offset, offset += 32);
  var sr = data.slice(offset, offset += 32);
  var pms1 = data.slice(offset, offset += 24);
  var pms2 = data.slice(offset, offset += 24);
  var chain_serialized_len = ba2int(data.slice(offset, offset += 3));
  var chain_serialized = data.slice(offset, offset += chain_serialized_len);
  var tlsver = data.slice(offset, offset += 2);
  var tlsver_initial = data.slice(offset, offset += 2);
  var response_len = ba2int(data.slice(offset, offset += 8));
  var response = data.slice(offset, offset += response_len);
  var IV_len = ba2int(data.slice(offset, offset += 2));
  var IV = data.slice(offset, offset += IV_len);
  var sig_len = ba2int(data.slice(offset, offset += 2));
  var sig = data.slice(offset, offset += sig_len);
  var commit_hash = data.slice(offset, offset += 32);
  var notary_pubkey = data.slice(offset, offset += sig_len);
  var time = data.slice(offset, offset += 4);
  assert(data.length === offset, 'invalid .pgsg length');

  offset = 0;
  var chain = []; //For now we only use the 1st cert in the chain
  while (offset < chain_serialized.length) {
    var len = ba2int(chain_serialized.slice(offset, offset += 3));
    var cert = chain_serialized.slice(offset, offset += len);
    chain.push(cert);
  }

  var commonName = getCommonName(chain[0]);
  //verify cert
  if (!verifyCert(chain)) {
    throw ('certificate verification failed');
  }
  var modulus = getModulus(chain[0]);
  //verify commit hash
  if (sha256(response).toString() !== commit_hash.toString()) {
    throw ('commit hash mismatch');
  }
  //verify sig
  var signed_data = sha256([].concat(commit_hash, pms2, modulus, time));
  var signing_key;
  if (from_past) {
    signing_key = notary_pubkey;
  } else {
    signing_key = chosen_notary.modulus;
  }
  if (!verify_commithash_signature(signed_data, sig, signing_key)) {
    throw ('notary signature verification failed');
  }

  //decrypt html and check MAC
  var s = new TLSNClientSession();
  s.__init__();
  s.unexpected_server_app_data_count = response.slice(0, 1);
  s.chosen_cipher_suite = cs;
  s.client_random = cr;
  s.server_random = sr;
  s.auditee_secret = pms1.slice(2, 2 + s.n_auditee_entropy);
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
  return [html_with_headers, commonName, data, notary_pubkey];
}



function makeSessionDir(server, creationTime, is_imported) {

  if (typeof(is_imported) === "undefined") {
    is_imported = false;
  }
  var imported_str = is_imported ? "-IMPORTED" : "";
  var server_sanitized = server;
  if (server.search(/\*/) > -1) {
    var parts = server.split('.');
    server_sanitized = parts[parts.length - 2] + '.' + parts[parts.length - 1];
  }
  var name = 'session-' + creationTime + '-' + server_sanitized + imported_str;
  return name;
}


//imported_data is an array of numbers
function verify_tlsn_and_show_data(imported_data, create) {
  try {
    var a = verify_tlsn(imported_data, create);
  } catch (e) {
    sendAlert({
      title: 'PageSigner failed to import file',
      text: 'The error was: ' + e
    });
    return;
  }
  if (create) {
    var data_with_headers = a[0];
    var commonName = a[1];
    var imported_data = a[2];
    var creationTime = getTime();
    var session_dir = makeSessionDir(commonName, creationTime, true);
    writeFile(session_dir, 'creationTime', creationTime)
      .then(function() {
        return writeDatafile(data_with_headers, session_dir);
      })
      .then(function() {
        console.log('resolved from writeDataFile');
        return writePgsg(imported_data, session_dir, commonName);
      })
      .then(function() {
        console.log('resolved from writePgsg');
        openTabs(session_dir);
        updateCache(sha256(imported_data));
        populateTable(); //refresh manager
      })
      .catch(function(error) {
        console.log("got error in vtsh: " + error);
      });
  }
}


function openTabs(dirname) {
  var commonName;
  getFileContent(dirname, "metaDomainName")
    .then(function(data) {
      commonName = data;
      return getFileContent(dirname, "metaDataFilename");
    })
    .then(function(name) {
      return getFileContent(dirname, name);
    })
    .then(function(html) {
      var url;
      if (is_chrome) url = chrome.extension.getURL('webextension/content/viewer.html');
      if (!is_chrome) url = chrome.extension.getURL('content/viewer.html');
      chrome.tabs.create({
          url: url
        },
        function(t) {
          setTimeout(function() {
            chrome.runtime.sendMessage({
              destination: 'viewer',
              type: 'html',
              data: html,
              sessionId: dirname,
              serverName: commonName
            });
          }, 100);
        });
    });
}



function viewRaw(dirname) {
  var commonName;
  getFileContent(dirname, "metaDomainName")
    .then(function(data) {
      commonName = data;
      return getFileContent(dirname, "raw.txt");
    })
    .then(function(data) {
      var prefix = is_chrome ? 'webextension/' : '';
      var url = chrome.extension.getURL(prefix + 'content/viewer.html');
      chrome.tabs.create({
          url: url
        },
        function(t) {
          setTimeout(function() {
            chrome.runtime.sendMessage({
              destination: 'viewer',
              data: data,
              type: 'raw',
              sessionId: dirname,
              serverName: commonName
            });
          }, 100);
        });
    })
}




function getFileContent(dirname, filename) {
  return new Promise(function(resolve, reject) {

    chrome.storage.local.get(dirname, function(items) {
      //TODO check if dirname filename exist
      console.log('in getFileContent got', items);
      resolve(items[dirname][filename]);
    });
  });
}


function populateTable() {
  var prev_tdict = tdict;
  tdict = {};
  //get all sessions from storage
  chrome.storage.local.get(null, function(items) {
    var newEntries = [];
    var keys = Object.keys(items);
    for (var i = 0; i < keys.length; i++) {
      if (!keys[i].startsWith('session')) continue;
      if (!prev_tdict.hasOwnProperty(keys[i])) {
        newEntries.push(keys[i]);
        continue;
      }
      if (prev_tdict[keys[i]]['lastModified'] != items[keys[i]]['lastModified']) {
        newEntries.push(keys[i]);
        continue;
      }
      tdict[keys[i]] = prev_tdict[keys[i]];
    }
    processNewEntries(newEntries).then(function() {
      sendTable();
    });
  });
}


function processNewEntries(dirnames) {
  return new Promise(function(resolve, reject) {
    chrome.storage.local.get(dirnames, function(items) {
      var keys = Object.keys(items);
      for (var i = 0; i < keys.length; i++) {
        var imported = false;
        if (keys[i].match("-IMPORTED$") == "-IMPORTED") {
          imported = true;
        }
        tdict[keys[i]] = {
          'name': items[keys[i]]['meta'],
          'imported': imported,
          'hash': sha256(items[keys[i]]['pgsg.pgsg']),
          'pgsg': items[keys[i]]['pgsg.pgsg'],
          'modtime': items[keys[i]]['lastModified'],
          'creationTime': items[keys[i]]['creationTime'],
          'dir': keys[i]
        };
      }
      resolve();
    });
  });
}


//Also check validity of pgsg before sending
function sendTable() {
  var rows = [];
  for (var key in tdict) {
    var row = tdict[key];
    var is_valid = false;
    if (valid_hashes.indexOf(row.hash.toString()) > -1) {
      is_valid = true;
    } else { //e.g. for some reason the cache was flushed
      try {
        verify_tlsn(row.pgsg, true);
        //if it doesnt throw - the check passed
        is_valid = true;
        updateCache(row.hash);
      } catch (e) {
        is_valid = false;
      }
    }
    rows.push({
      'name': row.name,
      'imported': row.imported,
      'valid': is_valid,
      'verifier': 'tlsnotarygroup4',
      'creationTime': row.creationTime,
      'dir': row.dir
    });
  }
  sendToManager(rows);
}


function sendToManager(data) {
  console.log('sending sendToManager ', data);
  if (is_chrome) {
    chrome.runtime.sendMessage({
      'destination': 'manager',
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


function getModulus(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der');
  var pk = c.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data;
  var pkba = ua2ba(pk);
  //expected modulus length 256, 384, 512
  var modlen = 256;
  if (pkba.length > 384) modlen = 384;
  if (pkba.length > 512) modlen = 512;
  var modulus = pkba.slice(pkba.length - modlen - 5, pkba.length - 5);
  return modulus;
}


function getCommonName(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der');
  var fields = c.tbsCertificate.subject.value;
  for (var i = 0; i < fields.length; i++) {
    if (fields[i][0].type.toString() !== [2, 5, 4, 3].toString()) continue;
    //first 2 bytes are DER-like metadata
    return ba2str(fields[i][0].value.slice(2));
  }
  return 'unknown';
}


function permutator(inputArr) {
  var results = [];

  function permute(arr, memo) {
    var cur, memo = memo || [];

    for (var i = 0; i < arr.length; i++) {
      cur = arr.splice(i, 1);
      if (arr.length === 0) {
        results.push(memo.concat(cur));
      }
      permute(arr.slice(), memo.concat(cur));
      arr.splice(i, 0, cur[0]);
    }

    return results;
  }

  return permute(inputArr);
}


function verifyCert(chain) {
  var chainperms = permutator(chain);
  for (var i = 0; i < chainperms.length; i++) {
    if (verifyCertChain(chainperms[i])) {
      return true;
    }
  }
  return false;
}



function updateCache(hash) {
  if (!(hash.toString() in valid_hashes)) {
    valid_hashes.push(hash.toString());
    chrome.storage.local.set({
      'valid_hashes': valid_hashes
    });
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

  chrome.tabs.query({
    active: true
  }, function(tabs) {
    if (chrome.extension.lastError) {
      uglyAlert(alertData);
      return;
    }
    chrome.tabs.executeScript(tabs[0].id, {
      file: (prefix + 'content/sweetalert.min.js')
    }, function() {
      if (chrome.extension.lastError) {
        uglyAlert(alertData);
        return;
      }
      chrome.tabs.insertCSS(tabs[0].id, {
        file: (prefix + 'content/sweetalert.css')
      }, function() {
        if (chrome.extension.lastError) {
          uglyAlert(alertData);
          return;
        }
        chrome.tabs.executeScript(tabs[0].id, {
          code: "swal(" + JSON.stringify(alertData) + ")"
        });
        if (chrome.extension.lastError) {
          uglyAlert(alertData);
          return;
        }
      });
    });
  });
}


function loadBusyIcon() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/icon_spin.gif');
  chrome.browserAction.setIcon({
    path: url
  });
  notarization_in_progress = true;
}

function loadNormalIcon() {
  var prefix = is_chrome ? 'webextension/' : '';
  var url = chrome.extension.getURL(prefix + 'content/icon.png');
  chrome.browserAction.setIcon({
    path: url
  });
  notarization_in_progress = false;
}


function Socket(name, port) {
  this.name = name;
  this.port = port;
  this.uid = Math.random().toString(36).slice(-10);
  this.buffer = [];
  this.recv_timeout = 20 * 1000;
}
//inherit the base class
Socket.prototype = Object.create(AbstractSocket.prototype);
Socket.prototype.constructor = Socket;

Socket.prototype.connect = function() {
  var that = this;
  return new Promise(function(resolve, reject) {
    chrome.runtime.sendMessage(appId, {
        'command': 'connect',
        'args': {
          'name': that.name,
          'port': that.port
        },
        'uid': that.uid
      },
      function(response) {
        console.log('in connect response', response);
        clearInterval(timer);
        if (response.retval === 'success') {
          //endless data fetching loop for the lifetime of this Socket
          var fetch = function() {
            chrome.runtime.sendMessage(appId, {
              'command': 'recv',
              'uid': that.uid
            }, function(response) {
              console.log('fetched some data', response.data.length, that.uid);
              that.buffer = [].concat(that.buffer, response.data);
              setTimeout(function() {
                fetch()
              }, 100);
            });
          };
          //only needed for Chrome
          fetch();
          resolve('ready');
        }
        reject(response.retval);
      });
    //dont wait for connect for too long
    var timer = setTimeout(function() {
      reject('connect: socket timed out');
    }, 1000 * 20);
  });
};
Socket.prototype.send = function(data_in) {
  chrome.runtime.sendMessage(appId, {
    'command': 'send',
    'args': {
      'data': data_in
    },
    'uid': this.uid
  });
};
Socket.prototype.close = function() {
  console.log('closing socket', this.uid);
  chrome.runtime.sendMessage(appId, {
    'command': 'close',
    'uid': this.uid
  });
};


//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
browser_specific_init();
