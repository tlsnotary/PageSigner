/* global chrome*/

import {NotificationBar} from './NotificationBar.js';
import {FileChooser} from './FileChooser.js';
import {decode_str, str2ba } from './utils.js';

class Viewer{
  constructor(){
    window.tabid = null; // allow the extension to put the id of the tab which opened this page
    window.isViewer = true;
    // isFileChooser will be toggled to true if extension calls Main.openFileChooser()
    window.isFileChooser = false;
    // isReady will be se to true after message listener is installed
    window.isReady = false;
  }

  main(){
    console.log('in viewer main');
    const that = this;
    chrome.runtime.onMessage.addListener(function(msg) {
      console.log('got msg', msg);
      if (msg.destination === 'fileChooser' && window.isFileChooser) {
        if (msg.message === 'duplicate'){
          that.showDuplicateNotice(msg.date, msg.name);
          return;
        }
        else {
          throw 'unexpected message';
        }
      }
      if (msg.destination !== 'viewer') return;
      if (msg.tabId != window.tabid) return;
      if (msg.message != 'show'){
        throw 'unexpected message';
      }
      console.log('got data in viewer');
      let hideButton = false;
      console.log('text size is', msg.response.length);
      // remove the HTTP headers
      let http_body = msg.response.split('\r\n\r\n').splice(1).join('\r\n\r\n');

      let type = that.getType(msg.response);
      if (['html', 'json', 'xml', 'txt'].indexOf(type) > -1) {
      // add CSP to prevent loading any resources from the page
        const csp = '<meta http-equiv=\'Content-Security-Policy\' content="default-src \'none\'; img-src data:"></meta>\r\n';
        document.write(csp + decode_str(http_body));
      }
      else {
      // a file which cannot be shown but has to be downloaded like e.g. PDF
        document.getElementById('type').textContent = type;
        document.getElementById('view file button').onclick = function() {
          that.view_file(str2ba(http_body), msg.serverName + '.' + type);};
        document.getElementById('view file').removeAttribute('hidden');
      }
      console.log('msg.data.sessionId', msg.sessionId);
      setTimeout(function(){
        // we need timeout because the body may not yet be available
        new NotificationBar().show(msg.sessionId, msg.serverName, msg.request,
          msg.response, hideButton);
        document.body.style.marginTop = '30px';
      }, 1000);
    });
    window.isReady = true;
  }


  getType (data_with_headers){
    const headers = data_with_headers.split('\r\n\r\n')[0];
    const header_lines = headers.split('\r\n');
    for (const line of header_lines) {
      if (line.search(/content-type:\s*/i) < 0) continue;
      if (line.match('application/pdf')){
        return 'pdf';
      }
      else if (line.match('image/jpeg')){
        return 'jpg';
      }
      return 'html';
    }
  }

  view_file(data, filename){
    console.log('view file button clicked');
    // create an invisible download link
    var exportedBlobUrl = URL.createObjectURL(new Blob([data]), {
      type: 'application/octet-stream'
    });
    var fauxLink = document.createElement('a');
    fauxLink.href = exportedBlobUrl;
    fauxLink.setAttribute('download', filename);
    document.body.appendChild(fauxLink);
    fauxLink.click();
  }

  showFileChooser(){
    console.log('in showFileChooser');
    window.isFileChooser = true;
    const fc = new FileChooser();
    fc.show();
  }

  showDuplicateNotice(date, name){
    document.getElementById('loader').setAttribute('hidden', true);
    document.getElementById('duplicate notice').removeAttribute('hidden');
    document.getElementById('dup name').textContent = name;
    document.getElementById('dup date').textContent = date;
    document.getElementById('dup open manager').addEventListener('click', function() {
      chrome.runtime.sendMessage({
        'destination': 'extension',
        'message': 'viewdata',
        'args': {
          'dir': date
        }
      });
    });
  }
}

window.viewer = new Viewer();
window.viewer.main();