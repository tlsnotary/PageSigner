/* global chrome*/

import {decode_str} from './utils.js';

// DetailsViewer show session details: raw request, response, notarization time
class DetailsViewer{
  constructor(){
    window.tabid = null; // allow the extension to put the id of the tab which opened this page
    window.isDetailsViewer = true;
    // isReady will be se to true after message listener is installed
    window.isReady = false;
  }

  main(){
    chrome.runtime.onMessage.addListener(function(obj) {
      if (obj.destination !== 'detailsViewer') return;
      console.log('got obj', obj);
      if (obj.tabId != window.tabid) return;
      document.getElementById('request').textContent = decode_str(obj.request);
      document.getElementById('response').textContent = decode_str(obj.response);
      if (obj.sessionId != undefined){
        document.getElementById('notarization_time').textContent = obj.sessionId;
      }
    });
    window.isReady = true;
  }
}

window.detailsViewer = new DetailsViewer();
window.detailsViewer.main();

