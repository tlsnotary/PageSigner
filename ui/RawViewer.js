import {decode_str} from './utils.js';

class RawViewer{
  constructor(){
    window.tabid = null; // allow the extension to put the id of the tab which opened this page
    window.isRawViewer = true;
    // isReady will be se to true after message listener is installed
    window.isReady = false;
  }
  
  main(){
    chrome.runtime.onMessage.addListener(function(obj) {
      if (obj.destination !== 'rawviewer') return;
      console.log('got obj', obj);
      if (obj.tabId != window.tabid) return;
      const request = decode_str(obj.data.request);
      const response = decode_str(obj.data.response);
      document.getElementById('request').textContent = request;
      document.getElementById('response').textContent = response;
      document.getElementById('notarization_time').textContent = obj.data.sessionId;
    });
    window.isReady = true;
  }
}

window.rawViewer = new RawViewer();
window.rawViewer.main();

