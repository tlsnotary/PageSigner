/* global chrome */

// class ProgressMonitor receives progress information about client's garbling,
// evaluation, blob upload, blob download. It dispatches progress status messages
// periodically or when queried.
// because Chrome has a bug and does not remove onMessage listener, we
// use only one ProgressMonitor and reset its state when a new notarization
// session starts

export class ProgressMonitor{
  constructor(){
    this.progress = {
      download: {},
      upload: {},
      garbling: {},
      last_stage: {},
      first_time: {},
    };
    // progress listeners may ask to give the current progress state
    const that = this;
    chrome.runtime.onMessage.addListener(function(data) {
      if (data.destination != 'progress monitor') return;
      chrome.runtime.sendMessage({
        destination: 'progress listeners',
        progress: that.progress
      });
    });

  }

  init(){
    this.progress = {
      download: {},
      upload: {},
      garbling: {},
      last_stage: {},
      first_time: {},
    };
  }

  // update is called with updates progress information
  update(type, obj){
    this.progress[type] = obj;
    chrome.runtime.sendMessage({
      destination: 'progress listeners',
      progress: this.progress
    });
  }

  // destroy de-registers listeners
  // doesn't do anything because of what seems like a Chrome bug.
  destroy(){
    // TODO it seems like Chrome does not remove onMessage listener
    chrome.runtime.onMessage.removeListener(this.listener);
  }
}