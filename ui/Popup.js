/* global chrome, browser*/

class Popup{
  constructor(){
    window.tabid = 1; // to distinguish this view during .getViews()
    this.currentUrl; // the url at the time when the user clicks notarize
    this.hasPermission; // shows whether currentUrl has already been allowed in Firefox
    this.is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
    this.is_edge = window.navigator.userAgent.match('Edg') ? true : false;
    this.is_firefox = window.navigator.userAgent.match('Firefox') ? true : false;
    this.is_opera = window.navigator.userAgent.match('OPR') ? true : false;

    // in Firefox we need to know the current URL before the user clicks notarize
    // to pass it to the click event listener so that it could run synchronously.
    // document.getElementById("notarize").addEventListener("mouseover",
    // function() {
    //   chrome.tabs.query({active: true}, async function(t) {
    //     currentUrl = t[0].url
    //     hasPermission = await browser.permissions.contains({origins: [currentUrl]})
    //   })
    // })

    const that = this;
    document.getElementById('notarize').addEventListener('click', function(){
      that.notarizeClicked(false);
    });

    document.getElementById('notarizeNow').addEventListener('click', function(){
      that.notarizeNowClicked(false);
    });

    document.getElementById('preview').addEventListener('click', function(){
      that.previewClicked(false);
    });

    document.getElementById('manage').addEventListener('click', function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'manage'
      });
      window.close();
    });

    document.getElementById('import').addEventListener('click', function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'fileChooser'
      });
      window.close();
    });

    document.getElementById('about').addEventListener('click', function() {
      document.getElementById('menu').hidden = true;
      document.getElementById('aboutWindow').hidden = false;
    });

    document.getElementById('app_disabled').addEventListener('click', function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'openChromeExtensions'
      });
      window.close();
    });

    chrome.runtime.onMessage.addListener(function(data) {
      that.processMessages(data);
    });

    chrome.runtime.sendMessage({
      destination: 'extension',
      message: 'popup active'
    });
  }

  // notarizeClicked triggers a dropdown menu when "Notarize this page" was pressed
  notarizeClicked(){
    const nn = document.getElementById('notarizeNow');
    const p = document.getElementById('preview');
    const pe = document.getElementById('previewExplanation');
    if (nn.hidden == true){
      nn.hidden = false;
      p.hidden = false;
      pe.hidden = false;
    } else {
      nn.hidden = true;
      p.hidden = true;
      pe.hidden = true;
    }
    return;
  }

  // notarizeNowClicked is triggered when "Notarize now" was pressed
  notarizeNowClicked(isAfterClick){
    isAfterClick = isAfterClick || false;
    const msg = isAfterClick ? 'notarizeAfter' : 'notarize';
    if (this.is_firefox && ! this.hasPermission && this.currentUrl.startsWith('https://')){
      // in Firefox we give a temporary permission just for the current tab's URL
      // also no async/await/callback here, otherwise Firefox will complain
      for (let el of document.getElementsByTagName('div')){
        el.setAttribute('hidden', '');
      }
      document.getElementById('grantPermission').removeAttribute('hidden');
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'pendingAction',
        action: msg
      });
      browser.permissions.request({origins: [this.currentUrl]});
    }
    else {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: msg
      });
    }
    if (isAfterClick){
      window.close();
    }
  }

  previewClicked(){
    chrome.runtime.sendMessage({
      destination: 'extension',
      message: 'preview'
    });
    window.close();
  }

  processMessages(data) {
    console.log('popup got message', data);
    if (data.destination !== 'popup') return;
    if (data.message === 'app_not_installed') {
      document.getElementById('menu').removeAttribute('hidden');
      var notarize = document.getElementById('notarize');
      notarize.setAttribute('hidden', true);
      if (this.is_edge || this.is_firefox || this.is_opera){
        const appNotInstalledFirefox = document.getElementById('appNotInstalledFirefox');
        appNotInstalledFirefox.removeAttribute('hidden');
        var showScript = document.getElementById('showPythonScript');
        showScript.onclick = function(){
          chrome.runtime.sendMessage({
            destination: 'extension',
            message: 'open python script'
          });
          window.close();
        };
      }
      else {
        document.getElementById('appNotInstalledChrome').removeAttribute('hidden');
        var openWebStore = document.getElementById('openWebStore');
        openWebStore.onclick = function(){
          chrome.tabs.create({url: 'https://chrome.google.com/webstore/detail/pagesigner-helper-app/oclohfdjoojomkfddjclanpogcnjhemd'});
        };
      }
    } else if (data.message === 'app_disabled') {
      document.getElementById('app_disabled').removeAttribute('hidden');
    } else if (data.message === 'show_menu') {
      document.getElementById('menu').removeAttribute('hidden');
    } else if (data.message === 'notarization_in_progress') {
      this.showInProgressDiv(data.firstTime);
    } else if (data.message === 'waiting_for_click') {
      document.getElementById('waiting_for_click').removeAttribute('hidden');
    } else if (data.message === 'popup error') {
      console.log('got popup error with', data);
      const error_div = document.getElementById('popup_error');
      error_div.removeAttribute('hidden');
      const error_text = document.getElementById('popup_error_text');
      error_text.textContent =  data.data.title + ' ' +data.data.text;
    } else {
      console.log('popup received unexpected message ' + data.message);
    }
  }

  // showInProgressDiv show the <div> with progress info and listens for
  // progress updates
  showInProgressDiv(isFirstTimeSetup){
    document.getElementById('menu').setAttribute('hidden', '');
    document.getElementById('in_progress').removeAttribute('hidden');

    const progressBars = {};
    const types = ['download', 'upload', 'garbling', 'last_stage'];
    if (isFirstTimeSetup){
      types.push('first_time');
      document.getElementById('first_time_progress_div').removeAttribute('hidden');
    }
    for (const type of types){
      const bar = document.getElementById(type+'_progress_bar');
      progressBars[type] = bar;
    }

    const that = this;
    chrome.runtime.onMessage.addListener(function(data) {
      if (data.destination != 'progress listeners') return;
      for (const type of types){
        const obj = data.progress[type];
        if (obj == undefined) continue;
        const value = Math.ceil((obj.current / obj.total)*100);
        if (isNaN(value)) continue;
        that.moveBar(progressBars[type], value);
        if (type === 'download'){
          const mbCount = Math.floor(obj.total / (1024*1024));
          document.getElementById('download_MB').textContent = String(mbCount);
          document.getElementById('upload_MB').textContent = String(mbCount);
        }
      }
    });

    // ask for an initial update, all future updates will arrive only
    // when there is actually stuff to update
    chrome.runtime.sendMessage({
      destination: 'progress monitor'
    });
  }


  moveBar(bar, goalWidth) {
    const curWidth = Number(bar.style.width.slice(0, -1));
    if (curWidth === goalWidth){
      return; // no update needed
    }
    bar.style.width = String(goalWidth) + '%';
    bar.innerHTML = String(goalWidth) + '%';
  }
}

new Popup();






















