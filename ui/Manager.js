/* global chrome, swal*/

import {str2ba} from './utils.js';

document.addEventListener('load', onload);
window.addEventListener('load', onload);

class Manager{
  constructor(){
    window.tabid = null;
    window.isManager = true;
    // isReady will be se to true after message listener is installed
    window.isReady = false;
  }

  main() {
    const that = this;
    chrome.runtime.onMessage.addListener(function(data) {
      if (data.destination != 'manager') return;
      if (data.command == 'payload'){
        console.log('data.payload', data.payload);
        that.processData(data.payload);
      }
      else if (data.command == 'export'){
        // .payload contains {pgsg: json, name: session_name}
        const exportedBlobUrl = URL.createObjectURL(new Blob([str2ba(data.payload.pgsg)]), {
          type: 'application/octet-stream'
        });
        var fauxLink = document.createElement('a');
        fauxLink.href = exportedBlobUrl;
        fauxLink.setAttribute('download', data.payload.name+'.pgsg');
        document.body.appendChild(fauxLink);
        fauxLink.click();
      }
    });
    window.isReady = true;
    chrome.runtime.sendMessage({
      destination: 'extension',
      message: 'refresh'
    });
  }

  processData(rows) {
    const tb = document.getElementsByTagName('tbody')[0];
    const initial_row_length = tb.rows.length;
    for (let j = 0; j < initial_row_length; j++) {
      tb.deleteRow(0);
    }
    // create descending sort order based on creation time
    rows.sort(function(a, b) {
      return Date.parse(a.creationTime) < Date.parse(b.creationTime) ? 1 : -1;
    });

    for (const r of rows) {
      this.addRow({
        'sessionName': r.sessionName,
        'serverName': r.serverName,
        'isImported': r.isImported,
        'isEdited': r.isEdited,
        'creationTime': r.creationTime,
        'version': r.version
      });
    }
  }


  addRow(args) {
    const that = this;
    const sid = args.creationTime;
    const tb = document.getElementById('tableBody');
    const row = tb.insertRow(tb.rows.length);

    const td_session = document.createElement('td');
    if (args.isImported){
      const importedIcon = document.createElement('img');
      importedIcon.src = '../img/import.svg';
      importedIcon.width = 16;
      importedIcon.height = 16;
      importedIcon.style.marginLeft = 5;
      importedIcon.style.marginRight = 5;
      importedIcon.title = 'This notarization session was imported';
      td_session.appendChild(importedIcon);
    }
    if (args.isEdited){
      const editedIcon = document.createElement('img');
      editedIcon.src = '../img/edited.svg';
      editedIcon.width = 16;
      editedIcon.height = 16;
      editedIcon.style.marginLeft = 5;
      editedIcon.style.marginRight = 5;
      editedIcon.title = 'This notarization session was edited';
      td_session.appendChild(editedIcon);
    }
    td_session.appendChild(document.createTextNode(args.sessionName));

    const iconDiv = document.createElement('div');

    const imgExp = document.createElement('img');
    imgExp.classList.add('icon');
    imgExp.src = '../img/export.svg';
    imgExp.width = 20;
    imgExp.height = 20;
    imgExp.style.marginLeft = 10;
    imgExp.title = 'Export the session so you can transfer it to others';
    imgExp.onclick = function(event) {
      console.log('export clicked');
      swal({
        title: 'You MUST LOG OUT before exporting',
        text: 'Before exporting you MUST LOG OUT of any sessions associated with the data you are about to export. Please LOG OUT NOW if you have any active sessions running and press OK to proceed',
        type: 'warning'
      },
      function() {
        chrome.runtime.sendMessage({
          destination: 'extension',
          message: 'export',
          sid: sid
        });
      });
    };
    imgExp.value = 'Export';
    iconDiv.appendChild(imgExp);

    const imgRen = document.createElement('img');
    imgRen.classList.add('icon');
    imgRen.src = '../img/rename.svg';
    imgRen.width = 20;
    imgRen.height = 20;
    imgRen.style.marginLeft = 10;
    imgRen.title = 'Give the session a more memorable name';
    imgRen.onclick = function(event) {
      that.doRename(event.target, sid);
    };
    iconDiv.appendChild(imgRen);

    const imgDel = document.createElement('img');
    imgDel.classList.add('icon');
    imgDel.src = '../img/delete.svg';
    imgDel.width = 20;
    imgDel.height = 20;
    imgDel.style.marginLeft = 10;
    imgDel.title = 'Permanently remove this session from disk';
    imgDel.onclick = function() {
      swal({
        title: 'Removing notarization data',
        text: 'This will remove the selected session: ' + args.sessionName + '. Are you sure?',
        type: 'warning'
      },
      function() {
        chrome.runtime.sendMessage({
          destination: 'extension',
          message: 'delete',
          sid: sid
        });
      });
    };
    imgDel.value = 'Delete';
    iconDiv.appendChild(imgDel);

    iconDiv.style.position = 'absolute';
    iconDiv.style.top = 2;
    iconDiv.style.right = 4;

    td_session.style.position = 'relative';
    td_session.appendChild(iconDiv);
    row.appendChild(td_session);

    const td_time = document.createElement('td');
    td_time.style.textAlign = 'center';
    td_time.textContent = args.creationTime;
    row.appendChild(td_time);

    const buttonDiv = document.createElement('div');

    const input1 = document.createElement('input');
    input1.type = 'button';
    input1.className = 'btn';
    input1.onclick = function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'showSession',
        sid: sid
      });
    };
    input1.value = 'HTML';
    buttonDiv.appendChild(input1);

    const input2 = document.createElement('input');
    input2.type = 'button';
    input2.className = 'btn';
    input2.onclick = function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'showDetails',
        sid: sid
      });
    };
    input2.value = 'Details';
    buttonDiv.appendChild(input2);

    const input3 = document.createElement('input');
    input3.type = 'button';
    input3.className = 'btn';
    input3.onclick = function() {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'raw editor',
        sid: sid
      });
    };
    input3.value = 'Edit';
    // Edit button will be used in fututre versions
    input3.style.visibility = 'hidden';
    if (args.isImported || args.isEdited || (args.version < 5)){
      input3.style.opacity = '0.3';
      input3.onclick = null;
      input3.title='You cannot edit sessions which were already edited or which were imported.';
      if (args.version < 5){
        input3.title='This session has an old version which cannot be edited';
      }
    }
    buttonDiv.appendChild(input3);

    const td3 = document.createElement('td');
    td3.style.textAlign = 'center';
    td3.appendChild(buttonDiv);
    row.appendChild(td3);
  }

  doRename(t, sid) {
    var isValid = (function() {
      var rg1 = /^[^\\/:\*\?"<>\|]+$/; // forbidden characters \ / : * ? " < > |
      var rg2 = /^\./; // cannot start with dot (.)
      var rg3 = /^(nul|prn|con|lpt[0-9]|com[0-9])(\.|$)/i; // forbidden file names
      return function isValid(fname) {
        if  (typeof(fname) !== 'string') return false;
        return rg1.test(fname) && !rg2.test(fname) && !rg3.test(fname);
      };
    })();
    swal({
      title: 'Enter a new name for the notarization file',
      type: 'input',
      inputPlaceholder: 'e.g. my profile'
    },
    function(new_name) {
      if (!(isValid(new_name))) {
        console.log('detected invalid name', new_name);
        // swal glitch - need a timeout
        setTimeout(function() {
          swal({
            title: 'Invalid filename',
            text: 'Please only use alphanumerical characters',
            type: 'warning'
          });
        }, 200);
      } else if (new_name === null) return; // escape pressed
      else {
        chrome.runtime.sendMessage({
          destination: 'extension',
          message: 'rename',
          sid: sid,
          newname: new_name
        });
      }
    });
  }
}

new Manager().main();
