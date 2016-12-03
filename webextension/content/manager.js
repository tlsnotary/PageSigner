var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
var port;

var table_populated = false; //used in testing only
chrome.storage.local.get('testing', function(obj) {
  if (obj.testing == true) {
    var script = document.createElement('script');
    script.src = 'testing/manager_test.js';
    document.body.appendChild(script);
  }
});

function onload() {
  if (is_chrome) {
    chrome.runtime.onMessage.addListener(function(data) {
      if (data.destination == 'manager') {
        console.log('hooray', data.payload);
        process_data(data.payload);
      }
    });
  } else {
    port = chrome.runtime.connect({
      name: "manager-to-extension"
    });
    port.onMessage.addListener(function(data) {
      //console.log("Message from legacy add-on: ", data);
      process_data(data.payload);
    });
  }

  sendMessage({
    'destination': 'extension',
    'message': 'refresh'
  });
}

document.addEventListener('load', onload);
window.addEventListener('load', onload);


function process_data(rows) {
  tb = document.getElementsByTagName('tbody')[0];
  var initial_row_length = tb.rows.length;
  for (var j = 0; j < initial_row_length; j++) {
    tb.deleteRow(0);
  }
  //create descending sort order based on creation time
  rows.sort(function(a, b) {
    var as = a.creationTime,
      bs = b.creationTime;
    return as == bs ? 0 : (as < bs ? 1 : -1);
  });

  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    addRow({
      'name': r.name,
      'imported': r.imported,
      'valid': r.valid,
      'verifier': r.verifier,
      'creationTime': r.creationTime,
      'dir': r.dir
    });
  }
  table_populated = true;
}



function addRow(args) {
  var dir = args.dir;
  var tb, row, td, a, img, text;
  tb = document.getElementById('myTableBody');
  row = tb.insertRow(tb.rows.length);

  td = document.createElement("td");
  td.id = 'toprightimg';
  td.appendChild(document.createTextNode(args.name));
  var importimg = document.createElement("img");
  importimg.src = 'import.png';
  importimg.width = 12;
  importimg.height = 12;
  importimg.id = 'topright';
  importimg.title = 'This notarization file was imported';
  if (!args.imported) {
    importimg.hidden = true;
  }
  td.appendChild(importimg);

  row.appendChild(td);

  td = document.createElement("td");
  a = document.createElement("a");
  a.title = 'Give the file a more memorable name';
  a.style = 'float: right';
  a.onclick = function(event) {
    doRename(event.target, args.name, dir);
  };
  a.text = 'Rename';
  td.appendChild(a);
  row.appendChild(td);

  td = document.createElement("td");
  a = document.createElement("a");
  a.title = 'Save the file so you can transfer it to others';
  a.style = 'float: right';
  a.onclick = function(event) {
    console.log('export clicked');
    swal({
        title: 'You MUST LOG OUT before exporting',
        text: 'Before exporting you MUST LOG OUT of any sessions associated with the data you are about to export. Please LOG OUT NOW if you have any active sessions running and press OK to proceed',
        type: "warning"
      },
      function() {
        //sendMessage({'destination':'extension','message':'export', 'args':{'dir': dir, 'file': args.name}});
        //get the Blob and create an invisible download link
        chrome.storage.local.get(dir, function(item) {

          function ba2ab(ba) {
            var ab = new ArrayBuffer(ba.length);
            var dv = new DataView(ab);
            for (var i = 0; i < ba.length; i++) {
              dv.setUint8(i, ba[i]);
            }
            return ab;
          };

          var ba = item[dir]['pgsg.pgsg'];
          var ab = ba2ab(ba);
          var exportedBlob = new Blob([ab]);
          var exportedBlobUrl = URL.createObjectURL(exportedBlob, {
            type: 'application/octet-stream'
          });
          var fauxLink = document.createElement('a');
          fauxLink.href = exportedBlobUrl;
          fauxLink.setAttribute('download', item[dir]['meta'] + '.pgsg');
          document.body.appendChild(fauxLink);
          fauxLink.click();
        });
      });
  };
  a.text = 'Export';
  td.appendChild(a);
  row.appendChild(td);

  td = document.createElement("td");
  a = document.createElement("a");
  a.title = 'permanently remove this set of files from disk';
  a.style = 'float: right';
  a.onclick = function(event) {
    swal({
        title: 'Removing notarization data',
        text: "This will remove all notarized data of " + args.name + ". Are you sure?",
        type: "warning"
      },
      function() {
        sendMessage({
          'destination': 'extension',
          'message': 'delete',
          'args': {
            'dir': dir
          }
        });
      });
  };
  a.text = 'Delete';
  td.appendChild(a);
  row.appendChild(td);

  td = document.createElement("td");
  td.textContent = args.creationTime;
  row.appendChild(td);

  td = document.createElement("td");
  img = document.createElement("img");
  img.height = 30;
  img.width = 30;
  var label;
  if (args.valid) {
    img.src = 'check.png';
    label = 'valid';
  } else {
    img.src = 'cross.png';
    label = 'invalid';
  }
  text = document.createElement("text");
  text.textContent = label;
  td.appendChild(img);
  td.appendChild(text);
  row.appendChild(td);

  td = document.createElement("td");
  td.textContent = args.verifier;
  row.appendChild(td);

  td = document.createElement("td");
  a = document.createElement("a");
  a.onclick = function(event) {
    sendMessage({
      'destination': 'extension',
      'message': 'viewdata',
      'args': {
        'dir': dir
      }
    });
  };
  a.text = "view";
  td.appendChild(a);
  text = document.createElement("text");
  text.textContent = ' , ';
  td.appendChild(text);
  a = document.createElement("a");
  a.onclick = function(event) {
    sendMessage({
      'destination': 'extension',
      'message': 'viewraw',
      'args': {
        'dir': dir
      }
    });
  };
  a.text = "raw";
  td.appendChild(a);

  row.appendChild(td);
}


function doRename(t, oldname, dir) {
  var isValid = (function() {
    var rg1 = /^[^\\/:\*\?"<>\|]+$/; // forbidden characters \ / : * ? " < > |
    var rg2 = /^\./; // cannot start with dot (.)
    var rg3 = /^(nul|prn|con|lpt[0-9]|com[0-9])(\.|$)/i; // forbidden file names
    return function isValid(fname) {
      return rg1.test(fname) && !rg2.test(fname) && !rg3.test(fname);
    };
  })();
  swal({
      title: "Enter a new name for the notarization file",
      type: "input",
      inputPlaceholder: "Write something"
    },
    function(new_name) {
      if (!(isValid(new_name))) {
        console.log('detected invalid name', new_name);
        //swal glitch - need a timeout
        setTimeout(function() {
          swal({
            title: "Invalid filename",
            text: 'Please only use alphanumerical characters',
            type: 'warning'
          });
        }, 200);
      } else if (new_name === null) return; //escape pressed
      else {
        sendMessage({
          'destination': 'extension',
          'message': 'rename',
          'args': {
            'dir': dir,
            'newname': new_name
          }
        });
      }
    });
}



function sendMessage(msg) {
  if (is_chrome) {
    chrome.runtime.sendMessage(msg);
  } else {
    port.postMessage(msg);
  }
}
