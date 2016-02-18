var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;

function install_bar(sessionId, serverName, hideButton) {
  if (hideButton === undefined) {
    hideButton = false;
  }

  var table = document.createElement("table");
  table.style.position = "fixed";
  table.style.top = "0px";
  table.style.left = "100px";
  table.style.background = "rgba(242, 241, 240, 0.9)";
  table.style.width = "80%";
  table.style.height = "32px";
  table.style.visibility = 'hidden';
  table.style.opacity = '0';
  table.style.webkitTransition = 'visibility 0s 2s, opacity 2s linear';
  table.style.transition = 'visibility 0s 2s, opacity 2s linear';
  var row = document.createElement("tr");

  var cell1 = document.createElement("td");
  var cell2 = document.createElement("td");
  var cell3 = document.createElement("td");
  var cell4 = document.createElement("td");

  cell3.style.align = "right";
  cell4.style.align = "right";
  var img = document.createElement("img");
  //icon.png base64-encoded
  img.src = "data:image/png;base64,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";
  img.height = 16;
  img.width = 16;
  var text = document.createElement("text");
  text.textContent = "PageSigner verified that this page was received from ";
  var domain = document.createElement("text");
  domain.id = "domainName";
  domain.textContent = serverName;
  var button = document.createElement("button");
  button.id = "viewRaw";
  button.textContent = "View raw data";
  button.style.MozBorderRadius = "4px";
  button.style.WebkitBorderRadius = "4px";
  button.style.borderRadius = "4px";
  button.onclick = function() {
    if (is_chrome) {
      chrome.runtime.sendMessage({
        destination: 'extension',
        message: 'viewraw',
        args: {
          dir: sessionId
        }
      });
    } else {
      var port = chrome.runtime.connect({
        name: "notification-to-extension"
      });
      port.postMessage({
        'destination': 'extension',
        'message': 'viewraw',
        args: {
          dir: sessionId
        }
      });
    }
  };
  if (hideButton) {
    button.hidden = true;
  }

  var close = document.createElement("a");
  close.text = "x";
  close.style = 'cursor: pointer;';
  close.onclick = function(event) {
    document.getElementById('tablediv').hidden = true;
  }

  cell4.appendChild(close);
  cell3.appendChild(button)
  cell2.appendChild(text);
  cell2.appendChild(domain);
  cell1.appendChild(img);
  row.appendChild(cell1);
  row.appendChild(cell2);
  row.appendChild(cell3);
  row.appendChild(cell4);
  table.appendChild(row);
  var tablediv = document.createElement('div');
  tablediv.appendChild(table);
  tablediv.id = 'tablediv';
  document.body.appendChild(tablediv);

  setTimeout(function() {
    //make a transition to visible
    table.style.visibility = 'visible';
    table.style.opacity = '1';
    table.style.webkitTransition = 'opacity 2s linear';
    table.style.transition = 'opacity 2s linear';
  }, 0);

}
