/* global chrome*/

export class NotificationBar{
  constructor(){}

  // show shows the notification bar at the top of the page.
  show(sessionId, serverName, request, response, hideButton) {
    hideButton = hideButton || false;
    // if sessionId was not passed, it means we are in the preview mode
    const isPreview = sessionId != undefined ? false : true;

    const table = document.createElement('table');
    table.style.position = 'fixed';
    table.style.top = '0px';
    table.style.left = '100px';
    table.style.background = 'rgba(242, 241, 240, 0.9)';
    table.style.width = '80%';
    table.style.height = '32px';
    table.style.visibility = 'hidden';
    table.style.opacity = '0';
    table.style.transition = 'visibility 0s 2s, opacity 2s linear';
    const row = document.createElement('tr');

    const cell1 = document.createElement('td');
    const cell2 = document.createElement('td');
    const cell3 = document.createElement('td');
    const cell4 = document.createElement('td');

    cell3.style.align = 'right';
    cell4.style.align = 'right';
    const img = document.createElement('img');
    img.src = '../img/icon.svg';
    img.height = 24;
    img.width = 24;
    const text = document.createElement('text');
    const domain = document.createElement('text');
    domain.id = 'domainName';

    if (isPreview){
      text.textContent = 'This is a preview of what the notarization result will look like. Press Details to preview the raw HTML data.';
    } else {
      text.textContent = 'PageSigner verified that this page was received from ';
      domain.textContent = serverName;
    }
    const button = document.createElement('button');
    button.id = 'viewRaw';
    button.textContent = 'Details';
    button.style.MozBorderRadius = '4px';
    button.style.WebkitBorderRadius = '4px';
    button.style.borderRadius = '4px';
    if (isPreview){
      button.onclick = function() {
        chrome.runtime.sendMessage({
          destination: 'extension',
          message: 'showPreviewDetails',
          serverName: serverName,
          request: request,
          response: response
        });
      };
    } else {
      button.onclick = function() {
        chrome.runtime.sendMessage({
          destination: 'extension',
          message: 'showDetails',
          sid: sessionId
        });
      };
    }
    if (hideButton) {
      button.hidden = true;
    }

    cell3.appendChild(button);
    cell2.appendChild(text);
    cell2.appendChild(domain);
    cell1.appendChild(img);
    row.appendChild(cell1);
    row.appendChild(cell2);
    row.appendChild(cell3);
    row.appendChild(cell4);
    table.appendChild(row);
    const tablediv = document.createElement('div');
    tablediv.appendChild(table);
    tablediv.id = 'tablediv';
    document.body.appendChild(tablediv);

    setTimeout(function() {
      // make a transition to visible
      table.style.visibility = 'visible';
      table.style.opacity = '1';
      table.style.transition = 'opacity 2s linear';
    }, 0);

  }
}
