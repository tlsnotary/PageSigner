var viewTabDocument;

function install_bar(){
//when running from Firefox, the var gBrowser is available
var using_chrome = typeof(gBrowser) === 'undefined';
var using_firefox = typeof(gBrowser) !== 'undefined';
var document = viewTabDocument;
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
cell3.style.align = "right";
var img = document.createElement("img");
img.src = using_chrome ? "icon16.png" : "../icon16.png";
var text = document.createElement("text");
text.textContent = "PageSigner verified that this page was received from ";
var domain = document.createElement("text");
domain.id = "domainName";
var sdir = document.createElement("text");
sdir.id = "sdir";
var button = document.createElement("button");
button.id = "viewRaw";
button.textContent = "View raw data with HTTP headers";
button.style.MozBorderRadius = "4px";
button.style.WebkitBorderRadius = "4px";
button.style.borderRadius = "4px";
button.onclick = function(){
	var dir = document['pagesigner-session-dir'];
	if (using_chrome){
		chrome.runtime.sendMessage({destination:'extension', message:'viewraw', args:{dir:dir}});
	}
	else if (using_firefox){
		var path = OS.Path.join(fsRootPath, dir, 'raw.txt');
		gBrowser.selectedTab = gBrowser.addTab(path);
	}
};
cell3.appendChild(button)
cell2.appendChild(text);
cell2.appendChild(domain);
cell1.appendChild(img);
row.appendChild(cell1);
row.appendChild(cell2);
row.appendChild(cell3);
table.appendChild(row);
table.appendChild(sdir);
document.body.appendChild(table);
document['pagesigner-session-dir'] = sdir;

setTimeout(function(){
	//make a transition to visible
	table.style.visibility = 'visible';
	table.style.opacity = '1';
	table.style.webkitTransition = 'opacity 2s linear';
	table.style.transition = 'opacity 2s linear';
}, 0);

}
