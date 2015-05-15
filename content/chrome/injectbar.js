var table = document.createElement("table");
table.style.position = "fixed";
table.style.top = "0px";
table.style.left = "100px";
table.style.background = "rgba(242, 241, 240, 0.9)";
table.style.width = "80%";
table.style.height = "32px";
table.className = "hidden";
var row = document.createElement("tr");
var cell1 = document.createElement("td");
var cell2 = document.createElement("td");
var cell3 = document.createElement("td");
cell3.style.align = "right";
var img = document.createElement("img");
img.src = "icon16.png";
var text = document.createElement("text");
text.textContent = "PageSigner successfully verified that the webpage below was received from ";
var domain = document.createElement("text");
domain.id = "domainName";
var button = document.createElement("button");
button.id = "viewRaw";
button.textContent = "View raw data with HTTP headers";
button.style.MozBorderRadius = "4px";
button.style.WebkitBorderRadius = "4px";
button.style.borderRadius = "4px";
button.onclick = function(){
	chrome.runtime.sendMessage({destination:'extension', message:'viewraw', args:{dir:sdir}});
	}
cell3.appendChild(button)
cell2.appendChild(text);
cell2.appendChild(domain);
cell1.appendChild(img);
row.appendChild(cell1);
row.appendChild(cell2);
row.appendChild(cell3);
table.appendChild(row);
document.body.appendChild(table);

setTimeout(function(){
	//make a transition to visible
	table.className = "visible";
}, 0);
