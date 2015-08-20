console.log("injecting some code");
document.addEventListener("hello", function(evt) {
	var data = evt.detail;
	console.log("got hello with", data);
	chrome.runtime.sendMessage(data);
});
//we cannot access page vars directly
var script = document.createElement('script');
script.appendChild(document.createTextNode('chrome_injected = true;'));
(document.body || document.head || document.documentElement).appendChild(script);
