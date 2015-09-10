console.log("injecting some code");
document.addEventListener("hello", function(evt) {
	var data = evt.detail;
	console.log("got hello with", data);
	chrome.runtime.sendMessage(data);
});

//this element is accessible by content scripts and by page javascript
document.getElementById('content_script_injected_into_page').textContent = 'true';
