
var link = document.getElementById("link");
link.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openInstallLink'});
	window.close();
});
