
var link1 = document.getElementById("link1");
link1.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openLink1'});
	window.close();
});

var link2 = document.getElementById("link2");
link2.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openLink2'});
	window.close();
});

var link3 = document.getElementById("link3");
link3.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openLink3'});
	window.close();
});
