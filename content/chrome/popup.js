chrome.runtime.sendMessage({'destination':'extension',
									'message':'popup active'});

chrome.runtime.onMessage.addListener(function(data){
	if (data.destination !== 'popup') return;
	if (data.message === 'file_access_disabled'){
		document.getElementById("enable_file_access").removeAttribute('hidden');
		document.body.style.width = '100%';
	}
	else if (data.message === 'app_not_installed'){
		document.getElementById("app_not_installed").removeAttribute('hidden');
	}
	else if (data.message === 'app_disabled'){
	    document.getElementById("app_disabled").removeAttribute('hidden');
	}
	else if (data.message === 'show_menu'){
	    document.getElementById("menu").removeAttribute('hidden');
	}
	else if (data.message === 'notarization_in_progress'){
	    document.getElementById("notarization_in_progress").removeAttribute('hidden');
	}
	else {
		console.log('popup received unexpected message ' + data.message);
	}
});


document.getElementById("notarize").addEventListener("click",
	function(){
		window.close();
		chrome.runtime.sendMessage({'destination':'extension',
									'message':'notarize'});
	});
	
document.getElementById("manage").addEventListener("click",
	function(){
		window.close();
		chrome.runtime.sendMessage({'destination':'extension',
									'message':'manage'});	
	});
	
document.getElementById("import").addEventListener("click",
	function(){
		window.close();
		var url = chrome.extension.getURL('content/chrome/file_picker.html');
		chrome.tabs.create({url:url}, function(t){
			console.log('tabid is', t.id);
		});
	});
	
document.getElementById("about").addEventListener("click",
	function(){
		chrome.windows.create({url:'content/chrome/about.html',
							type:'detached_panel',
							width:300,
							height:300,
							left:500})
		window.close();
	});

var app_not_installed = document.getElementById("app_not_installed");
app_not_installed.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openInstallLink'});
	window.close();
});

var app_disabled = document.getElementById("app_disabled");
app_disabled.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openChromeExtensions'});
	window.close();
});

var enable_file_access = document.getElementById("enable_file_access");
enable_file_access.addEventListener("click", function(evt){
	chrome.runtime.sendMessage({'destination':'extension',
						'message':'openChromeExtensions'});
	window.close();
});


//if this file is opened in a tab during testing, it will have a hash appended to the URL
setTimeout(function(){
	var hash = window.location.hash;
	if (hash === "#manage"){
		document.getElementById('manage').click();
	}
}, 100);
