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

