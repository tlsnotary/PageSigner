var is_chrome = false;
if (navigator.userAgent.search('Chrome') > -1){
	var is_chrome = true;
}
var idiv;


function onload(){
	if (is_chrome){
		chrome.runtime.onMessage.addListener(
		  function(request, sender, sendResponse) {
			if (request.destination !== 'manager') return;
			console.log('got request', request);
			process_data(request.data);
		});
	}
	else {
		idiv = document.getElementById('extension2manager');
		idiv.addEventListener('click', function(e){
			console.log('changed to', idiv.textContent);
			if (idiv.textContent === '') return; //spurious clicks can happen
			var data = JSON.parse(idiv.textContent);
			process_data(data);
		});
	}
	sendMessage({'destination':'extension', 'message':'refresh'});
}

document.addEventListener('load', onload);
window.addEventListener('load', onload);


function process_data(rows){
    tb = document.getElementsByTagName('tbody')[0];
    var initial_row_length = tb.rows.length;
    for (var j=0; j < initial_row_length; j++){
		tb.deleteRow(0);
	}
	//create sort order based on names (more intuitive than time,
    //but should really be user-configurable sort of course...
    rows.sort(function (a,b){
		var as = a.name, bs = b.name;
		return as == bs ? 0: (as > bs ? 1 : -1);
    });
	
    for (var i=0; i < rows.length; i++){
		var r = rows[i];
		addRow({'name':r.name,
				'imported':r.imported,
				'valid':r.valid,
				'verifier':r.verifier,
				'dir':r.dir});
	}
}



function addRow(args){
	var dir = args.dir.split('/').pop();
	var tb, row, td, a, img, text;
	tb = document.getElementById('myTableBody');
	row = tb.insertRow(tb.rows.length);
	td = document.createElement("td");
	td.appendChild(document.createTextNode(args.name));
	row.appendChild(td);
	
	td = document.createElement("td");
	a = document.createElement("a");
	a.title = 'Give the file a more memorable name';
	a.style = 'float: right';
	a.onclick = function (event){ doRename(event.target, args.name, dir);};
	a.text = 'Rename';
	td.appendChild(a);
	row.appendChild(td);
	
	td = document.createElement("td");
	a = document.createElement("a");
	a.title = 'Save the file so you can transfer it to others';
	a.style = 'float: right';
	a.onclick = function (event){
		console.log('export clicked');
		swal({
		title:'You MUST LOG OUT before exporting',
		text:'Before exporting you MUST LOG OUT of any sessions associated with the data you are about to export. Please LOG OUT NOW if you have any active sessions running and press OK to proceed',
		type: "warning"}, 
		function(){
			sendMessage({'destination':'extension','message':'export',
			'args':{'dir': dir, 'file': args.name}});
		});
		
	};
	a.text = 'Export';
	td.appendChild(a);
	row.appendChild(td);
	
	td = document.createElement("td");
	a = document.createElement("a");
	a.title = 'permanently remove this set of files from disk';
	a.style = 'float: right';
	a.onclick = function (event){
		swal({
			title:'Removing notarization data',
			text: "This will remove all notarized data of "+args.name+". Are you sure?",
			type: "warning"
		},
		function(){
			sendMessage({'destination':'extension', 'message':'delete',
									'args':{'dir':dir}});
		});
	};
	a.text = 'Delete';
	td.appendChild(a);
	row.appendChild(td);
	
	td = document.createElement("td");
	//make sure the -IMPORTED suffix isnt present
	td.textContent = dir.slice(0,19) + ' , ' + dir.slice(20).split('-')[0];
	row.appendChild(td);

	td = document.createElement("td");
	var implabel = "mine";
	if (args.imported) implabel = "imported";
	td.textContent = implabel;
	row.appendChild(td);
	
	td = document.createElement("td");
	img = document.createElement("img");
	img.height = 30;
	img.width = 30;
	var label;
	var extrapath = is_chrome ? '/content/' : '';
	if (args.valid){
		img.src = extrapath + 'check.png';
		label = 'valid';
	}
	else {
		img.src = extrapath + 'cross.png';
		label = 'invalid';
	}
	text = document.createElement("text");
	text.textContent = label;
	td.appendChild(img);
	td.appendChild(text);
	row.appendChild(td);
	
	td = document.createElement("td");
	td.textContent = args.verifier;
	row.appendChild(td);
	
	td = document.createElement("td");
	a = document.createElement("a");
	a.onclick = function (event){
		sendMessage({'destination':'extension', 'message':'viewdata',
						'args':{'dir':dir}});
	};
	a.text = "view";
	td.appendChild(a);
	text = document.createElement("text");
	text.textContent = ' , ';
	td.appendChild(text);
	a = document.createElement("a");
	a.onclick = function (event){
		sendMessage({'destination':'extension', 'message':'viewraw',
						'args':{'dir':dir}});
	};
	a.text = "raw";
	td.appendChild(a);
	
	row.appendChild(td);
}


function doRename(t, oldname, dir){
    var isValid=(function(){
    var rg1=/^[^\\/:\*\?"<>\|]+$/; // forbidden characters \ / : * ? " < > |
		var rg2=/^\./; // cannot start with dot (.)
		var rg3=/^(nul|prn|con|lpt[0-9]|com[0-9])(\.|$)/i; // forbidden file names
		return function isValid(fname){
		  return rg1.test(fname)&&!rg2.test(fname)&&!rg3.test(fname);
		};
    })();
    swal({
		title: "Enter a new name for the notarization file", 
		type: "input",
		inputPlaceholder: "Write something" 
	},
	function(new_name){
		if(!(isValid(new_name))){
			//swal glitch - need a timeout
			setTimeout(function(){
				swal({title:"Invalid filename", text:'Please only use alphanumerical characters', type:'warning'});
			}, 200);
		}
		else if (new_name === null) return; //escape pressed
		else {
			sendMessage({'destination':'extension',
							'message':'rename',
							'args':{'dir':dir, 'newname':new_name}
			});
		}
	});    
}



function sendMessage(msg){
	console.log('in sendMessage', msg);
	if (is_chrome){
		chrome.runtime.sendMessage(msg);
	}
	else {
		var json = JSON.stringify(msg);
		var buf = document.getElementById('manager2extension');
		buf.textContent = json;
		buf.click();
	}
}


