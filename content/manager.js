//root directory of managed files
var pgsg_dir = getPGSGdir().path;
//array of existing files
var pgsg_subdirs = []; //subdirectories of pagesigner directory
//keys are directory names (which have fixed format 
//timestamp-server name), values are:
//[pgsg OS.File object, filehash, boolean imported, html table row object]:
var tdict ={}; 
//keep track of changes
var tdict_prev = {};
var tloaded = false;

function tableRefresher(){
    if (!tloaded){
	setTimeout(tableRefresher,500);
	return;
    }
    //table is ready to be drawn
    for (var d in tdict){
	if (!(d in tdict_prev)){
	    //entirely new entry
	    addNewRow(tdict[d][0],d,tdict[d][2],'none',"none","none");
	    verifyEntry(d, tdict[d][0].path); //populates validation fields
	}
	else if (tdict[d][1].toString() != tdict_prev[d][1].toString()){
	    //file is modified; reverify
	    verifyEntry(d, tdict[d][0].path);
	}
    }
    tloaded = false; //wait for next change
    setTimeout(tableRefresher, 500);
}

function importPGSGFile(){
    main.verify(); //TODO if import fails due to unverified signature, there is no message to user.
    loadManager();
}


function doRename(t){
    var isValid=(function(){
    var rg1=/^[^\\/:\*\?"<>\|]+$/; // forbidden characters \ / : * ? " < > |
    var rg2=/^\./; // cannot start with dot (.)
    var rg3=/^(nul|prn|con|lpt[0-9]|com[0-9])(\.|$)/i; // forbidden file names
    return function isValid(fname){
      return rg1.test(fname)&&!rg2.test(fname)&&!rg3.test(fname);
    }
    })();
    var new_name = window.prompt("Enter a new name for the notarization file:");
    if(!(isValid(new_name))){
	alert("Invalid filename");
	return;
    }
    if (!new_name.endsWith(".pgsg")){
	new_name = new_name + ".pgsg";
    }
    basename = OS.Path.basename(t.id);
    original_path = t.id;
    basedir = OS.Path.dirname(t.id);
    basedir_name = OS.Path.basename(basedir);
    //rename file on disk
    OS.File.move(original_path,OS.Path.join(basedir,new_name));
    var row = tdict[basedir_name][3];
    row.parentNode.removeChild(row);
    delete tdict[basedir_name];
    loadManager();
}

function doSave(t){
    filename = tdict[t.id][0].path;
    savePGSGFile(filename);
    //no need to reload here
}

function addNewRow(fileEntry, dirname, imported,verified,verifier,html_link){
    let sname = dirname.substr(20);
    if (imported){ sname = sname.slice(0,-9);}
    tstamp = dirname.substr(0,19);
    var row = tdict[dirname][3];
    var x = jsonToDOM([ "td", {}, fileEntry.name.slice(0,-5)],document,{});
    var y = jsonToDOM(["button",
		{id: fileEntry.path,
		 style: 'float: right',
		 onclick: function (event){doRename(event.target);}
		 }, "Rename"], document,{});
    var z = jsonToDOM(["button",
		{id: dirname,
		 style: 'float: right',
		 onclick: function (event){doSave(event.target);}
		 }, "Export"], document,{});
    x.appendChild(y);
    x.appendChild(z);
    row.appendChild(x);
    row.appendChild(jsonToDOM([ "td", {}, tstamp + ' , ' + sname],document,{}));
    if (!imported){
	row.appendChild(jsonToDOM([ "td", {}, "mine"],document,{}));
    }
    else {
	row.appendChild(jsonToDOM([ "td", {}, "imported"],document,{}));
	}
    row.appendChild(jsonToDOM([ "td", {}, verified],document,{}));
    row.appendChild(jsonToDOM([ "td", {}, verifier],document,{}));
    row.appendChild(jsonToDOM([ "td", {}, html_link],document,{}));
    x = jsonToDOM([ "td", {}, ""],document,{});
    y = jsonToDOM(["button",
		{id: dirname,
		 title: 'permanently remove this set of files from disk',
		 onclick: function (event){deleteFile(event.target);}
		 }, "Delete"], document,{});
    x.appendChild(y);
    row.appendChild(x);
}


function deleteFile(basename){
	var r = confirm("This will remove the entire directory:"+basename.id+", including html. Are you sure?");
	if (r){
	    OS.File.removeDir(OS.Path.join(pgsg_dir,basename.id));
	    var row = tdict[basename.id][3];
	    row.parentNode.removeChild(row);
	    delete tdict[basename.id];
	    loadManager();
	}
}

function loadManager() {
   //this function will rebuild the tdict and compare to the old version
   tdict_prev = tdict;
   tdict = {}  
   pgsg_subdirs = [];
   tloaded = false;
  let iterator = new OS.File.DirectoryIterator(pgsg_dir);
  let promise = iterator.forEach(
    function onEntry(entry) {
	if (!entry.isDir){
	    console.log("entry was not a directory, ignored:"+entry.path);
	}
	else {
	    pgsg_subdirs.push(entry);	    
	}    
    }
  );
  promise.then(
    function onSuccess() {
      iterator.close();
      for (var i=0; i < pgsg_subdirs.length; i++){
	let imported = false;
	if (pgsg_subdirs[i].name.match("-IMPORTED$")=="-IMPORTED"){ 
	    imported = true;
	}
	var iterator2 = new OS.File.DirectoryIterator(pgsg_subdirs[i].path);
	
	let promise2 = iterator2.forEach(
	function (entry2) { 
	    if (entry2.path.endsWith(".pgsg")){
		OS.File.read(entry2.path).then(function (read_data){
		    file_hash = sha256(read_data);
		    dirname = OS.Path.basename(OS.Path.dirname(entry2.path));
		    var row;
		    if (!(dirname in tdict_prev)){
			var tbody = document.getElementById("myTableData").getElementsByTagName('tbody')[0];
			row = tbody.insertRow(tbody.rows.length); 
		    }
		    else {
			row = tdict_prev[dirname][3];
		    } 
		    tdict[dirname]=[entry2, file_hash, imported, row];
		    if (Object.keys(tdict).length == pgsg_subdirs.length){
			//remove rows that refer to subdirs no longer existing 
			//(will only happen if user manually deletes that subdirectory).
			Array.prototype.diff = function(a) {
			return this.filter(function(i) {return a.indexOf(i) < 0;});
			};
			var dict_diff = Object.keys(tdict_prev).diff(Object.keys(tdict));
			for (var i=0; i<dict_diff.length; i++){
			    var row = tdict_prev[dict_diff[i]][3];
			    row.parentNode.removeChild(row);
			}
			tloaded = true;
		    }
		});
	   }
	});
	promise2.then(
	   function() {
	    iterator2.close();
      } ,
    function (reason) {
      iterator2.close();
      throw reason;
    }
     );
    }
}, function onFailure(reason){
    iterator.close();
    throw reason;
    });
}

function updateRow(basename, col, x){
	cell = tdict[basename][3].cells[col];
	parent = cell.parentNode;
	new_element = jsonToDOM([ "td", {}, ""],document,{});
	new_element.appendChild(x);
	parent.insertBefore(new_element, cell);
	parent.removeChild(cell);
}

function verifyEntry(basename, path){
	OS.File.read(path).then( function(imported_data){
	    return verify_tlsn(imported_data, true);
	}).then(function (a){
	    displayVerification(basename, a[3]);
	}).catch( function(error){
	    log("Error in verifyEntry: "+error);
	    var x = jsonToDOM([ "td", {}, ""],document,{});
	    var y = jsonToDOM(["img",
			{height: '30',
			 width: '30',
			 src: 'chrome://pagesigner/content/cross.png',
			 }, "Not verified"], document,{});
	    var z = jsonToDOM([ "text", {}, " Not verified: "+error],document,{});
	    x.appendChild(y);
	    x.appendChild(z);
	    updateRow(basename,3,x);
	    x = jsonToDOM([ "td", {}, "none"],document,{});
	    y = jsonToDOM([ "td", {}, "none"],document,{});
	    updateRow(basename,4,x);
	    updateRow(basename,5,y);

	});	
}

function displayVerification(basename, pubkey){
    //find the right notary object based on provided pubkey
    var used_notary = null;
    for (var i=0;i<pagesigner_servers.length;i++){
	if (pagesigner_servers[i].sig.modulus.toString() == pubkey.toString()){
	    used_notary = pagesigner_servers[i];
	}
    }
    if (!(used_notary)){ //can happen if the signing notary is not in our trusted list
	throw ("unknown notary");
    }
    var x = jsonToDOM([ "td", {}, ""],document,{});
    var y = jsonToDOM(["img",
	    {height: '30',
	    width: '30',
	    src: 'chrome://pagesigner/content/check.png',
	    }, "Valid"], document,{});
    var z = jsonToDOM(["text",{}," valid"],document,{});
    x.appendChild(y);
    x.appendChild(z)
    updateRow(basename,3,x);
    x = jsonToDOM([ "td", {}, used_notary.name],document,{});
    updateRow(basename,4,x); //TODO: pretty print pubkey?
    var html_link = getPGSGdir();
    html_link.append(basename);
    html_link.append('html.html');
    block_urls.push(html_link.path);
    
    x = jsonToDOM([ "td", {}, ""],document,{});
    y = jsonToDOM(["a",
	    {href: 'file://' + html_link.path,
	    }, "view"], document,{});
    var q = jsonToDOM(["text",{}," , "],document,{});
    z = jsonToDOM(["a",
	    {href: 'file://' + OS.Path.join(pgsg_dir,basename,"raw.txt"),
	    }, "raw"], document,{});	    
    x.appendChild(y);
    x.appendChild(q);
    x.appendChild(z);
    updateRow(basename,5,x);
}


//The following code supports dynamically inserting
//elements into the DOM
jsonToDOM.namespaces = {
    html: "http://www.w3.org/1999/xhtml",
    xul: "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul"
};
jsonToDOM.defaultNamespace = jsonToDOM.namespaces.html;

function jsonToDOM(xml, doc, nodes) {
    function namespace(name) {
        var reElemNameParts = /^(?:(.*):)?(.*)$/.exec(name);
        return { namespace: jsonToDOM.namespaces[reElemNameParts[1]], shortName: reElemNameParts[2] };
    }

    // Note that 'elemNameOrArray' is: either the full element name (eg. [html:]div) or an array of elements in JSON notation
    function tag(elemNameOrArray, elemAttr) {
        // Array of elements?  Parse each one...
        if (Array.isArray(elemNameOrArray)) {
            var frag = doc.createDocumentFragment();
            Array.forEach(arguments, function(thisElem) {
                frag.appendChild(tag.apply(null, thisElem));
            });
            return frag;
        }

        // Single element? Parse element namespace prefix (if none exists, default to defaultNamespace), and create element
        var elemNs = namespace(elemNameOrArray);
        var elem = doc.createElementNS(elemNs.namespace || jsonToDOM.defaultNamespace, elemNs.shortName);

        // Set element's attributes and/or callback functions (eg. onclick)
        for (var key in elemAttr) {
            var val = elemAttr[key];
            if (nodes && key == "key") {
                nodes[val] = elem;
                continue;
            }

            var attrNs = namespace(key);
            if (typeof val == "function") {
                // Special case for function attributes; don't just add them as 'on...' attributes, but as events, using addEventListener
                elem.addEventListener(key.replace(/^on/, ""), val, false);
            }
            else {
                // Note that the default namespace for XML attributes is, and should be, blank (ie. they're not in any namespace)
                elem.setAttributeNS(attrNs.namespace || "", attrNs.shortName, val);
            }
        }

        // Create and append this element's children
        var childElems = Array.slice(arguments, 2);
        childElems.forEach(function(childElem) {
            if (childElem != null) {
                elem.appendChild(
                    typeof childElem == "object" ? tag.apply(null, childElem) :
                        childElem instanceof doc.defaultView.Node ? childElem :
                            doc.createTextNode(childElem)
                );
            }
        });

        return elem;
    }

    return tag.apply(null, xml);
}

tableRefresher();