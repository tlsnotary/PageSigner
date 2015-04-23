var kernelId = 'aki-503e7402';
var snapshotID_main = 'snap-cdd399f8';
var snapshotID_sig = 'snap-00083b35';
var imageID_main = 'ami-5e39040c';
var imageID_sig = 'ami-88724fda';
var oracles_intact = false; //must be explicitely set to true


var local1 =
{'name':'local1',
'main':{
	"IP":"localhost",
	"port":"10011"
},
'sig':{
	"modulus":[215,74,157,189,225,84,124,238,135,250,223,150,83,215,130,154,222,184,43,205,133,160,176,8,52,155,87,117,197,229,246,0,64,184,40,78,129,72,186,146,56,29,45,31,227,143,41,210,158,57,140,144,133,147,160,174,233,4,7,218,170,207,121,87,56,147,149,1,40,240,136,166,62,168,25,83,154,79,37,127,135,161,155,79,86,248,117,255,244,202,254,215,118,139,39,112,242,36,26,109,140,32,247,187,23,71,78,108,189,85,123,144,16,200,167,28,192,13,173,18,251,221,216,215,233,78,151,169,75,96,96,244,15,150,156,24,217,117,71,199,116,184,212,159,5,23,11,146,0,189,46,2,18,149,38,77,236,202,200,113,143,255,46,36,234,204,79,142,182,181,131,30,201,145,86,235,109,18,117,93,36,224,235,70,82,183,39,32,129,78,222,88,46,93,170,78,104,133,26,227,31,252,204,221,255,79,53,221,63,183,116,212,125,102,163,235,213,144,186,11,247,227,8,252,49,53,66,88,13,79,173,124,193,122,240,167,151,154,152,189,223,12,199,34,30,127,244,135,82,176,18,121,8,231,151,93,232,181,29,26,180,92,197,156,201,210,110,100,182,168,88,98,129,69,84,111,144,138,249,47,65,136,245,51,184,233,106,30,7,54,114,242,155,25,127,198,129,252,18,7,161,158,247,69,254,250,38,235,109,21,35,133,105,62,204,182,69,152,237,5,204,102,30,142,184,132,206,188,189,78,75,72,164,216,87,7,154,254,163,163,85,227,154,121,15,98,131,226,67,145,255,135,193,148,218,81,157,152,170,33,70,77,177,183,29,84,117,39,21,53,138,75,21,231,148,149,144,122,52,132,219,35,200,91,228,171,80,212,34,88,60,198,91,193,105,251,100,169,41,68,25,160,131,184,247,199,5,152,47,143,107,7,240,22,56,150,10,204,110,200,179,117,20,147,94,137,207,196,67,94,108,4,56,157,102,176,110,83,62,4,168,64,120,110,23,172,131,100,23,104,19,159,36,152,132,235,137,236,25,233,225,55,239,79,147,72,226,79,39,26,200,214,15,161,43,236,198,235,236,76,19,80,223,28,120,39,15,233,251,181,101,203,202,45,6,180,244,86,211,41,99,108,42,221,215,182,214,10,176,243,99,157]
}
}


var waxwing =
{'name':'waxwing',
'main':{
	"IP":"109.169.23.122",
	"port":"8080"
},
'sig':{
	"modulus":[224,117,88,3,77,22,21,87,102,16,49,34,212,117,228,143,107,119,84,137,127,133,182,197,78,228,53,44,99,148,120,52,229,237,38,170,114,203,155,241,7,125,255,187,163,50,194,175,189,187,104,38,15,60,226,225,9,244,92,172,223,189,152,53,69,71,241,61,26,21,252,130,202,3,95,171,200,91,72,152,2,102,50,15,30,139,63,162,3,1,132,24,30,181,130,215,74,43,209,240,227,13,229,117,70,176,79,82,15,164,189,115,138,228,250,96,88,36,181,185,130,92,255,29,100,245,83,14,96,149,27,3,51,222,17,49,48,151,130,242,107,69,74,47,134,190,233,160,9,202,103,168,33,82,60,227,232,18,47,204,216,119,132,213,234,214,56,141,149,227,113,141,243,219,190,113,233,108,153,36,249,139,217,95,1,124,141,42,233,209,140,167,191,172,249,12,32,5,139,219,80,42,144,108,162,101,90,23,224,71,150,229,227,95,219,194,226,106,238,167,72,37,172,105,219,78,84,99,137,213,72,156,65,216,105,92,163,152,158,195,170,169,200,146,163,233,35,2,75,66,38,108,63,98,197,47,52,242,129,226,220,182,58,34,214,205,79,131,250,136,167,203,130,181,81,85,29,17,153,17,62,157,219,9,178,171,245,214,129,9,92,166,234,230,67,87,132,190,106,16,59,236,49,24,230,93,4,211,222,236,64,246,248,163,5,150,183,208,58,23,73,244,209,10,230,175,56,169,1,160,53,87,154,221,27,135,125,229,77,54,174,178,10,189,249,68,232,56,117,178,130,142,7,142,116,55,124,48,7,254,179,78,162,248,156,35,126,53,238,148,63,152,180,16,237,241,147,246,7,137,126,119,146,49,244,38,197,42,112,84,152,147,58,122,60,26,79,216,111,74,171,183,64,247,245,224,34,237,10,255,167,199,180,189,122,50,230,114,14,180,85,127,155,67,142,202,203,243,130,120,146,117,185,51,100,91,12,198,61,182,157,59,64,127,66,42,36,179,188,219,171,23,129,162,189,90,163,105,56,139,99,43,11,9,162,131,243,65,52,191,154,166,165,250,167,180,190,226,146,127,13,115,0,33,198,134,191,17,100,165,13,251,216,36,61,222,60,59,219,41,6,123,243,182,213,38,109,125,194,176,97,11]
}
}


var oracle = 
{'name':'oracle1',
'main': {
	"IP":"52.74.29.34",
	"port":"10011",
	'DI':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeInstances&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=u6rcenB%2Feng0c%2FMknOEJu7nbb8s0qHd84AJmF1pLTCc%3D',
	'DV':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeVolumes&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-70423d7e&Signature=22tBu9aEToc1he01%2BN%2BBn8S6ESPt2ZAOOuCDdCrr7kc%3D',
	'GCO':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=GetConsoleOutput&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=lvCv2bPNLaEcqPv%2FoGef3lN2ni83A%2B5sMBEpnPcb740%3D',
	'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=GetUser&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=rKqb5XyhcRMCPhIXsUv0ETkcjOBvLr5xskUWpbyGyB8%3D',
	'DIA':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ntW%2F89MAan9PebvA%2B3%2F4P8qwHWwJ%2B1v0VqoItBAIqAE%3D',
	'instanceId': 'i-e2f28d2f'
},
'sig': {
	"modulus":[200,206,3,195,115,240,245,171,146,48,87,244,28,184,6,253,36,28,201,42,163,10,2,113,165,195,180,162,209,12,74,118,133,170,236,185,52,20,121,92,140,131,66,32,133,233,147,209,176,76,156,79,14,189,86,65,16,214,6,182,132,159,144,194,243,15,126,236,236,52,69,102,75,34,254,167,110,251,254,186,193,182,162,25,75,218,240,221,148,145,140,112,238,138,104,46,240,194,192,173,65,83,7,25,223,102,197,161,126,43,44,125,129,68,133,41,10,223,94,252,143,147,118,123,251,178,7,216,167,212,165,187,115,58,232,254,76,106,55,131,73,194,36,74,188,226,104,201,128,194,175,120,198,119,237,71,205,214,56,119,36,77,28,22,215,61,13,144,145,6,120,46,19,217,155,118,237,245,78,136,233,106,108,223,209,115,95,223,10,147,171,215,4,151,214,200,9,27,49,180,23,136,54,194,168,147,33,15,204,237,68,163,149,152,125,212,9,243,81,145,20,249,125,44,28,19,155,244,194,237,76,52,200,219,227,24,54,15,88,170,36,184,109,122,187,224,77,188,126,212,143,93,30,143,133,58,99,169,222,225,26,29,223,22,27,247,92,225,253,124,185,77,118,117,0,83,169,28,217,22,200,68,109,17,198,88,203,163,33,3,184,236,43,170,51,225,147,255,78,41,154,197,8,171,81,253,134,151,107,68,23,66,7,81,150,5,110,184,138,22,137,46,209,152,39,227,125,106,161,131,240,41,82,65,223,129,172,90,26,189,158,240,66,244,253,246,167,66,170,209,20,162,210,245,110,193,172,24,188,18,23,207,10,83,84,250,96,149,144,126,237,45,194,154,163,145,235,30,41,235,211,162,201,215,4,58,102,133,60,43,166,143,81,187,7,72,140,76,120,146,248,54,106,170,25,126,241,161,106,103,108,108,123,10,88,180,208,219,53,34,106,206,96,55,108,24,238,126,194,107,88,32,77,180,29,73,193,13,123,99,229,219,197,175,244,70,8,110,113,130,126,8,109,74,216,203,61,26,146,195,228,240,25,150,173,47,123,108,94,106,114,13,212,195,246,24,42,138,245,122,63,112,93,201,174,104,30,14,112,18,214,80,139,58,224,215,185,12,69,203,206,112,58,231,171,117,159,214,73,173,44,155],
	'DI':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeInstances&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=dVywKE9V8YSticfknIpUh3OY0zuN%2BOpsozLN%2F44u%2FHk%3D',
	'DV':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeVolumes&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-82bfc08c&Signature=Jqu7ykkGqCmvuSvJgD7odC8%2F6onaijr%2BsVGg8nEOES4%3D',
	'GCO':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=GetConsoleOutput&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=15CXO6WVRzww8VvZ5noXRqI5HpjIaDXUYdzR0j1AOaI%3D',
	'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=GetUser&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=qtHAlM8MedH7NRlJazfqYdlVJFaXEbiU9CenC%2FWc1CQ%3D',
	'DIA':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=Leqk1fx7X1AQkErydEljdwZoEV9LmxMm9EC8mwodCIs%3D',
	'instanceId': 'i-eaee9127',
	'IP': '52.74.155.127'
}
}
//there can be potentially multiple oracles to choose from
var oracles = [];
oracles.push(oracle);
//all servers trusted to perform notary (including non-oracles)
//TODO: configurable
var pagesigner_servers = [oracle, waxwing];

//assuming both events happened on the same day, get the time
//difference between them in seconds
//the time string looks like "2015-04-15T19:00:59.000Z"
function getSecondsDelta (later, sooner){
	assert (later.length == 24);
	if (later.slice(0,11) !== sooner.slice(0, 11)){
		return 999999; //not on the same day
	}
	var laterTime = later.slice(11,19).split(':');
	var soonerTime = sooner.slice(11,19).split(':');
	var laterSecs = parseInt(laterTime[0])*3600+parseInt(laterTime[1])*60+parseInt(laterTime[2]);
	var soonerSecs = parseInt(soonerTime[0])*3600+parseInt(soonerTime[1])*60+parseInt(soonerTime[2]);
	return laterSecs - soonerSecs;
}



function modulus_from_pubkey(pem_pubkey){
	var b64_str = '';
	var lines = pem_pubkey.split('\n');
	//omit header and footer lines
	for (var i=1; i < (lines.length-1); i++){
		b64_str += lines[i];
	}
	var der = b64decode(b64_str);
	//last 5 bytes are 2 DER bytes and 3 bytes exponent, our pubkey is the preceding 512 bytes
	var pubkey = der.slice(der.length - 517, der.length -5);
	return pubkey;
}


function checkDescribeInstances(xmlDoc, instanceId, IP, type){
	try{
	var imageID;
	var snapshotID;
	if (type === 'main'){
		imageID = imageID_main;
		snapshotID = snapshotID_main;
	}
	else if (type === 'sig'){
		imageID = imageID_sig;
		snapshotID = snapshotID_sig;
	}
	else {throw('unknown oracle type');}
	
	var rs = xmlDoc.getElementsByTagName('reservationSet');
	assert(rs.length === 1);
	var rs_items = rs[0].children;
	assert(rs_items.length === 1);
	var ownerId = rs_items[0].getElementsByTagName('ownerId')[0].textContent;
	var isets = rs_items[0].getElementsByTagName('instancesSet');
	assert(isets.length === 1);
	var instances = isets[0].children;
	assert(instances.length === 1);
	var parent = instances[0];
	assert(parent.getElementsByTagName('instanceId')[0].textContent === instanceId);
	assert(parent.getElementsByTagName('imageId')[0].textContent === imageID);
	assert(parent.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].textContent === 'running');
	var launchTime = parent.getElementsByTagName('launchTime')[0].textContent;
	assert(parent.getElementsByTagName('kernelId')[0].textContent === kernelId);
	assert(parent.getElementsByTagName('ipAddress')[0].textContent === IP);
	assert(parent.getElementsByTagName('rootDeviceType')[0].textContent === 'ebs');
	assert(parent.getElementsByTagName('rootDeviceName')[0].textContent === '/dev/xvda');
	var devices = parent.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item');
	assert(devices.length === 1);
	assert(devices[0].getElementsByTagName('deviceName')[0].textContent === '/dev/xvda');
	assert(devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].textContent === 'attached');
	var volAttachTime = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].textContent;
	var volumeId = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].textContent;
	//get seconds from "2015-04-15T19:00:59.000Z"
	assert(getSecondsDelta(volAttachTime, launchTime) <= 3);	
	}catch(e){
		return false;
	}
	return {'ownerId':ownerId, 'volumeId':volumeId, 'volAttachTime':volAttachTime, 'launchTime':launchTime};
}


function checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime, type){
	try{
	var imageID;
	var snapshotID;
	if (type === 'main'){
		imageID = imageID_main;
		snapshotID = snapshotID_main;
	}
	else if (type === 'sig'){
		imageID = imageID_sig;
		snapshotID = snapshotID_sig;
	}
	else {throw('unknown oracle type');}
	
	var volumes = xmlDoc.getElementsByTagName('volumeSet')[0].children;
	assert(volumes.length === 1);
	var volume = volumes[0];
	assert(volume.getElementsByTagName('volumeId')[0].textContent === volumeId);
	assert(volume.getElementsByTagName('snapshotId')[0].textContent === snapshotID);
	assert(volume.getElementsByTagName('status')[0].textContent === 'in-use');
	var volCreateTime = volume.getElementsByTagName('createTime')[0].textContent;
	var attVolumes = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item');
	assert(attVolumes.length === 1);
	var attVolume = attVolumes[0];
	assert(attVolume.getElementsByTagName('volumeId')[0].textContent === volumeId);
	assert(attVolume.getElementsByTagName('instanceId')[0].textContent === instanceId);
	assert(attVolume.getElementsByTagName('device')[0].textContent === '/dev/xvda');
	assert(attVolume.getElementsByTagName('status')[0].textContent === 'attached');
	var attTime = attVolume.getElementsByTagName('attachTime')[0].textContent;
	assert(volAttachTime === attTime);
	assert(getSecondsDelta(attTime, volCreateTime) === 0);	
	}catch(e){
		return false;
	}
	return true;
}


function checkGetConsoleOutput(xmlDoc, instanceId, launchTime, type, main_pubkey){
	try{
	assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
	var timestamp = xmlDoc.getElementsByTagName('timestamp')[0].textContent;
	//prevent funny business: last consoleLog entry no later than 4 minutes after instance starts
	assert(getSecondsDelta(timestamp, launchTime) <= 240);
	var b64data = xmlDoc.getElementsByTagName('output')[0].textContent;
	var logstr = ba2str(b64decode(b64data));
	//now other string starting with xvd except for xvda
	console.log("Before first assert, logstr is: "+logstr);
	assert(logstr.search(/xvd[^a]/g) === -1);
	var mainmark = 'TLSNotary main server pubkey which is embedded into the signing server:';
	var sigmark = 'TLSNotary siging server pubkey:';
	var sigimportedmark = 'TLSNotary imported main server pubkey:'
	var pkstartmark = '-----BEGIN PUBLIC KEY-----';
	var pkendmark = '-----END PUBLIC KEY-----';
	
	if (type === 'main'){
		var mark_start = logstr.search(mainmark);
		assert(mark_start !== -1);
		var pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
		var pubkey_end = pubkey_start+ logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
		var pubkey = logstr.slice(pubkey_start, pubkey_end);
		assert(pubkey.length > 0);
		return pubkey;
	}
	else if (type === 'sig'){
		var mark_start = logstr.search(sigmark);
		assert(mark_start !== -1);
		var pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
		var pubkey_end = pubkey_start+ logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
		var mypubkey = logstr.slice(pubkey_start, pubkey_end);
		assert(mypubkey.length > 0);
		
		mark_start = logstr.search(sigimportedmark);
		assert(mark_start !== -1);
		pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
		pubkey_end = pubkey_start+ logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
		var hispubkey = logstr.slice(pubkey_start, pubkey_end);
		assert(main_pubkey === hispubkey);
		
		return mypubkey;
	}
	else {
		return false;
	}
	}catch(e){
		return false;
	}
}

// "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
// This is a sanity check because the instance is stripped of the code which parses userData.	
function checkDescribeInstanceAttribute(xmlDoc, instanceId){
	try{
	assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
	assert(xmlDoc.getElementsByTagName('userData')[0].textContent === "");
	}catch(e){
		return false;
	}
	return true;
}


function checkGetUser(xmlDoc, ownerId){
	try{
	assert(xmlDoc.getElementsByTagName('UserId')[0].textContent === ownerId);
	assert(xmlDoc.getElementsByTagName('Arn')[0].textContent.slice(-(ownerId.length + ':root'.length)) === ownerId+':root');
	}catch(e){
		return false;
	}
	return true;
}


function check_oracle(o, type, main_pubkey){
	return new Promise(function(resolve, reject) {
		var xhr = get_xhr();
		xhr.open('GET', o.DI, true);
		xhr.onload = function(){
			var xmlDoc = xhr.responseXML;
			var result = checkDescribeInstances(xmlDoc, o.instanceId, o.IP, type);
			if (!result){
				reject('checkDescribeInstances');
			}
			else {
				resolve(result);
			}
		};
		xhr.send();
		log('sent');
	})
	.then(function(args){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.DV, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkDescribeVolumes(xmlDoc, o.instanceId, args.volumeId, args.volAttachTime, type);
				if (!result){
					reject('checkDescribeVolumes');
				}
				else {
					resolve({'ownerId':args.ownerId, 'launchTime':args.launchTime});
				}
			};
			xhr.send();
			log('sent');
		});
	})
	.then(function(args){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.GU, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkGetUser(xmlDoc, args.ownerId);
				if (!result){
					reject('checkGetUser');
				}
				else {
					resolve(args.launchTime);
				}
			};
			xhr.send();
			log('sent');
		});
	})
	.then(function(launchTime){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.GCO, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkGetConsoleOutput(xmlDoc, o.instanceId, launchTime, type, main_pubkey.pubkey);
				if (!result){
					reject('checkGetConsoleOutput');
				}
				else {
					var yes = true;
					if (type === 'main'){
						main_pubkey.pubkey = result;
					}
					else if (type === 'sig'){
						if (modulus_from_pubkey(result).toString() !== o.modulus.toString()){
							reject('modulus_from_pubkey');
						}
					}
					resolve();
				}
			};
			xhr.send();
			log('sent');
		});
	})
	.then(function(){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.DIA, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkDescribeInstanceAttribute(xmlDoc, o.instanceId);
				if (!result){
					reject('checkDescribeInstanceAttribute');
				}
				else {
					resolve();
				}
			};
			xhr.send();
			log('sent');
		});
	})
	.then(function(){
		var mark = 'AWSAccessKeyId=';
		var start;
		var id;
		var ids = [];
		//"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
		//The can be a user with limited privileges for whom the API would report only partial information.
		for (var url in [o.DI, o.DV, o.GU, o.GCO, o.DIA]){
			start = url.search(mark)+mark.length;
			id = url.slice(start, start + url.slice(start).search('&'));
			ids.push(id);
		}
		assert(new Set(ids).size === 1);
		log('oracle verification successfully finished');		
	});
}


