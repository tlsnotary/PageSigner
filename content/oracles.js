var snapshotID = 'snap-adf1ffb5';
var imageID = 'ami-34487c5e';
var oracles_intact = false; //must be explicitely set to true

var oracle = 
{'name':'tlsnotarygroup2',
	"IP":"52.91.68.11",
	"port":"10011",
	'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIWS22W7G7OTUNLSQ&Action=DescribeInstances&Expires=2019-01-01&InstanceId=i-2e8bc6ae&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=Pb3uZBrXVAfzWMA6mLdNpKAvAVfGJ2N8E7wCqL7b4XI%3D',
	'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIWS22W7G7OTUNLSQ&Action=DescribeVolumes&Expires=2019-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-002cbedf&Signature=whV7jZD6tebef%2FGFYXUdZ0ERkaF0wUIozNyP%2BaOJ9gs%3D',
	'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIWS22W7G7OTUNLSQ&Action=GetConsoleOutput&Expires=2019-01-01&InstanceId=i-2e8bc6ae&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=XgSwdUOyg4QKhA%2FUEhtIImQ0E83P6yLz80%2BMd7vr8%2BA%3D',
	'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIWS22W7G7OTUNLSQ&Action=GetUser&Expires=2019-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=ezF7yyfR6uagJuzemXol2V0qPgDz53hGMrC7ofOuHvI%3D',
	'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIWS22W7G7OTUNLSQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2019-01-01&InstanceId=i-2e8bc6ae&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=Hs0DzGV6H1EaDYsEDIuQX44fhriU8TlHyzdBTE0JTg0%3D',
	'instanceId': 'i-2e8bc6ae',
	'modulus':[226,73,225,54,14,216,53,169,36,131,211,80,213,20,162,190,18,133,116,183,142,6,243,176,141,192,14,220,104,101,81,104,178,196,78,63,227,167,125,87,125,24,155,116,90,229,178,146,135,102,144,119,206,19,62,154,187,167,123,193,152,101,207,58,104,88,126,66,73,29,189,165,9,110,217,28,207,217,65,149,7,204,23,91,92,1,145,90,253,63,152,150,22,233,60,182,110,44,181,25,227,6,22,165,122,87,201,110,139,208,207,148,133,217,106,104,126,26,140,167,72,211,59,214,182,230,59,77,100,48,10,199,183,162,138,52,168,254,115,241,5,93,229,86,160,22,158,218,76,101,26,241,238,153,91,17,201,28,143,144,73,107,41,178,56,72,143,23,154,47,184,119,41,146,157,218,56,49,236,25,32,35,236,255,155,122,47,149,24,91,5,169,38,27,228,8,107,196,46,77,176,244,99,66,137,88,162,79,226,53,103,68,119,32,107,109,226,177,216,71,209,203,218,125,167,90,246,252,202,194,36,226,90,194,242,126,15,77,245,174,47,155,83,152,55,78,100,66,102,181,38,201,0,95,218,83,112,5,247,222,68,173,232,136,82,248,233,138,238,78,204,53,8,63,194,119,181,242,119,168,84,89,240,190,135,239,113,83,56,38,246,235,179,145,52,57,196,205,202,101,194,132,187,114,116,93,146,36,156,249,114,1,118,204,246,81,16,233,97,150,162,233,225,186,90,195,175,251,218,79,193,74,55,204,63,60,148,248,252,240,202,125,58,24,72,70,90,211,40,208,136,207,91,26,219,58,165,96,196,219,195,214,158,249,208,194,162,190,56,149,110,147,57,136,140,110,107,225,84,210,199,165,170,244,169,15,45,207,226,113,48,58,182,32,166,116,212,94,66,22,171,90,160,20,153,151,172,116,74,172,111,158,20,76,92,151,40,139,218,220,105,175,99,203,4,137,241,66,152,213,220,45,28,64,36,38,153,216,130,186,124,225,195,16,162,135,146,211,171,14,71,254,128,60,121,183,223,31,83,33,229,100,192,175,199,226,9,38,194,16,12,128,16,177,175,153,201,242,247,98,42,68,32,136,222,85,81,39,81,28,183,53,82,59,242,20,39,127,59,214,38,175,127,209,107,106,106,11,10,71,165,163]
}


//there can be potentially multiple oracles to choose from
var oracles = [];
oracles.push(oracle);
//all servers trusted to perform notary (including non-oracles)
//TODO: configurable
var pagesigner_servers = [oracle];

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


function checkDescribeInstances(xmlDoc, instanceId, IP){
	try{
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
	assert(parent.getElementsByTagName('virtualizationType')[0].textContent === 'hvm');	
	}catch(e){
		return false;
	}
	return {'ownerId':ownerId, 'volumeId':volumeId, 'volAttachTime':volAttachTime, 'launchTime':launchTime};
}


function checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime){
	try{	
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
	//Crucial: volume was created from snapshot and attached at the same instant
	//this guarantees that there was no time window to modify it
	assert(getSecondsDelta(attTime, volCreateTime) === 0);	
	}catch(e){
		return false;
	}
	return true;
}


function checkGetConsoleOutput(xmlDoc, instanceId, launchTime){
	try{
	assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
	var timestamp = xmlDoc.getElementsByTagName('timestamp')[0].textContent;
	//prevent funny business: last consoleLog entry no later than 5 minutes after instance starts
	assert(getSecondsDelta(timestamp, launchTime) <= 300);
	var b64data = xmlDoc.getElementsByTagName('output')[0].textContent;
	var logstr = ba2str(b64decode(b64data));
	var sigmark = 'PageSigner public key for verification';
	var pkstartmark = '-----BEGIN PUBLIC KEY-----';
	var pkendmark = '-----END PUBLIC KEY-----';
		
	var mark_start = logstr.search(sigmark);
	assert(mark_start !== -1);
	var pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
	var pubkey_end = pubkey_start+ logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
	var pk = logstr.slice(pubkey_start, pubkey_end);
	assert(pk.length > 0);
	return pk;
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


function check_oracle(o){
	return new Promise(function(resolve, reject) {
		var xhr = get_xhr();
		xhr.open('GET', o.DI, true);
		xhr.onload = function(){
			var xmlDoc = xhr.responseXML;
			var result = checkDescribeInstances(xmlDoc, o.instanceId, o.IP);
			if (!result){
				reject('checkDescribeInstances');
			}
			else {
				resolve(result);
			}
		};
		xhr.send();
	})
	.then(function(args){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.DV, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkDescribeVolumes(xmlDoc, o.instanceId, args.volumeId, args.volAttachTime);
				if (!result){
					reject('checkDescribeVolumes');
				}
				else {
					resolve({'ownerId':args.ownerId, 'launchTime':args.launchTime});
				}
			};
			xhr.send();
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
		});
	})
	.then(function(launchTime){
		return new Promise(function(resolve, reject) {
			var xhr = get_xhr();
			xhr.open('GET', o.GCO, true);
			xhr.onload = function(){
				var xmlDoc = xhr.responseXML;
				var result = checkGetConsoleOutput(xmlDoc, o.instanceId, launchTime);
				if (!result){
					reject('checkGetConsoleOutput');
				}
				else {
					if (modulus_from_pubkey(result).toString() !== o.modulus.toString()){
						reject('modulus_from_pubkey');
					}
					resolve();
				}
			};
			xhr.send();
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
		});
	})
	.then(function(){
		var mark = 'AWSAccessKeyId=';
		var start;
		var id;
		var ids = [];
		//"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
		//The attacker can be a user with limited privileges for whom the API would report only partial information.
		for (var url in [o.DI, o.DV, o.GU, o.GCO, o.DIA]){
			start = url.search(mark)+mark.length;
			id = url.slice(start, start + url.slice(start).search('&'));
			ids.push(id);
		}
		assert(new Set(ids).size === 1);
		console.log('oracle verification successfully finished');		
	});
}


