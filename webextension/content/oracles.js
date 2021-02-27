var oracles_intact = false; //will be set to true after the oracle check completes

var old_oracle = {
  'snapshotId': 'snap-0bf942f29a64f0f50',
  'imageId': 'ami-016509fc994427733',
  'name': 'tlsnotarygroup9',
  'IP': '35.174.184.105',
  'instanceId': 'i-04f8cbc53fcc36f1d',
  'pubkeyPEM': '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaXM2Lxec8G3XJ6P86J3Qng+DKNzP\n0zGPlI7AqNLr+kCZ0obomrcvGS8QO0xyAVUaqK+oNIWFVKQf6LZPwP9m4w==\n-----END PUBLIC KEY-----'
}

var oracle = {
  'snapshotId': 'snap-0ca15091021ef43fc',
  'imageId': 'ami-08514e4e0cd45a2f4',
  'name': 'tlsnotarygroup10',
  'IP': '54.174.129.130',
  'port': '10011',
  'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeInstances&Expires=2030-01-01&InstanceId=i-0b39e16ddbb48f05e&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=DSk%2B%2BwQqVGPv%2FC5vyq8zvfFHxSFvLkmXsGipeNUYBQQ%3D',
  'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeVolumes&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-0d245f72f3413ae86&Signature=EDM414fdY2jHT0mhGofbuJU73vqwLWlKnJgOsw8U4dc%3D',
  'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=GetConsoleOutput&Expires=2030-01-01&InstanceId=i-0b39e16ddbb48f05e&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ekQyfK7f%2FSj9i%2B5fiLc4B3Wui2fz9JmW2%2BGtSNgtr0o%3D',
  'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=GetUser&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=jgeLNTQY1yVtUs2JCChV1AlzaQLkyn6%2BKx%2BQIxmlLew%3D',
  'DIAud':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2030-01-01&InstanceId=i-0b39e16ddbb48f05e&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=LSb9dFBO0faQvY9EjjF6axvQoal%2FqmMcAiruMJchBxg%3D',
  'DIAk':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeInstanceAttribute&Attribute=kernel&Expires=2030-01-01&InstanceId=i-0b39e16ddbb48f05e&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=XWMW8%2FaGlZn2%2BgJGCmj%2FXHQ5%2FELC%2Bs0pWgpSzv2dcfw%3D',
  'DIAr':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeInstanceAttribute&Attribute=ramdisk&Expires=2030-01-01&InstanceId=i-0b39e16ddbb48f05e&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=%2BhpRfE08kuIuNC9irB0YkoHxLzEvcjomGcgbdfE31MA%3D',
  'DImg':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI2NJVYXCCAQDCC5Q&Action=DescribeImages&Expires=2030-01-01&ImageId.1=ami-08514e4e0cd45a2f4&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=CHGkCkAEshf366SEVqz091IHM0ifQmmvIpXtrTeKNyA%3D',
  'instanceId': 'i-0b39e16ddbb48f05e',
  'pubkeyPEM': '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7kyCJQVb6z2qqZmwxE3Uhqtpg0b6\nTn4YzrusUrajjARpy11GvrCpJaa+6LjUwZVNAS6fQ1s7LthGa2AHRJeWpQ==\n-----END PUBLIC KEY-----'
}


//there can be potentially multiple oracles to choose from
var oracles = [];
oracles.push(oracle);


//assuming both events happened on the same day, get the time
//difference between them in seconds
//the time string looks like "2015-04-15T19:00:59.000Z"
function getSecondsDelta(later, sooner) {
  assert(later.length == 24);
  if (later.slice(0, 11) !== sooner.slice(0, 11)) {
    return 999999; //not on the same day
  }
  var laterTime = later.slice(11, 19).split(':');
  var soonerTime = sooner.slice(11, 19).split(':');
  var laterSecs = parseInt(laterTime[0]) * 3600 + parseInt(laterTime[1]) * 60 + parseInt(laterTime[2]);
  var soonerSecs = parseInt(soonerTime[0]) * 3600 + parseInt(soonerTime[1]) * 60 + parseInt(soonerTime[2]);
  return laterSecs - soonerSecs;
}



function checkDescribeInstances(xmlDoc, instanceId, IP, imageId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstancesResponse').length == 1)
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
    assert(parent.getElementsByTagName('imageId')[0].textContent === imageId);
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
    assert(getSecondsDelta(volAttachTime, launchTime) <= 2);
    assert(parent.getElementsByTagName('virtualizationType')[0].textContent === 'hvm');
  } catch (e) {
    throw('checkDescribeInstances exception')
  }
  return {
    'ownerId': ownerId,
    'volumeId': volumeId,
    'volAttachTime': volAttachTime,
    'launchTime': launchTime
  };
}


function checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime, snapshotId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeVolumesResponse').length == 1)
    var volumes = xmlDoc.getElementsByTagName('volumeSet')[0].children;
    assert(volumes.length === 1);
    var volume = volumes[0];
    assert(volume.getElementsByTagName('volumeId')[0].textContent === volumeId);
    assert(volume.getElementsByTagName('snapshotId')[0].textContent === snapshotId);
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
  } catch (e) {
    throw('checkDescribeVolumes exception')
  }
  return true;
}


function checkGetConsoleOutput(xmlDoc, instanceId, launchTime, pubkeyPEM) {
  try {
    assert(xmlDoc.getElementsByTagName('GetConsoleOutputResponse').length == 1)
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    var timestamp = xmlDoc.getElementsByTagName('timestamp')[0].textContent;
    //prevent funny business: last consoleLog entry no later than 5 minutes after instance starts
    //However, it was once observed that timestamp was switched on 2018-01-01. Maybe AWS resets it
    //every first day of the year?
    //Update Oct 2018. 
    //AWS spuriously changed the timestamp of an instance launched in Jan 2018 to Sep 2018.
    //Commenting out the assert because otherwise we'd have to relaunch the oracle server after each
    //such spurious glitch
    //assert(getSecondsDelta(timestamp, launchTime) <= 300);
    var b64data = xmlDoc.getElementsByTagName('output')[0].textContent;
    var logstr = ba2str(b64decode(b64data));
    var sigmark = 'PageSigner public key for verification';
    var pkstartmark = '-----BEGIN PUBLIC KEY-----';
    var pkendmark = '-----END PUBLIC KEY-----';

    var mark_start = logstr.search(sigmark);
    assert(mark_start !== -1);
    var pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
    var pubkey_end = pubkey_start + logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
    var chunk = logstr.slice(pubkey_start, pubkey_end);
    var lines = chunk.split('\n');
    var pk = pkstartmark + '\n';
    for (var i = 1; i < lines.length-1; i++) {
      var words = lines[i].split(' ');
      pk = pk + words[words.length-1] + '\n';
    }
    pk = pk + pkendmark;
    assert(pk.length > 0);
    assert(pk.split('\r\n').join('\n') == pubkeyPEM)
    return true;
  } catch (e) {
    throw('checkGetConsoleOutput exception')
  }
}

// "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
// This is a sanity check because the instance is stripped of the code which parses userData.
function checkDescribeInstanceAttributeUserdata(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1)
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('userData')[0].textContent === "");
  } catch (e) {
    throw('checkDescribeInstanceAttributeUserdata exception')
  }
  return true;
}

function checkDescribeInstanceAttributeKernel(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1)
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('kernel')[0].textContent === "");
  } catch (e) {
    throw('checkDescribeInstanceAttributeKernel exception')
  }
  return true;
}

function checkDescribeInstanceAttributeRamdisk(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1)
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('ramdisk')[0].textContent === "");
  } catch (e) {
    throw('checkDescribeInstanceAttributeRamdisk exception')
  }
  return true;
}


function checkGetUser(xmlDoc, ownerId) {
  try {
    assert(xmlDoc.getElementsByTagName('GetUserResponse').length == 1)
    assert(xmlDoc.getElementsByTagName('UserId')[0].textContent === ownerId);
    assert(xmlDoc.getElementsByTagName('Arn')[0].textContent.slice(-(ownerId.length + ':root'.length)) === ownerId + ':root');
  } catch (e) {
    throw('checkGetUser exception')
  }
  return true;
}


function checkDescribeImages(xmlDoc, imageId, snapshotId){
  try {  
    assert(xmlDoc.getElementsByTagName('DescribeImagesResponse').length == 1)
    var images = xmlDoc.getElementsByTagName('imagesSet')[0].children;
    assert(images.length == 1);
    var image = images[0];
    assert(image.getElementsByTagName('imageId')[0].textContent == imageId);
    assert(image.getElementsByTagName('rootDeviceName')[0].textContent == '/dev/xvda');
    var devices = image.getElementsByTagName('blockDeviceMapping')[0].children;
    assert(devices.length == 1);
    var device = devices[0];
    var ebs = device.getElementsByTagName('ebs')[0];
    assert(ebs.getElementsByTagName('snapshotId')[0].textContent == snapshotId);
  } catch (e) {
    throw('checkDescribeImages exception')
  }
  return true;
}



async function fetch_and_parse(resource){
  var text;
  if (typeof(resource) == 'string'){
    var req = await fetch(resource)
    text = await req.text()
  }
  else if (typeof(resource) == 'object'){
    text = resource.text
  }
  else {
    throw('unknown resource type in fetch_and_parse')
  }
  var xmlDoc = new DOMParser().parseFromString(text, "text/xml")
  return xmlDoc
}


async function check_oracle(o, isOld) {
  var xmlDocDI = await fetch_and_parse(o.DI)
  var rv = checkDescribeInstances(xmlDocDI, o.instanceId, o.IP, o.imageId);
  var volumeId = rv.volumeId
  var volAttachTime = rv.volAttachTime
  var ownerId = rv.ownerId
  var launchTime = rv.launchTime

  var xmlDocDV = await fetch_and_parse(o.DV)
  checkDescribeVolumes(xmlDocDV, o.instanceId, volumeId, volAttachTime, o.snapshotId);

  var xmlDocGU = await fetch_and_parse(o.GU)
  checkGetUser(xmlDocGU, ownerId);

  var xmlDocGCO = await fetch_and_parse(o.GCO)
  var result = checkGetConsoleOutput(xmlDocGCO, o.instanceId, launchTime, o.pubkeyPEM);
  
  var xmlDocDIAud = await fetch_and_parse(o.DIAud)
  checkDescribeInstanceAttributeUserdata(xmlDocDIAud, o.instanceId);

  var xmlDocDIAk = await fetch_and_parse(o.DIAk)
  checkDescribeInstanceAttributeKernel(xmlDocDIAk, o.instanceId);

  var xmlDocDIAr = await fetch_and_parse(o.DIAr)
  checkDescribeInstanceAttributeRamdisk(xmlDocDIAr, o.instanceId);

  var xmlDocDImg = await fetch_and_parse(o.DImg)
  checkDescribeImages(xmlDocDImg, o.imageId, o.snapshotId);

  if (isOld == true){
    //unfortunately there is no way to perform the 'AWSAccessKeyId=' check (see below)
    //for an old oracle server
    console.log('oracle verification successfully finished');
    return true;
  }

  var mark = 'AWSAccessKeyId=';
  var start;
  var id;
  var ids = [];
  //"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
  //The attacker can be a user with limited privileges for whom the API would report only partial information.
  for (var url in [o.DI, o.DV, o.GU, o.GCO, o.DIAud, o.DIAk, o.DIAr, o.DImg]) {
    start = url.search(mark) + mark.length;
    id = url.slice(start, start + url.slice(start).search('&'));
    ids.push(id);
  }
  assert(new Set(ids).size === 1);
  console.log('oracle verification successfully finished');
  return true;
}


async function verifyOldOracle(name){
  if (old_oracle.name != name){
    return {result:false}
  }
  var o = old_oracle;
  for (let key of ['DI', 'DV', 'GU', 'GCO', 'DIAud', 'DIAk', 'DIAr', 'DImg']){
    var pgsg = await import_resource('old oracles/'+name+'/'+key+'.pgsg')
    var rv = await verifyPgsg(JSON.parse(pgsg))
    var serverName = rv[1]
    assert(serverName.split('.').slice(-2).join('.') == 'amazonaws.com')
    var clearText = rv[0]
    //remove HTTP headers
    var httpBody = clearText.split('\r\n\r\n').slice(1)
    o[key] = {text:httpBody}
  }
  var rv = await check_oracle(o, true);
  if (rv == true){
    return {result:true, oracle:o};
  }
  return {result:false};
}




if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    check_oracle,
    oracle,
    verifyOldOracle
  }
}