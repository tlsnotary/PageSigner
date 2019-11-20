var snapshotID = 'snap-064a466a93406fc97';
var imageID = 'ami-05d008a7920548e61';
var oracles_intact = false; //must be explicitely set to true

var oracle = {
  'name': 'tlsnotarygroup7',
  'IP': '54.226.204.51',
  'port': '10011',
'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2025-01-01&InstanceId=i-05e567cedbaa2d4f0&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ypb7MplXGj9IJi10o4I0wjyFzBW%2B9WB81iebjsiwkkU%3D',
'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-025de53b3c9c27bcd&Signature=C2GacFlwRVJLz%2BY0n6aKPrdNJaZSqJN%2FDAHkpFywKk4%3D',
'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2025-01-01&InstanceId=i-05e567cedbaa2d4f0&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ClP2LQwMf%2BbWR1GoYYnpp2h8Jzkh%2FG1H9SRNFDwENis%3D',
'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=N%2BsdNA6z3QReVsHsf7RV4uZLzS5Pqi0n3QSfqBAMs8o%3D',
'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2025-01-01&InstanceId=i-05e567cedbaa2d4f0&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=uF6c%2FKMHzQjXm6JILQIJ3ofqQIWa%2F7tk7jCtGLghl7w%3D',
  'instanceId': 'i-05e567cedbaa2d4f0',
  'modulus': [183,211,99,46,67,60,38,241,120,196,117,188,233,13,119,234,188,112,200,207,21,101,32,0,106,42,126,62,153,82,112,156,74,172,231,172,15,199,195,177,47,118,125,186,162,23,76,141,151,131,158,4,85,22,165,186,217,50,240,185,168,55,33,70,215,203,49,170,102,224,227,208,34,150,76,58,179,93,48,50,183,235,195,245,71,25,108,124,51,104,235,35,162,141,229,175,229,124,162,145,89,1,73,82,103,119,199,255,85,104,18,80,243,20,109,163,124,198,249,217,178,32,46,88,222,99,31,4,24,251,51,55,92,52,9,107,155,34,150,227,107,177,88,224,220,131,130,214,88,230,42,235,210,177,112,92,83,32,208,117,1,154,119,185,69,122,31,253,175,44,19,25,142,39,141,39,225,156,106,219,126,75,146,74,125,188,246,241,16,134,24,105,150,118,144,172,16,183,202,156,18,96,113,62,171,254,242,90,88,179,162,50,129,53,214,19,37,64,195,78,187,83,139,91,238,109,26,225,176,218,55,105,95,230,178,129,183,81,105,132,50,221,212,128,94,24,10,33,80,59,99,99,170,10,113,174,81,173,95,198,45,44,4,73,165,64,51,5,168,189,195,78,28,194,86,85,213,247,149,33,41,134,254,16,181,53,153,2,210,170,74,248,167,187,44,40,214,239,125,155,230,32,7,135,214,52,170,112,212,249,158,139,106,59,205,58,13,121,62,149,3,236,241,49,201,167,86,113,132,0,67,44,172,9,117,68,207,240,145,103,167,66,133,121,14,233,195,18,31,186,230,104,106,89,251,32,100,188,97,23,9,145,5,214,62,110,119,90,67,26,54,166,182,11,206,118,125,82,219,171,151,239,213,211,26,114,151,200,237,101,180,184,157,114,163,81,225,138,169,222,63,149,216,232,81,136,110,102,59,238,126,176,3,161,198,248,204,200,72,198,158,16,180,1,229,2,235,13,155,125,13,218,128,162,141,206,77,120,83,185,177,62,94,222,66,221,88,64,249,99,126,132,6,164,37,178,172,212,240,198,67,118,134,245,21,106,241,154,56,160,5,204,161,52,156,132,233,27,221,130,55,108,246,124,145,67,170,199,180,2,51,92,44,246,26,181,153,71,159,229,84,100,64,94,28,205,222,240,146,128,5,199]
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



function modulus_from_pubkey(pem_pubkey) {
  var b64_str = '';
  var lines = pem_pubkey.split('\n');
  //omit header and footer lines
  for (var i = 1; i < (lines.length - 1); i++) {
    b64_str += lines[i];
  }
  var der = b64decode(b64_str);
  //last 5 bytes are 2 DER bytes and 3 bytes exponent, our pubkey is the preceding 512 bytes
  var pubkey = der.slice(der.length - 517, der.length - 5);
  return pubkey;
}


function checkDescribeInstances(xmlDoc, instanceId, IP) {
  try {
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
  } catch (e) {
    return false;
  }
  return {
    'ownerId': ownerId,
    'volumeId': volumeId,
    'volAttachTime': volAttachTime,
    'launchTime': launchTime
  };
}


function checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime) {
  try {
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
  } catch (e) {
    return false;
  }
  return true;
}


function checkGetConsoleOutput(xmlDoc, instanceId, launchTime) {
  try {
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
    return pk;
  } catch (e) {
    return false;
  }
}

// "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
// This is a sanity check because the instance is stripped of the code which parses userData.
function checkDescribeInstanceAttribute(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('userData')[0].textContent === "");
  } catch (e) {
    return false;
  }
  return true;
}


function checkGetUser(xmlDoc, ownerId) {
  try {
    assert(xmlDoc.getElementsByTagName('UserId')[0].textContent === ownerId);
    assert(xmlDoc.getElementsByTagName('Arn')[0].textContent.slice(-(ownerId.length + ':root'.length)) === ownerId + ':root');
  } catch (e) {
    return false;
  }
  return true;
}


function check_oracle(o) {
  return new Promise(function(resolve, reject) {
      var xhr = get_xhr();
      xhr.open('GET', o.DI, true);
      xhr.onload = function() {
        var xmlDoc = xhr.responseXML;
        var result = checkDescribeInstances(xmlDoc, o.instanceId, o.IP);
        if (!result) {
          reject('checkDescribeInstances');
        } else {
          resolve(result);
        }
      };
      xhr.send();
    })
    .then(function(args) {
      return new Promise(function(resolve, reject) {
        var xhr = get_xhr();
        xhr.open('GET', o.DV, true);
        xhr.onload = function() {
          var xmlDoc = xhr.responseXML;
          var result = checkDescribeVolumes(xmlDoc, o.instanceId, args.volumeId, args.volAttachTime);
          if (!result) {
            reject('checkDescribeVolumes');
          } else {
            resolve({
              'ownerId': args.ownerId,
              'launchTime': args.launchTime
            });
          }
        };
        xhr.send();
      });
    })
    .then(function(args) {
      return new Promise(function(resolve, reject) {
        var xhr = get_xhr();
        xhr.open('GET', o.GU, true);
        xhr.onload = function() {
          var xmlDoc = xhr.responseXML;
          var result = checkGetUser(xmlDoc, args.ownerId);
          if (!result) {
            reject('checkGetUser');
          } else {
            resolve(args.launchTime);
          }
        };
        xhr.send();
      });
    })
    .then(function(launchTime) {
      return new Promise(function(resolve, reject) {
        var xhr = get_xhr();
        xhr.open('GET', o.GCO, true);
        xhr.onload = function() {
          var xmlDoc = xhr.responseXML;
          var result = checkGetConsoleOutput(xmlDoc, o.instanceId, launchTime);
          if (!result) {
            reject('checkGetConsoleOutput');
          } else {
            if (modulus_from_pubkey(result).toString() !== o.modulus.toString()) {
              reject('modulus_from_pubkey');
            }
            resolve();
          }
        };
        xhr.send();
      });
    })
    .then(function() {
      return new Promise(function(resolve, reject) {
        var xhr = get_xhr();
        xhr.open('GET', o.DIA, true);
        xhr.onload = function() {
          var xmlDoc = xhr.responseXML;
          var result = checkDescribeInstanceAttribute(xmlDoc, o.instanceId);
          if (!result) {
            reject('checkDescribeInstanceAttribute');
          } else {
            resolve();
          }
        };
        xhr.send();
      });
    })
    .then(function() {
      var mark = 'AWSAccessKeyId=';
      var start;
      var id;
      var ids = [];
      //"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
      //The attacker can be a user with limited privileges for whom the API would report only partial information.
      for (var url in [o.DI, o.DV, o.GU, o.GCO, o.DIA]) {
        start = url.search(mark) + mark.length;
        id = url.slice(start, start + url.slice(start).search('&'));
        ids.push(id);
      }
      assert(new Set(ids).size === 1);
      console.log('oracle verification successfully finished');
    });
}
