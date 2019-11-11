var snapshotID = 'snap-05b5f6041423fd2db';
var imageID = 'ami-0ca1099143a3f8ab6';
var oracles_intact = false; //must be explicitely set to true

var oracle = {
  'name': 'tlsnotarygroup6',
  'IP': '54.242.234.190',
  'port': '10011',
'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2025-01-01&InstanceId=i-005926de206f0842f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=rut81I7SfyvZelmaqMoO4ecYOBpr38pxWklSw%2F0BLzE%3D',
'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-0bc0c744e7e80caf8&Signature=dRMzmaKFpO2rpyZMASBCk%2FcN6Xis7sbAO%2FNwl955xuQ%3D',
'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2025-01-01&InstanceId=i-005926de206f0842f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ug1S5Q8P%2FdhxjmxOcQieccIsXanBLp3bSnMd6N1aET4%3D',
'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=N%2BsdNA6z3QReVsHsf7RV4uZLzS5Pqi0n3QSfqBAMs8o%3D',
'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2025-01-01&InstanceId=i-005926de206f0842f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=bbLlfTGyLKv7KbfTjA0oNxyA1jsKCEA5JeTOe94iVZw%3D',
  'instanceId': 'i-005926de206f0842f',
  'modulus': [202,10,158,137,72,89,164,206,137,132,96,179,110,186,190,243,158,163,50,21,74,51,180,157,59,226,117,149,80,52,168,38,230,70,86,111,200,84,169,131,111,210,243,0,148,248,17,82,168,164,94,212,247,244,97,208,21,196,210,151,163,198,255,107,76,115,65,180,35,199,59,160,145,35,81,171,92,127,218,87,94,235,252,252,43,53,61,176,73,49,47,33,154,137,195,212,156,116,251,51,245,57,105,250,235,55,142,134,95,6,158,254,202,211,96,59,102,0,102,30,171,150,30,2,195,1,115,230,81,184,32,121,1,221,185,124,217,134,56,255,163,8,120,131,68,249,129,58,43,253,128,160,255,52,118,6,136,207,0,124,246,100,86,104,144,13,153,3,93,29,154,68,21,150,52,225,231,191,165,25,248,201,1,251,203,127,135,228,81,57,21,211,222,202,102,122,215,120,166,237,250,182,102,213,18,53,86,123,25,6,3,86,95,91,182,201,138,141,136,32,65,249,232,24,25,71,24,153,179,174,153,212,187,225,127,224,151,130,89,61,91,35,109,32,14,27,161,52,29,255,219,249,8,85,117,85,219,155,26,137,239,47,158,254,133,1,55,102,67,132,211,227,204,138,57,1,221,39,6,163,12,115,192,116,89,130,249,79,252,125,185,209,109,205,101,44,141,5,30,201,215,175,101,203,216,31,168,40,244,156,29,138,205,78,252,183,59,169,237,75,154,99,239,73,38,133,83,44,244,190,97,22,147,42,172,78,253,164,193,194,166,221,215,23,48,88,32,131,169,83,54,222,232,113,243,139,58,13,221,116,26,94,148,85,51,0,146,159,76,168,247,92,210,220,89,111,195,194,218,215,13,12,95,61,239,142,149,196,130,115,98,187,100,62,131,73,200,150,18,196,203,200,194,95,166,76,125,52,42,163,110,10,158,190,193,212,117,33,144,137,18,227,139,170,105,92,77,153,108,123,33,18,152,128,130,69,138,203,145,31,147,10,12,213,174,162,127,82,205,145,254,7,62,231,148,33,233,51,182,160,233,63,218,191,172,214,68,135,140,34,144,181,228,85,208,109,58,203,236,225,131,113,134,170,78,52,246,94,244,160,134,189,248,5,121,69,29,230,224,94,142,51,188,59,106,85,125,120,213,242,182,73]
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
