var snapshotID = 'snap-03bae56722ceec3f0';
var imageID = 'ami-1f447c65';
var oracles_intact = false; //must be explicitely set to true

var oracle = {
  'name': 'tlsnotarygroup5',
  'IP': '54.158.251.14',
  'port': '10011',
'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=AWkxF%2FlBVL%2FBl2WhQC62qGJ80qhL%2B%2B%2FJXvSp8mm5sIg%3D',
'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-056223d4e1ce55d9c&Signature=DCYnV1vNqE3cyTm6bmtNS1idGdBT7DcbeLtZfcm3ljo%3D',
'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=I%2F1kp7oSli9GvYrrP5HD52D6nOy7yCq9dowaDomSAOQ%3D',
'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=N%2BsdNA6z3QReVsHsf7RV4uZLzS5Pqi0n3QSfqBAMs8o%3D',
'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ENM%2Bw9WkB4U4kYDMN6kowJhZenuCEX3c1G7xSuu6GZA%3D',
  'instanceId': 'i-0858c02ad9a33c579',
  'modulus': [186,187,68,57,92,215,243,62,188,248,16,13,3,29,40,217,208,206,78,13,202,184,82,121,26,51,203,41,169,11,4,102,228,127,110,117,170,48,210,212,160,51,175,246,110,178,43,106,94,255,69,0,217,91,225,7,84,133,193,43,177,254,75,191,109,50,212,190,177,61,64,230,188,105,56,252,40,3,91,190,117,1,52,30,210,137,136,13,216,110,83,21,164,56,248,215,33,159,129,149,85,236,130,194,79,227,184,135,133,61,85,201,243,225,121,233,36,84,207,218,86,68,99,21,150,252,28,220,4,93,81,57,214,94,147,56,234,236,0,178,93,39,48,143,21,120,241,33,73,239,185,255,255,79,112,194,72,226,84,158,182,96,159,33,111,57,212,27,23,133,223,152,101,240,98,181,94,38,147,195,187,245,226,158,11,102,91,91,47,146,178,65,180,73,176,209,32,27,99,183,254,161,115,38,186,31,132,165,252,189,226,72,152,219,177,52,47,178,121,45,30,143,78,142,223,133,112,136,72,165,166,225,18,62,249,119,157,198,68,114,69,199,32,121,201,72,159,13,37,66,160,210,83,163,131,128,54,178,219,5,74,94,214,244,43,123,140,156,192,89,120,211,61,192,76,70,176,122,247,198,21,220,79,212,200,192,88,126,200,115,71,102,66,92,102,60,179,213,125,123,86,195,67,204,71,222,249,46,242,179,11,111,12,158,91,189,215,72,190,15,165,11,102,51,1,91,116,127,31,12,55,193,249,170,15,231,13,189,60,73,8,239,238,18,44,131,78,190,164,46,41,169,139,43,230,105,2,170,231,202,203,126,74,202,172,112,217,194,26,202,140,71,183,45,239,213,254,213,139,27,95,163,172,27,176,189,233,59,181,49,225,220,125,90,182,120,183,236,62,100,170,130,122,202,206,193,77,130,250,167,187,238,39,197,216,183,56,203,72,122,168,64,217,225,8,233,13,164,224,23,255,239,230,44,90,31,149,106,207,28,9,249,154,163,84,231,149,167,59,194,193,41,106,239,30,137,188,78,45,66,30,224,233,181,132,146,106,227,135,229,106,71,168,69,149,167,154,150,106,29,130,114,109,11,66,120,42,128,247,166,248,152,103,131,56,88,37,46,19,240,110,135,15,234,44,39,87,65,232,105,2,163]
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
    assert(getSecondsDelta(timestamp, launchTime) <= 300);
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
