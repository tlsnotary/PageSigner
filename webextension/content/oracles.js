var snapshotID = 'snap-2c1fab9b';
var imageID = 'ami-15192302';
var oracles_intact = false; //must be explicitely set to true

var oracle = {
  'name': 'tlsnotarygroup4',
  'IP': '54.152.4.116',
  'port': '10011',
  'DI': 'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2019-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ByJUrXXgB%2BmJwc2Irk%2BxfZQh1yR3tYiqcA6Hp2gKciE%3D',
  'DV': 'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2019-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-006fce93&Signature=DXq7nf5BrpjUF7Rj%2FMJgk%2Bbs959FrVcJvfquT%2BeNS%2BM%3D',
  'GCO': 'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2019-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ZUPfAD0jruIIupYSUrXUW7SR9vDhiNIyuVLvO7kgLLM%3D',
  'GU': 'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2019-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=C%2B2l1fpHxTt4p0JnROsu%2FMLlOnAJBjQ%2FS%2B8p%2FumAcH0%3D',
  'DIA': 'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2019-01-01&InstanceId=i-4b3aff5c&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=FBc9vervde7ofgVYS3MR1kIjrW8yyAJQ8wDtURAJkwM%3D',
  'instanceId': 'i-4b3aff5c',
  'modulus': [160, 219, 242, 71, 45, 207, 8, 59, 79, 223, 247, 65, 118, 79, 92, 119, 51, 107, 26, 66, 49, 174, 16, 126, 182, 43, 221, 31, 56, 45, 138, 214, 69, 246, 225, 36, 162, 66, 241, 197, 137, 45, 96, 224, 13, 213, 205, 59, 163, 225, 202, 179, 175, 99, 112, 135, 37, 149, 17, 87, 168, 15, 93, 245, 138, 106, 137, 39, 236, 125, 88, 170, 131, 191, 243, 226, 163, 209, 235, 135, 152, 55, 101, 152, 168, 71, 152, 48, 157, 184, 96, 196, 19, 187, 171, 238, 168, 208, 59, 101, 32, 119, 124, 132, 16, 43, 162, 173, 242, 160, 81, 39, 173, 128, 196, 136, 86, 121, 80, 10, 12, 233, 53, 185, 147, 114, 124, 68, 216, 23, 186, 156, 117, 53, 21, 52, 200, 223, 222, 52, 201, 180, 208, 17, 165, 33, 212, 48, 55, 111, 235, 30, 189, 200, 248, 218, 90, 191, 253, 172, 93, 146, 140, 248, 150, 70, 93, 221, 161, 172, 179, 156, 58, 230, 161, 111, 95, 45, 90, 27, 102, 206, 136, 222, 127, 191, 203, 43, 156, 198, 50, 21, 232, 229, 41, 110, 195, 37, 206, 62, 126, 249, 50, 1, 45, 157, 87, 13, 172, 255, 161, 110, 34, 151, 53, 233, 96, 201, 139, 149, 220, 67, 182, 190, 23, 135, 40, 93, 221, 214, 41, 159, 219, 183, 119, 132, 86, 205, 216, 161, 97, 0, 28, 124, 91, 1, 125, 209, 106, 47, 220, 75, 108, 224, 143, 139, 150, 188, 23, 23, 15, 203, 42, 231, 76, 253, 239, 195, 6, 111, 246, 30, 31, 156, 115, 190, 52, 52, 37, 213, 102, 0, 150, 110, 7, 150, 120, 61, 190, 135, 244, 228, 107, 87, 87, 223, 24, 212, 178, 205, 198, 61, 140, 16, 44, 6, 224, 168, 214, 53, 201, 247, 121, 138, 240, 72, 7, 73, 149, 181, 133, 147, 124, 221, 222, 46, 121, 176, 200, 162, 48, 33, 59, 241, 254, 30, 247, 7, 165, 91, 166, 113, 133, 119, 234, 229, 129, 162, 64, 164, 205, 172, 79, 182, 147, 63, 226, 133, 82, 201, 26, 251, 17, 227, 251, 0, 25, 238, 38, 70, 85, 229, 92, 103, 180, 87, 60, 159, 148, 113, 135, 33, 169, 101, 184, 138, 239, 71, 40, 187, 1, 133, 134, 49, 160, 236, 165, 160, 250, 77, 140, 213, 234, 172, 225, 231, 174, 21, 29, 220, 60, 221, 177, 21, 26, 245, 163, 155, 187, 28, 66, 50, 159, 184, 97, 107, 14, 86, 26, 145, 171, 88, 137, 238, 212, 36, 79, 123, 183, 190, 202, 177, 201, 132, 121, 178, 127, 149, 13, 184, 243, 47, 132, 120, 153, 28, 41, 169, 72, 251, 152, 86, 153, 212, 63, 247, 29, 52, 173, 26, 252, 249, 63, 146, 188, 53, 97, 244, 90, 123, 71, 47, 195, 142, 91, 123, 213, 151, 166, 229, 208, 154, 127, 208, 243, 253, 168, 154, 171, 110, 253, 153, 129, 176, 27, 155, 195, 103, 49, 211, 182, 55]
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
    var pk = logstr.slice(pubkey_start, pubkey_end);
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
