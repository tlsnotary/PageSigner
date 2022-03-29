import {ba2str, b64decode, assert, ba2int, verifyAttestationDoc, ba2hex, eq,
  sha256} from './utils.js';

// rootsOfTrust contains an array of trusted EBS snapshots
// essentially the whole oracle verification procedure boils down to proving that an EC2 instance was
// launched from an AMI which was created from one of the "rootsOfTrust" snapshot ids.
const rootsOfTrust = [
  'snap-0ccb00d0e0fb4d4da',
  'snap-07eda3ed4836f82fb',
  'snap-023d50ee97873a1f0',
  'snap-0e50af508006037dc',
  'snap-023dda76582a6b29f',
  'snap-027ade4f1002864da'];
// URLFetcher trusted enclave measurements, see
// https://github.com/tlsnotary/URLFetcher
const URLFetcherPCR0 = 'f70217239e8a1cb0f3c010b842a279e2b8d30d3700d7e4722fef22291763479a13783dc76d5219fabbd7e5aa92a7b255';
const URLFetcherPCR1 = 'c35e620586e91ed40ca5ce360eedf77ba673719135951e293121cb3931220b00f87b5a15e94e25c01fecd08fc9139342';
const URLFetcherPCR2 = 'efba114128ccd6af1d1366a12c1ac89e4a4ca5ea1434d779efadfd3ec0d1da5b7c0d8525239fac29ffde2946e07d1c16';


// assuming both events happened on the same day, get the time
// difference between them in seconds
// the time string looks like "2015-04-15T19:00:59.000Z"
function getSecondsDelta(later, sooner) {
  assert(later.length == 24);
  if (later.slice(0, 11) !== sooner.slice(0, 11)) {
    return 999999; // not on the same day
  }
  const laterTime = later.slice(11, 19).split(':');
  const soonerTime = sooner.slice(11, 19).split(':');
  const laterSecs = parseInt(laterTime[0]) * 3600 + parseInt(laterTime[1]) * 60 + parseInt(laterTime[2]);
  const soonerSecs = parseInt(soonerTime[0]) * 3600 + parseInt(soonerTime[1]) * 60 + parseInt(soonerTime[2]);
  return laterSecs - soonerSecs;
}



function checkDescribeInstances(xmlDoc, instanceId, imageId, volumeId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstancesResponse').length == 1);
    const rs = xmlDoc.getElementsByTagName('reservationSet');
    assert(rs.length === 1);
    const rs_items = rs[0].children;
    assert(rs_items.length === 1);
    var ownerId = rs_items[0].getElementsByTagName('ownerId')[0].textContent;
    const isets = rs_items[0].getElementsByTagName('instancesSet');
    assert(isets.length === 1);
    const instances = isets[0].children;
    assert(instances.length === 1);
    const parent = instances[0];
    assert(parent.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(parent.getElementsByTagName('imageId')[0].textContent === imageId);
    assert(parent.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].textContent === 'running');
    // other instance types may use non-nvme disks and thus would bypass the check that
    // only one nvme* disk is allowed
    assert (parent.getElementsByTagName('instanceType')[0].textContent.startsWith('t3'));
    var launchTime = parent.getElementsByTagName('launchTime')[0].textContent;
    assert(parent.getElementsByTagName('rootDeviceType')[0].textContent === 'ebs');
    assert(parent.getElementsByTagName('rootDeviceName')[0].textContent === '/dev/sda1');
    const devices = parent.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item');
    assert(devices.length === 1);
    assert(devices[0].getElementsByTagName('deviceName')[0].textContent === '/dev/sda1');
    assert(devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].textContent === 'attached');
    var volAttachTime = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].textContent;
    assert(devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].textContent === volumeId);
    // get seconds from "2015-04-15T19:00:59.000Z"
    assert(getSecondsDelta(volAttachTime, launchTime) <= 2);
    assert(parent.getElementsByTagName('virtualizationType')[0].textContent === 'hvm');
    assert(parent.getElementsByTagName('hypervisor')[0].textContent === 'xen');
  } catch (e) {
    throw('checkDescribeInstances exception');
  }
  return {
    'ownerId': ownerId,
    'volAttachTime': volAttachTime,
    'launchTime': launchTime
  };
}


function checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime, snapshotIds) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeVolumesResponse').length == 1);
    const volumes = xmlDoc.getElementsByTagName('volumeSet')[0].children;
    assert(volumes.length === 1);
    const volume = volumes[0];
    assert(volume.getElementsByTagName('volumeId')[0].textContent === volumeId);
    assert(snapshotIds.includes(volume.getElementsByTagName('snapshotId')[0].textContent));
    assert(volume.getElementsByTagName('status')[0].textContent === 'in-use');
    const volCreateTime = volume.getElementsByTagName('createTime')[0].textContent;
    const attVolumes = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item');
    assert(attVolumes.length === 1);
    const attVolume = attVolumes[0];
    assert(attVolume.getElementsByTagName('volumeId')[0].textContent === volumeId);
    assert(attVolume.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(attVolume.getElementsByTagName('device')[0].textContent === '/dev/sda1');
    assert(attVolume.getElementsByTagName('status')[0].textContent === 'attached');
    const attTime = attVolume.getElementsByTagName('attachTime')[0].textContent;
    assert(volAttachTime === attTime);
    // Crucial: volume was created from snapshot and attached at the same instant
    // this guarantees that there was no time window to modify it
    assert(getSecondsDelta(attTime, volCreateTime) === 0);
  } catch (e) {
    throw('checkDescribeVolumes exception');
  }
  return true;
}


function checkGetConsoleOutput(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('GetConsoleOutputResponse').length == 1);
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    const b64data = xmlDoc.getElementsByTagName('output')[0].textContent;
    const logstr = ba2str(b64decode(b64data));
    // the only nvme* strings allowed are: nvme, nvme0, nvme0n1, nvme0n1p1
    // this ensures that instance has only one disk device. This is
    // a redundant check, because the patched ramdisk must halt the boot process if
    // it detects more than one disk device.
    const allowedSet = ['nvme', 'nvme0', 'nvme0n1', 'nvme0n1p1'];
    // match all substrings starting with nvme, folowed by a count of from 0 to 7 symbols from
    // the ranges 0-9 and a-z
    for (const match of [...logstr.matchAll(/nvme[0-9a-z]{0,7}/g)]){
      assert(match.length == 1);
      assert(allowedSet.includes(match[0]), 'disallowed nvme* string present in log');
    }

    const sigmark = 'PageSigner public key for verification';
    const pkstartmark = '-----BEGIN PUBLIC KEY-----';
    const pkendmark = '-----END PUBLIC KEY-----';

    const mark_start = logstr.search(sigmark);
    assert(mark_start !== -1);
    const pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark);
    const pubkey_end = pubkey_start + logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length;
    const chunk = logstr.slice(pubkey_start, pubkey_end);
    const lines = chunk.split('\n');
    let pk = pkstartmark + '\n';
    for (let i = 1; i < lines.length-1; i++) {
      const words = lines[i].split(' ');
      pk = pk + words[words.length-1] + '\n';
    }
    pk = pk + pkendmark;
    assert(pk.length > 0);
    const pubkeyPEM = pk.split('\r\n').join('\n');
    return pubkeyPEM;
  } catch (e) {
    throw('checkGetConsoleOutput exception');
  }
}

// "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
// This is a sanity check because the instance is stripped of the code which parses userData.
function checkDescribeInstanceAttributeUserdata(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1);
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('userData')[0].textContent === '');
  } catch (e) {
    throw('checkDescribeInstanceAttributeUserdata exception');
  }
  return true;
}

function checkDescribeInstanceAttributeKernel(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1);
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('kernel')[0].textContent === '');
  } catch (e) {
    throw('checkDescribeInstanceAttributeKernel exception');
  }
  return true;
}

function checkDescribeInstanceAttributeRamdisk(xmlDoc, instanceId) {
  try {
    assert(xmlDoc.getElementsByTagName('DescribeInstanceAttributeResponse').length == 1);
    assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
    assert(xmlDoc.getElementsByTagName('ramdisk')[0].textContent === '');
  } catch (e) {
    throw('checkDescribeInstanceAttributeRamdisk exception');
  }
  return true;
}


function checkGetUser(xmlDoc, ownerId) {
  try {
    assert(xmlDoc.getElementsByTagName('GetUserResponse').length == 1);
    assert(xmlDoc.getElementsByTagName('UserId')[0].textContent === ownerId);
    assert(xmlDoc.getElementsByTagName('Arn')[0].textContent.slice(-(ownerId.length + ':root'.length)) === ownerId + ':root');
  } catch (e) {
    throw('checkGetUser exception');
  }
  return true;
}


function checkDescribeImages(xmlDoc, imageId, snapshotIds){
  try {
    assert(xmlDoc.getElementsByTagName('DescribeImagesResponse').length == 1);
    const images = xmlDoc.getElementsByTagName('imagesSet')[0].children;
    assert(images.length == 1);
    const image = images[0];
    assert(image.getElementsByTagName('imageId')[0].textContent == imageId);
    assert(image.getElementsByTagName('imageState')[0].textContent == 'available');
    assert(image.getElementsByTagName('rootDeviceName')[0].textContent == '/dev/sda1');
    const devices = image.getElementsByTagName('blockDeviceMapping')[0].children;
    assert(devices.length == 1);
    const device = devices[0];
    assert(device.getElementsByTagName('deviceName')[0].textContent == '/dev/sda1');
    const ebs = device.getElementsByTagName('ebs')[0];
    assert(snapshotIds.includes(ebs.getElementsByTagName('snapshotId')[0].textContent));
    assert(image.getElementsByTagName('virtualizationType')[0].textContent == 'hvm');
    assert(image.getElementsByTagName('hypervisor')[0].textContent == 'xen');
  } catch (e) {
    throw('checkDescribeImages exception');
  }
  return true;
}


async function fetch_and_parse(obj){
  // we don't fetch it ourselves anymore. URLFetcher already did that for us.
  // const req = await fetch(obj.request);
  // const text = await req.text();
  const xmlDoc = new DOMParser().parseFromString(obj.response, 'text/xml');
  return xmlDoc;
}

export async function getURLFetcherDoc(IP, port = 10011){
  // get URLFetcher document containing attestation for AWS HTTP API URLs needed to
  // verify that the oracle was correctly set up.
  // https://github.com/tlsnotary/URLFetcher
  const resp = await fetch('http://' + IP + ':' + port + '/getURLFetcherDoc', {
    method: 'POST',
    mode: 'cors',
    cache: 'no-store',
  });
  return new Uint8Array(await resp.arrayBuffer());
}

export async function verifyNotary(URLFetcherDoc) {
  // URLFetcherDoc is a concatenation of 4-byte transcript length | transcript | attestation doc
  const transcriptLen = ba2int(URLFetcherDoc.slice(0, 4));
  const transcript = URLFetcherDoc.slice(4, 4+transcriptLen);
  const attestation = URLFetcherDoc.slice(4+transcriptLen);

  // transcript is a JSON array for each request[ {"request":<URL>, "response":<text>} , {...}]
  const transJSON = JSON.parse(ba2str(transcript));
  // find which URL corresponds to which API call
  const markers = [
    {'DescribeInstances': 'DI'},
    {'DescribeVolumes': 'DV'},
    {'GetConsoleOutput': 'GCO'},
    {'GetUser': 'GU'},
    {'userData': 'DIAud'},
    {'kernel': 'DIAk'},
    {'ramdisk': 'DIAr'},
    {'DescribeImages': 'DImg'}];
  const o = {};
  for (let i=0; i < markers.length; i++){
    const key  = Object.keys(markers[i]);
    for (let j=0; j < transJSON.length; j++){
      if (transJSON[j].request.indexOf(key) > -1){
        o[markers[i][key]] = transJSON[j];
      }
    }
  }
  assert(Object.keys(o).length === markers.length);


  // check that the URLs are formatted in a canonical way
  // Note that AWS expects URL params to be sorted alphabetically. If we put them in
  // arbitrary order, the query will be rejected

  // "AWSAccessKeyId" should be the same in all URLs to prove that the queries are made
  // on behalf of AWS user "root". Otherwise, a potential attack opens up when AWS APi calls
  // are made on behalf of a user with limited privileges for whom the API report only
  // partial information.
  const AWSAccessKeyId = o.DI.request.match(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId=[A-Z0-9]{20}'))[0].split('=')[1];
  // We only allow oracles instantiated from TLSNotary's AWS account.
  assert(AWSAccessKeyId === 'AKIAI2NJVYXCCAQDCC5Q');
  assert(AWSAccessKeyId.length === 20);

  const instanceId = o.DI.request.match(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeInstances&Expires=2030-01-01&InstanceId=i-[a-f0-9]{17}'))[0].split('=')[4];
  assert(instanceId.length === 19);

  const volumeId = o.DV.request.match(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeVolumes&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-[a-f0-9]{17}'))[0].split('=')[7];
  assert(volumeId.length === 21);

  const amiId = o.DImg.request.match(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeImages&Expires=2030-01-01&ImageId.1=ami-[a-f0-9]{17}'))[0].split('=')[4];
  assert(amiId.length === 21);

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeInstances&Expires=2030-01-01&InstanceId='+instanceId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DI.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeVolumes&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId='+volumeId+'&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DV.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=GetConsoleOutput&Expires=2030-01-01&InstanceId='+instanceId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.GCO.request));

  assert(new RegExp('^https://iam.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=GetUser&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=[a-zA-Z0-9%]{46,56}$').test(o.GU.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2030-01-01&InstanceId='+instanceId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DIAud.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeInstanceAttribute&Attribute=kernel&Expires=2030-01-01&InstanceId='+instanceId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DIAk.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeInstanceAttribute&Attribute=ramdisk&Expires=2030-01-01&InstanceId='+instanceId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DIAr.request));

  assert(new RegExp('^https://ec2.us-east-1.amazonaws.com/\\?AWSAccessKeyId='+AWSAccessKeyId+'&Action=DescribeImages&Expires=2030-01-01&ImageId.1='+amiId+'&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{46,56}$').test(o.DImg.request));

  const xmlDocDI = await fetch_and_parse(o.DI);
  const rv = checkDescribeInstances(xmlDocDI, instanceId, amiId, volumeId);
  const volAttachTime = rv.volAttachTime;
  const ownerId = rv.ownerId;

  const xmlDocDV = await fetch_and_parse(o.DV);
  checkDescribeVolumes(xmlDocDV, instanceId, volumeId, volAttachTime, rootsOfTrust);

  const xmlDocGU = await fetch_and_parse(o.GU);
  checkGetUser(xmlDocGU, ownerId);

  const xmlDocGCO = await fetch_and_parse(o.GCO);
  const pubkeyPEM = checkGetConsoleOutput(xmlDocGCO, instanceId);

  const xmlDocDIAud = await fetch_and_parse(o.DIAud);
  checkDescribeInstanceAttributeUserdata(xmlDocDIAud, instanceId);

  const xmlDocDIAk = await fetch_and_parse(o.DIAk);
  checkDescribeInstanceAttributeKernel(xmlDocDIAk, instanceId);

  const xmlDocDIAr = await fetch_and_parse(o.DIAr);
  checkDescribeInstanceAttributeRamdisk(xmlDocDIAr, instanceId);

  const xmlDocDImg = await fetch_and_parse(o.DImg);
  checkDescribeImages(xmlDocDImg, amiId, rootsOfTrust);

  // verify the attestation document
  const attestRV = await verifyAttestationDoc(attestation);
  assert(eq(attestRV[0], await sha256(transcript)));
  assert(URLFetcherPCR0 === ba2hex(attestRV[1]));
  assert(URLFetcherPCR1 === ba2hex(attestRV[2]));
  assert(URLFetcherPCR2 === ba2hex(attestRV[3]));

  console.log('oracle verification successfully finished');
  return pubkeyPEM;
}