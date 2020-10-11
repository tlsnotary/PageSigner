//js native ArrayBuffer to Array of numbers
function ab2ba(ab) {
  var view = new DataView(ab);
  var int_array = [];
  for (var i = 0; i < view.byteLength; i++) {
    int_array.push(view.getUint8(i));
  }
  return int_array;
}


function ba2ab(ba) {
  assert (ba.length != 'undefined', "Can only convert from an array")
  var ab = new ArrayBuffer(ba.length);
  var dv = new DataView(ab);
  for (var i = 0; i < ba.length; i++) {
    dv.setUint8(i, ba[i]);
  }
  return ab;
}



function ba2ua(ba) {
  var ua = new Uint8Array(ba.length);
  for (var i = 0; i < ba.length; i++) {
    ua[i] = ba[i];
  }
  return ua;
}

  function ua2ba(ua) {
  var ba = [];
  for (var i = 0; i < ua.byteLength; i++) {
    ba.push(ua[i]);
  }
  return ba;
}

/*CryptoJS only exposes word arrays of ciphertexts which is awkward to use
so we convert word(4byte) array into a 1-byte array*/
function wa2ba(wordArray) {
  var byteArray = [];
  for (var i = 0; i < wordArray.length; ++i) {
    var word = wordArray[i];
    for (var j = 3; j >= 0; --j) {
      byteArray.push((word >> 8 * j) & 0xFF);
    }
  }
  return byteArray;
}

//CryptoJS doesnt accept bytearray input but it does accept a hexstring
function ba2hex(bytearray) {
  try {
    var hexstring = '';
    for (var i = 0; i < bytearray.length; i++) {
      var hexchar = bytearray[i].toString(16);
      if (hexchar.length == 1) {
        hexchar = "0" + hexchar;
      }
      hexstring += hexchar;
    }
    return hexstring;
  } catch (e) {
    var place_for_breakpoint = 0;
  }
}


//convert a hex string into byte array
function hex2ba(str) {
  var ba = [];
  //pad with a leading 0 if necessary
  if (str.length % 2) {
    str = "0" + str;
  }
  for (var i = 0; i < str.length; i += 2) {
    ba.push(parseInt("0x" + str.substr(i, 2)));
  }
  return ba;
}

//Turn a max 4 byte array (big-endian) into an int.
function ba2int(x) {
  assert(x.length <= 8, "Cannot convert bytearray larger than 8 bytes");
  var retval = 0;
  for (var i = 0; i < x.length; i++) {
    retval |= x[x.length - 1 - i] << 8 * i;
  }
  return retval;
}


//Turn an int into a bytearray. Optionally left-pad with zeroes
function bi2ba(x, args) {
  assert(typeof(x) == "number", "Only can convert numbers");
  var fixed = null;
  if (typeof(args) !== 'undefined') {
    fixed = args.fixed;
  }
  var bytes = [];
  do {
    var onebyte = x & (255);
    x = x >> 8;
    bytes = [].concat(onebyte, bytes);
  } while (x !== 0);
  var padding = [];
  if (fixed) {
    for (var i = 0; i < fixed - bytes.length; i++) {
      padding = [].concat(padding, 0x00);
    }
  }
  return [].concat(padding, bytes);
}


//converts string to bytearray
function str2ba(str) {
  if (typeof(str) !== "string") {
    throw ("Only type string is allowed in str2ba");
  }
  ba = [];
  for (var i = 0; i < str.length; i++) {
    ba.push(str.charCodeAt(i));
  }
  return ba;
}

function ba2str(ba) {
  if (typeof(ba) !== "object") {
    throw ("Only type object is allowed in ba2str");
  }
  var result = "";
  for (var i = 0; i < ba.length; i++) {
    result += String.fromCharCode(ba[i]);
  }
  return result;
}




async function sha256(ba) {
  var digest = await crypto.subtle.digest('SHA-256', ba2ab(ba))
  return (ab2ba(digest))
}



function assert(condition, message) {
  if (!condition) {
    throw message || "Assertion failed";
  }
}

function isdefined(obj) {
  assert(typeof(obj) !== "undefined", "obj was undefined");
}

//Not in use for now
function log() {
  if (verbose) {
    console.log(Array.prototype.slice.call(arguments));
  }
}


function getRandom(number) {
  //window was undefined in this context, so i decided to pass it explicitely
  return Array.from(crypto.getRandomValues(new Uint8Array(number)));
}



function b64encode(aBytes) {
  if (typeof window === 'undefined') {
    //running in nodejs
    return Buffer.from(aBytes).toString('base64');
  }
  else {
    //if aBytes is too large > ~100 KB, we may get an error
    //RangeError: Maximum call stack size exceeded
    //therefore we split the input into chunks
    var strings = '';
    var chunksize = 4096;
    for (var i = 0; i * chunksize < aBytes.length; i++){
      strings += String.fromCharCode.apply(null, aBytes.slice(i * chunksize, (i + 1) * chunksize));
    }
    return btoa(strings);
  }
}


function b64decode(sBase64) {
  if (typeof window === 'undefined') {
    //running in nodejs
    return Buffer.from(sBase64, 'base64').toJSON().data;
  }
  else {
    return atob(sBase64).split("").map(function(c) {
      return c.charCodeAt(0);
    });
  }
}

//conform to base64url format replace +/= with -_ 
function b64urlencode (aBytes){
  var str;
  if (typeof window === 'undefined') {
    //running in nodejs
    str = Buffer.from(aBytes).toString('base64');
  }
  else {
    str = btoa(String.fromCharCode.apply(null, aBytes));
  }
  return str.split('+').join('-').split('/').join('_').split('=').join('')
}

//plaintext must be string
function dechunk_http(http_data) {
  //'''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
  http_header = http_data.slice(0, http_data.search('\r\n\r\n') + '\r\n\r\n'.length);
  //#\s* below means any amount of whitespaces
  if (http_header.search(/transfer-encoding:\s*chunked/i) === -1) {
    return http_data; //#nothing to dechunk
  }
  var http_body = http_data.slice(http_header.length);

  var dechunked = http_header;
  var cur_offset = 0;
  var chunk_len = -1; //#initialize with a non-zero value
  while (true) {
    var new_offset = http_body.slice(cur_offset).search('\r\n');
    if (new_offset === -1) { //#pre-caution against endless looping
      //#pinterest.com is known to not send the last 0 chunk when HTTP gzip is disabled
      return dechunked;
    }
    var chunk_len_hex = http_body.slice(cur_offset, cur_offset + new_offset);
    var chunk_len = parseInt(chunk_len_hex, 16);
    if (chunk_len === 0) {
      break; //#for properly-formed html we should break here
    }
    cur_offset += new_offset + '\r\n'.length;
    dechunked += http_body.slice(cur_offset, cur_offset + chunk_len);
    cur_offset += chunk_len + '\r\n'.length;
  }
  return dechunked;
}


function gunzip_http(http_data) {
  var http_header = http_data.slice(0, http_data.search('\r\n\r\n') + '\r\n\r\n'.length);
  //#\s* below means any amount of whitespaces
  if (http_header.search(/content-encoding:\s*deflate/i) > -1) {
    //#TODO manually resend the request with compression disabled
    throw ('please disable compression and rerun the notarization');
  }
  if (http_header.search(/content-encoding:\s.*gzip/i) === -1) {
    console.log('nothing to gunzip');
    return http_data; //#nothing to gunzip
  }
  var http_body = http_data.slice(http_header.length);
  var ungzipped = http_header;
  if (!http_body) {
    //HTTP 304 Not Modified has no body
    return ungzipped;
  }
  var inflated = pako.inflate(http_body);
  ungzipped += ba2str(inflated);
  return ungzipped;
}

function getTime() {
  var today = new Date();
  var time = today.getFullYear() + '-' + ("00" + (today.getMonth() + 1)).slice(-2) + '-' + ("00" + today.getDate()).slice(-2) + '-' + ("00" + today.getHours()).slice(-2) + '-' + ("00" + today.getMinutes()).slice(-2) + '-' + ("00" + today.getSeconds()).slice(-2);
  return time;
}

//PEM certificate/pubkey to ArrayBuffer
function pem2ab(pem) {
  var lines = pem.split('\n');
  var encoded = '';
  for(let line of lines){
    if (line.trim().length > 0 &&
        line.indexOf('-BEGIN CERTIFICATE-') < 0 &&
        line.indexOf('-BEGIN PUBLIC KEY-') < 0 &&
        line.indexOf('-END PUBLIC KEY-') < 0 &&
        line.indexOf('-END CERTIFICATE-') < 0 ) {
      encoded += line.trim();
    }
  }
  return ba2ab(b64decode(encoded))    
}


//compare 2 Arrays
function eq(a, b) {
  return Array.isArray(a) &&
    Array.isArray(b) &&
    a.length === b.length &&
    a.every((val, index) => val === b[index]);
}



// convert OpenSSL's signature format (asn1 DER) into WebCrypto's IEEE P1363 format
function sigDER2p1363(sigDER){
  var o = 0
  assert(eq(sigDER.slice(o,o+=1), [0x30]))
  var total_len = ba2int(sigDER.slice(o,o+=1))
  assert(sigDER.length == total_len+2)
  assert(eq(sigDER.slice(o,o+=1), [0x02]))
  var r_len = ba2int(sigDER.slice(o,o+=1))
  assert(r_len == 32 || r_len==33)
  var r = sigDER.slice(o,o+=r_len)
  assert(eq(sigDER.slice(o,o+=1), [0x02]))
  var s_len = ba2int(sigDER.slice(o,o+=1))
  assert(s_len == 32 || s_len==33)
  var s = sigDER.slice(o,o+=s_len)
  if (s.length == 31){
    s = [].concat([0x00], s)
  }
  if (r_len == 33){
    assert(eq(r.slice(0,1), [0x00]))
    r = r.slice(1)
  }
  if (s_len == 33){
    assert(eq(s.slice(0,1), [0x00]))
    s = s.slice(1)
  }
  var sig_p1363 = [].concat(r,s) 
  return sig_p1363;
}


//take PEM EC pubkey and output a "raw" pubkey with all asn1 data stripped
function pubkeyPEM2raw(pkPEM){
  //prepended asn1 data for ECpubkey prime256v1
  const preasn1 = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
  pk_ba = ab2ba(pem2ab(pkPEM))
  assert(eq(pk_ba.slice(0, preasn1.length), preasn1))
  var pkraw = pk_ba.slice(preasn1.length)
  return pkraw
}


//test a string against a wildcard - useful when checking certificate's names
function wildTest(wildcard, str) {
  let w = wildcard.replace(/[.+^${}()|[\]\\]/g, '\\$&'); // regexp escape 
  const re = new RegExp(`^${w.replace(/\*/g,'.*').replace(/\?/g,'.')}$`,'i');
  return re.test(str); // remove last 'i' above to have case sensitive
}


if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    assert,
    ba2ab,
    ba2str,
    bi2ba,
    ab2ba,
    ba2int,
    b64encode,
    b64decode,
    b64urlencode,
    dechunk_http,
    gunzip_http,
    eq,
    getTime,
    pem2ab,
    pubkeyPEM2raw,
    sha256,
    sigDER2p1363,
    str2ba,
    wildTest
  }
}