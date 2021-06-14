async function send_and_recv(command, data, expected_response, uid) {
  var url = "http://" + chosen_notary.IP + ":" + chosen_notary.port
  var payload = JSON.stringify({'request':command, 'uid': uid, 'data':b64encode(data)})
  try{
    var req = await fetch(url, {method:'POST', body: payload, cache: 'no-store'})
  }
  catch (err){
    throw('Could not connect to the PageSigner server. The error was:' + err)
  }
  var text_ab = await req.arrayBuffer()
  var text = ba2str(ab2ba(text_ab))
  console.log(text.length, text.slice(-100))

  var response_json = JSON.parse(text);
  if (response_json.response !== expected_response) {
    reject('Unexpected response. Expected ' + expected_response + ' but got ' + response);
    return;
  }
  var data = b64decode(response_json.data);
  return data;
}


const start_audit = async function(server, port, headers){
  var mhm = false //multiple handshake messages

  var all_handshakes = []; //a concatenation of all handshake messages up to this point
  var client_write_key = null;
  var client_write_IV = null;
  var cwkCryptoKey = null; // client_write_key in Crypto.Subtle format
  var uid = Math.random().toString(36).slice(-10); //a new uid for each notarized page

  let supported_groups_extension = []
  supported_groups_extension.push(0x00, 0x0a) //Type supported_groups
  supported_groups_extension.push(0x00, 0x04) //Length
  supported_groups_extension.push(0x00, 0x02) //Supported Groups List Length
  supported_groups_extension.push(0x00, 0x17) //Supported Group: secp256r1

  let signature_algorithm_extension = []
  supported_groups_extension.push(0x00, 0x0d) //Type signature_algorithms
  signature_algorithm_extension.push(0x00, 0x04) //Length
  signature_algorithm_extension.push(0x00, 0x02) //Signature Hash Algorithms Length
  signature_algorithm_extension.push(0x04, 0x01) //Signature Algorithm: rsa_pkcs1_sha256 (0x0401)

  let server_name_extension = []
  let server_name = str2ba(server)
  server_name_extension.push(0x00, 0x00) //Extension type: server_name
  server_name_extension = server_name_extension.concat(bi2ba(server_name.length+5, {fixed:2})) //Length
  server_name_extension = server_name_extension.concat(bi2ba(server_name.length+3, {fixed:2})) //Server Name List Length
  server_name_extension.push(0x00) //Type: host name
  server_name_extension = server_name_extension.concat(bi2ba(server_name.length, {fixed:2})) //Server Name Length
  server_name_extension = server_name_extension.concat(server_name)

  let max_fragment_length_extension = []
  if (use_max_fragment_length){
    max_fragment_length_extension.push(0x00, 0x01) //Type: max_fragment_length
    max_fragment_length_extension.push(0x00, 0x01) //Length
    //allowed values 0x01 = 512 0x02 = 1024 0x03 = 2048 0x04 = 4096
    //some servers support 0x04 but send alert if < 0x04
    max_fragment_length_extension.push(0x04)
  }
  
  let extlen = supported_groups_extension.length + signature_algorithm_extension.length + server_name_extension.length + max_fragment_length_extension.length

  ch = []
  ch.push(0x01) //Handshake type: Client Hello 
  ch = ch.concat( bi2ba((extlen + 43), {fixed:3}) ) //Length
  ch.push(0x03, 0x03) //Version: TLS 1.2
  var client_random = getRandom(32)
  ch = ch.concat(client_random)
  ch.push(0x00) //Session ID Length
  ch.push(0x00, 0x02) //Cipher Suites Length
  ch.push(0xc0, 0x2f) //Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ch.push(0x01) //Compression Methods Length
  ch.push(0x00) //Compression Method: null

  ch = ch.concat( bi2ba((extlen), {fixed:2}) )
  ch = [].concat(ch, supported_groups_extension, signature_algorithm_extension, server_name_extension, max_fragment_length_extension)
  all_handshakes = all_handshakes.concat(ch)

  var tls_record_header = []
  tls_record_header.push(0x16) //Type: Handshake
  tls_record_header.push(0x03, 0x03) // Version: TLS 1.2
  tls_record_header = tls_record_header.concat(bi2ba((ch.length), {fixed:2})) // Length 

  var sckt = new Socket(server, port);
  await sckt.connect()
  console.log('connected')
  sckt.send([].concat(tls_record_header, ch)); //Send Client Hello

  //asynchronously prepair keypair for auditee<-->auditor ECDH 
  var rvgk = await crypto.subtle.generateKey({'name':'ECDH', 'namedCurve':'P-256'}, true, ['deriveBits']);
  var commPubkey = rvgk.publicKey
  var commPrivkey = rvgk.privateKey
  var commRawPubkey = await crypto.subtle.exportKey('raw', commPubkey);
  var commRawPubkey_ba = ab2ba(commRawPubkey)

  var s = await sckt.recv(true);
  console.log(s)

  //Parse Server Hello, Certificate, Server Key Exchange, Server Hello Done
  if (eq(s.slice(0,2), [0x15, 0x03])){
    console.log('Server sent Alert instead of Server Hello')
    throw ('Unfortunately PageSigner is not yet able to notarize this website. You can contact the PageSigner developers and ask to add support for this website.');
  }
  var p = 0 //current position in byte stream
  assert(eq(s.slice(p, p+=1), [0x16])) //Type: Handshake
  assert(eq(s.slice(p, p+=2), [0x03, 0x03])) //Version: TLS 1.2
  let handshakelen = ba2int(s.slice(p, p+=2)) 
  //This may be the length of multiple handshake messages (MHM)
  //For MHM there is only 1 TLS Record layer header followed by Handshake layer messages
  //Without MHM, each handshake message has its own TLS Record header

  var shlen = ba2int(s.slice(p+1, p+4))
  var sh = s.slice(p, p + 4 + shlen)
  all_handshakes = all_handshakes.concat(sh)

  assert(eq(s.slice(p, p+=1), [0x02])) //Server Hello
  var shlen = ba2int(s.slice(p, p+=3))
  assert(eq(s.slice(p, p+=2), [0x03, 0x03])) //Version: TLS 1.2
  var server_random = s.slice(p, p+=32)
  let sidlen = ba2int(s.slice(p, p+=1))
  if (sidlen) p+=sidlen //32 bytes of session ID, if any
  assert(eq(s.slice(p, p+=2), [0xc0, 0x2f])) //Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 
  assert(eq(s.slice(p, p+=1), [0x00])) //Compression Method: null (0)
  //May contain Extensions. We don't need to parse them
  p = 5+4+shlen

  if (handshakelen > shlen+4) mhm = true //multiple handshake messages
  
  if (!mhm){
    //read the TLS Record header 
    assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])) //Type: Handshake # Version: TLS 1.2
    var reclen = ba2int(s.slice(p, p+=2))
  }

  var clen = ba2int(s.slice(p+1, p+4))
  var c = s.slice(p, p + 4 + clen)
  all_handshakes = all_handshakes.concat(c)

  assert(eq(s.slice(p, p+=1), [0x0b])) //Certificate
  var clen = ba2int(s.slice(p, p+=3)) 
  if (!mhm) assert(reclen == clen+4)
  var certslen = ba2int(s.slice(p, p+=3))
  var certs_last_pos = p + certslen
  var certs = []
  while (p < certs_last_pos){
    let certlen = ba2int(s.slice(p, p+=3))
    let certder = s.slice(p, p+certlen); p+=certlen
    certs.push(certder)
  }
  var vcrv = await verifyChain(certs);
  if (vcrv[0] != true) {
    throw ('Cannot notarize because the website presented an untrusted certificate');
  }
  if (vcrv[1]) certs.push(vcrv[1]) //add an intermediate certificate which was missing from the chain


  var commonName = getCommonName(certs[0]);
  assert(checkCertSubjName(certs[0], server) == true, "server name is not the same as the certificate's subject name(s)")

 
  if (mhm && (handshakelen+5 == p)){
    //another MHM header will follow, read its header
    assert(eq(s.slice(p, p+=1), [0x16])) //Type: Handshake
    assert(eq(s.slice(p, p+=2), [0x03, 0x03])) //Version: TLS 1.2
    handshakelen = ba2int(s.slice(p, p+=2)) //This may be the length of multiple handshake messages (MHM)
  }
  if (!mhm){
    //read the TLS Record header 
    assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])) //Type: Handshake # Version: TLS 1.2
    var reclen = ba2int(s.slice(p, p+=2))
  }

  var skelen = ba2int(s.slice(p+1, p+4))
  var ske = s.slice(p, p + 4+ skelen)
  all_handshakes = all_handshakes.concat(ske)

  assert(eq(s.slice(p, p+=1), [0x0c])) //Handshake Type: Server Key Exchange (12)
  var skelen = ba2int(s.slice(p, p+=3)) 
  if (!mhm) assert(reclen == skelen+4)
  // EC Diffie-Hellman Server Params
  assert(eq(s.slice(p, p+=1), [0x03])) //Curve Type: named_curve (0x03)
  assert(eq(s.slice(p, p+=2), [0x00, 0x17])) //Named Curve: secp256r1 (0x0017)
  var pklen = ba2int(s.slice(p, p+=1))
  assert (pklen == 65) //Pubkey Length: 65
  var ec_pubkey_server = s.slice(p, p+=pklen)
  assert(eq(s.slice(p, p+=2), [0x04, 0x01])) //#Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
  var siglen = ba2int(s.slice(p, p+=2))
  var rsa_sig = s.slice(p, p+=siglen)

  var vecprv = await verifyECParamsSig(certs[0], ec_pubkey_server, rsa_sig, client_random, server_random)
  if (vecprv != true){
    throw ('EC parameters signature verification failed');
  }

  //Parse Server Hello Done
  if (!mhm) {
    //read the TLS Record header 
    assert(eq(s.slice(p, p+=3), [0x16, 0x03, 0x03])) //Type: Handshake # Version: TLS 1.2
    let reclen = ba2int(s.slice(p, p+=2))
  }
  var shd = s.slice(p, p+=4)
  assert(eq(shd, [0x0e, 0x00, 0x00, 0x00]))
  assert(p == s.length)

  all_handshakes = all_handshakes.concat(shd)

  var reply_data_enc = await send_and_recv('cr_sr_spk_commpk', [].concat(
    client_random, server_random, ec_pubkey_server, commRawPubkey_ba), 'commpk_commpksig_cpk_cwk_cwi', uid)
  //communication pubkey is not encrypted
  //Notary's EC pubkey for ECDH secret for communication
  var comm_pk = reply_data_enc.slice(0,65)
  var commSymmetricKey = await getECDHSecret(comm_pk, commPrivkey)
  var reply_data = await decryptNotaryResponse(commSymmetricKey, reply_data_enc.slice(65))

  var o = 0 //offset
  //get signature over communication pubkey
  var siglen = ba2int(reply_data.slice(o,o+=1))
  var commpk_sig = reply_data.slice(o, o+=siglen)
  //check signature
  var to_be_signed = await sha256(comm_pk)
  assert(await verifyNotarySig(commpk_sig, chosen_notary.pubkeyPEM, to_be_signed) == true)

  var cpk = reply_data.slice(o,o+=65) //Client's pubkey for ECDH
  client_write_key = reply_data.slice(o, o+=16)
  client_write_IV = reply_data.slice(o, o+=4)

  
  //Send Client Key Exchange, Change Cipher Spec and Encrypted Handshake Message
  var cke_tls_record_header = [0x16, 0x03, 0x03, 0x00, 0x46] //Type: Handshake, Version: TLS 1.3, Length 
  cke = [0x10] //Handshake type: Client Key Exchange 
  cke.push(0x00, 0x00, 0x42) // Length
  cke.push(0x41) //Pubkey Length: 65
  cke = [].concat(cke, cpk) // Client's Pubkey

  ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
      
  //hash of all the handshakes. This is only data visible at the handshake layer
  //and does not include record layer headers
  all_handshakes = [].concat(all_handshakes, cke)
  var hs_hash = await sha256(all_handshakes)

  var enc = await encryptNotaryRequest(commSymmetricKey, hs_hash)
  var reply_data_enc = await send_and_recv('hshash', enc, 'vd', uid)
  var reply_data = await decryptNotaryResponse(commSymmetricKey, reply_data_enc)

  assert(reply_data.length == 12)
  verify_data = reply_data.slice(0, 12)


  var client_finished = await (async function encrypt_client_finished(){
    let finished = [].concat([0x14, 0x00, 0x00, 0x0c], verify_data) //Finished (0x14) with length 12
    all_handshakes = [].concat(all_handshakes, finished)

    let explicit_nonce = getRandom(8)
    let nonce = [].concat(client_write_IV, explicit_nonce)
    let seq_num = 0
    let aad = [] //additional_data
    aad = [].concat(aad, bi2ba(seq_num, {fixed:8})) // seq_num
    aad.push(0x16) // type 0x16 = Handshake
    aad.push(0x03, 0x03) // TLS Version 1.2
    aad.push(0x00, 0x10) // 16 bytes of unencrypted data
    let ck = await crypto.subtle.importKey("raw", ba2ab(client_write_key), "AES-GCM", true, ["encrypt", "decrypt"]);
    cwkCryptoKey = ck
    let ciphertext = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv: ba2ab(nonce), additionalData: ba2ab(aad)}, cwkCryptoKey, ba2ab(finished));
    let ct = ab2ba(ciphertext)
    let f = [0x16, 0x03, 0x03, 0x00, 0x28] //Finished message of 40 (0x28) bytes length
    f = [].concat(f, explicit_nonce, ct)
    return f
  })()

  var data_to_send = [].concat(cke_tls_record_header, cke, ccs, client_finished)

  sckt.send(data_to_send); //Send Client Key Exchange
  var data = await sckt.recv(true)

  if (eq(data.slice(0,2), [0x15, 0x03])){
    console.log('Server sent Alert instead of Server Finished')
    throw('Server sent Alert instead of Server Finished')
  }
  //Parse CCS and Server's Finished
  var ccs = data.slice(0,6)
  assert(eq(ccs, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]))

  var f = null; //server finished
  if (data.length == 6) {
  //didnt receive the Finished message, try again
    f = await recv_socket(sock, True);
  }
  else {
    f = data.slice(6)
  }
    
  assert (eq(f.slice(0,5), [0x16, 0x03, 0x03, 0x00, 0x28]))
  var enc_f = f.slice(5, 45) //encrypted Finished message
  //There may be some other garbage received after the Finished message
  
  //Send Server's encrypted Finished for decryption and Handshake hash to check server's verify data
  let hshash2 = await sha256(all_handshakes)

  var enc = await encryptNotaryRequest(commSymmetricKey, [].concat(enc_f, hshash2))
  var reply_data_enc = await send_and_recv('encf_hshash2', enc, 'verify_status', uid)
  var reply_data = await decryptNotaryResponse(commSymmetricKey, reply_data_enc)

  assert(eq(reply_data, [0x01]))


  var appdata = await (async function encrypt_request(){
    let headers_ba = str2ba(headers);
    let explicit_nonce = getRandom(8)
    let nonce = [].concat(client_write_IV, explicit_nonce)
    let aad = [] 
    let seq_num = 1
    aad = [].concat(aad, bi2ba(seq_num, {fixed:8}))
    aad = [].concat(aad, [0x17, 0x03, 0x03]) //type 0x17 = Application data , TLS Version 1.2
    aad = [].concat(aad, bi2ba(headers_ba.length, {fixed:2})) //length bytes of unencrypted data 
    let ciphertext = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv: ba2ab(nonce),
      additionalData: ba2ab(aad)}, cwkCryptoKey, ba2ab(headers_ba));
    let ct = ab2ba(ciphertext)
    let appdata = []
    appdata = [].concat(appdata, [0x17, 0x03, 0x03]) // Type: Application data, TLS Version 1.2
    appdata = [].concat(appdata, bi2ba(explicit_nonce.length + ct.length, {fixed:2})) //2-byte length of encrypted data
    appdata = [].concat(appdata, explicit_nonce, ct)
    return appdata
  })()

  sckt.send(appdata)
  var server_response = await sckt.recv();
  console.log('server_reply.length', server_response.length)

  var encRecords = splitResponseIntoRecords(server_response)
  var commitHash = await computeCommitHash(encRecords)

  var enc = await encryptNotaryRequest(commSymmetricKey, commitHash)
  var reply_data_enc = await send_and_recv('commithash', enc, 'swk_swi_sig_time', uid)
  var reply_data = await decryptNotaryResponse(commSymmetricKey, reply_data_enc)

  var o = 0; //offset
  var server_write_key = reply_data.slice(o, o+=16)
  var server_write_IV = reply_data.slice(o, o+=4)
  console.log('server_write_key, server_write_IV', server_write_key, server_write_IV)
  var sig_len = ba2int(reply_data.slice(o, o+=1))
  var notary_signature = reply_data.slice(o, o+=sig_len)
  var time = reply_data.slice(o, o+=4)
  console.log('resp.length', reply_data.length)
  assert(reply_data.length == o)

  //Check notary server signature
  var signed_data = await sha256([].concat(ec_pubkey_server, server_write_key, server_write_IV, commitHash, time))
  assert(await verifyNotarySig(notary_signature, chosen_notary.pubkeyPEM, signed_data) == true)

  var cleartexts = await decrypt_tls_responseV4(encRecords, server_write_key, server_write_IV)
  
  var dechunked = dechunk_http(ba2str(cleartexts))
  var ungzipped = gunzip_http(dechunked)
  console.log('ungzipped.length', ungzipped.length)

  return [certs, rsa_sig, client_random, server_random, ec_pubkey_server, server_write_key, server_write_IV, encRecords, ungzipped, notary_signature, time ]
}


//split a raw TLS response into encrypted application layer records
function splitResponseIntoRecords(s){
  var records = []
  var p = 0 //position in the stream
  var alertSeen = false

  while (p < s.length){
    if (alertSeen){
      console.log('Server unexpectedly sent more data after Alert')
      throw('Server unexpectedly sent more data after Alert')
    }
    if (! eq(s.slice(p,p+3), [0x17,0x03,0x03])){
      if (eq(s.slice(p,p+3), [0x15,0x03,0x03])){
        if (records.length == 0){
          console.log('Server sent Alert instead of response')
          throw('Server sent Alert instead of response')
        }
        alertSeen = true
        console.log('server sent Alert, presumably Close Notify')
      }
      else{
        console.log('Server sent an unknown message')
        throw('Server sent an unknown message')
      }
    }
    
    p+=3 
    let reclen = ba2int(s.slice(p, p+=2))
    let record = s.slice(p, p+=reclen)
    if (alertSeen){
      continue
    }
    else {
      records.push(record)
    }
  }
  assert(p == s.length, 'The server sent a misformatted reponse')
  return records
}

 
//commit hash inputs are sha256 hashes of "AES GCM authentication tag" for each TLS record
async function computeCommitHash(encRecords){
  var hashesOfAuthTags = []
  for (let encRec of encRecords){
    //The last 16 bytes of encrypted TLS application layer record (in AES GCM)
    //is the record's authentication tag  
    var authTag = encRec.slice(-16)
    //poseidon works with ints
    var hash = await sha256(authTag)
    hashesOfAuthTags.push(hash)
  }
  //convert all hashes into a byte array
  var commitHashInput = []
  for (let hash of hashesOfAuthTags){
    commitHashInput = commitHashInput.concat(hash)
  }
  var commitHash = await sha256(commitHashInput)
  return commitHash
}


async function decryptNotaryResponse (key, enc){
  var IV = enc.slice(0,12)
  var ciphertext = enc.slice(12)
  var data_ab = await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv: ba2ab(IV)},
    key,
    ba2ab(ciphertext));
  var data = ab2ba(data_ab)
  return data;
}


async function encryptNotaryRequest(key, cleartext){
  var IV = getRandom(12)
  var enc = await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: ba2ab(IV)},
    key,
    ba2ab(cleartext));
  var data = [].concat(IV, ab2ba(enc))
  return data;
}


//pub/privkey must be in WebCrypto format
async function getExpandedKeys(hisPubkey, myPrivkey, cr, sr){
  var Secret = await crypto.subtle.deriveBits(
    {'name': 'ECDH', 'public': hisPubkey },
    myPrivkey,
    256)
  var Secret_CryptoKey = await crypto.subtle.importKey(
      "raw",
      Secret,
      {name: 'HMAC', hash:'SHA-256'},
      true,
      ['sign']);

  //calculate Master Secret and expanded keys
  var seed = [].concat(str2ba('master secret'), cr, sr);
  var a0 = ba2ab(seed)
  var a1 = await crypto.subtle.sign('HMAC', Secret_CryptoKey, a0);
  var a2 = await crypto.subtle.sign('HMAC', Secret_CryptoKey, a1);
  var p1 = await crypto.subtle.sign('HMAC', Secret_CryptoKey, ba2ab([].concat(ab2ba(a1),seed)));
  var p2 = await crypto.subtle.sign('HMAC', Secret_CryptoKey, ba2ab([].concat(ab2ba(a2),seed)));
  var ms = [].concat(ab2ba(p1), ab2ba(p2)).slice(0,48)
  var MS_CryptoKey = await crypto.subtle.importKey("raw", ba2ab(ms), {name: 'HMAC', hash:'SHA-256'}, true, ['sign']);

  //Expand keys
  var eseed = [].concat(str2ba('key expansion'), sr, cr);
  var ea0 = ba2ab(eseed)
  var ea1 = await crypto.subtle.sign('HMAC', MS_CryptoKey, ea0);
  var ea2 = await crypto.subtle.sign('HMAC', MS_CryptoKey, ea1);
  var ep1 = await crypto.subtle.sign('HMAC', MS_CryptoKey, ba2ab([].concat(ab2ba(ea1),eseed)));
  var ep2 = await crypto.subtle.sign('HMAC', MS_CryptoKey, ba2ab([].concat(ab2ba(ea2),eseed)));

  var ek = [].concat(ab2ba(ep1), ab2ba(ep2)).slice(0,40)
  //GCM doesnt need MAC keys
  var client_write_key = ek.slice(0, 16)
  var server_write_key = ek.slice(16, 32)
  var client_write_IV = ek.slice(32, 36)
  var server_write_IV = ek.slice(36, 40)
  return [client_write_key, server_write_key, client_write_IV, server_write_IV, MS_CryptoKey]
}


  //Calculate ECDH shared secret between auditee and auditor
  //16 bytes of that secret is the symmetric key
async function getECDHSecret(hisPubkeyRaw_ba, myPrivkey){
  var comm_pk_CryptoKey = await crypto.subtle.importKey(
    "raw",
    ba2ab(hisPubkeyRaw_ba),
    {name: 'ECDH', namedCurve:'P-256'},
    true,
    []);

  var Secret = await crypto.subtle.deriveBits(
    {'name': 'ECDH', 'public': comm_pk_CryptoKey },
    myPrivkey,
    256)

  var commSymmetricKey = await crypto.subtle.importKey(
    "raw",
    ba2ab(ab2ba(Secret).slice(0,16)),
    "AES-GCM", true, ["encrypt", "decrypt"]);

  return commSymmetricKey;
}


async function decrypt_tls_responseV3(s, server_write_key, server_write_IV){

  var swkCryptoKey = await crypto.subtle.importKey("raw", 
    ba2ab(server_write_key), "AES-GCM", true, ["encrypt", "decrypt"]);

  //split up into TLS segments
  var p = 0 //position in the stream
  var seq_num = 0 // seq_num 0 was in the Server Finished message, we will start with seq_num 1
  var cleartext = []

  while (p < s.length){
    p+=3 
    let seglen = ba2int(s.slice(p, p+=2))
    p-=5 //go back
    let segment = s.slice(p, p+=5+seglen)
    if (! eq(segment.slice(0,3), [0x17,0x03,0x03])){
      if (eq(segment.slice(0,3), [0x15,0x03,0x03])){
        console.log('Server sent Alert')
        throw('Server sent Alert')
      }
      else{
        console.log('Server sent an unknown message')
        throw('Server sent an unknown message')
      }
    }

    var seg_enc = segment.slice(5)
    var explicit_nonce = seg_enc.slice(0,8)
    var nonce = [].concat(server_write_IV, explicit_nonce)

    var aad = [] //additional_data
    seq_num += 1
    aad = [].concat(aad, bi2ba(seq_num, {fixed:8}))
    aad = [].concat(aad, [0x17,0x03,0x03]) //type 0x17 = Application Data, TLS Version 1.2
    //len(unencrypted data) == len (encrypted data) - len(explicit nonce) - len (auth tag)
    aad = [].concat(aad, bi2ba(seg_enc.length - 8 - 16, {fixed:2}))

    try {
      var cleartext_segment = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: ba2ab(nonce), additionalData: ba2ab(aad)}, 
        swkCryptoKey, 
        ba2ab(seg_enc.slice(8))); //encrypted segment is prepended with 8 bytes of IV
    }
    catch (e) {
      console.log(e)
      throw('Decryption error', e.name)
    }
    cleartext = [].concat(cleartext, ab2ba(cleartext_segment))
  }
  assert(p == s.length)
  return cleartext
}



async function decrypt_tls_responseV4(encRecords, server_write_key, server_write_IV){

  var swkCryptoKey = await crypto.subtle.importKey("raw", 
    ba2ab(server_write_key), "AES-GCM", true, ["encrypt", "decrypt"]);

  var seq_num = 0 // seq_num 0 was in the Server Finished message, we will start with seq_num 1
  var cleartext = []
    
  for (let rec of encRecords){
    var explicit_nonce = rec.slice(0,8)
    var nonce = [].concat(server_write_IV, explicit_nonce)

    var aad = [] //additional_data
    seq_num += 1
    aad = [].concat(aad, bi2ba(seq_num, {fixed:8}))
    aad = [].concat(aad, [0x17,0x03,0x03]) //type 0x17 = Application Data, TLS Version 1.2
    //len(unencrypted data) == len (encrypted data) - len(explicit nonce) - len (auth tag)
    aad = [].concat(aad, bi2ba(rec.length - 8 - 16, {fixed:2}))

    try {
      var cleartext_segment = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: ba2ab(nonce), additionalData: ba2ab(aad)}, 
        swkCryptoKey, 
        ba2ab(rec.slice(8))); //encrypted segment is prepended with 8 bytes of IV
    }
    catch (e) {
      console.log(e)
      throw('Decryption error', e.name)
    }
    cleartext = [].concat(cleartext, ab2ba(cleartext_segment))
  }
  return cleartext
}


//verify signature over EC parameters from Server Key Exchange
async function verifyECParamsSig(cert_ba, ECpubkey, sig, cr, sr){
   var nb64url = b64urlencode(getModulus(cert_ba));   
   //JSON web key format for public key with exponent 65537
   jwk = {'kty':'RSA', 'use':'sig', 'e': 'AQAB', 'n': nb64url}
   
   var to_be_signed = [].concat(cr, sr, [0x03, 0x00, 0x17, 0x41], ECpubkey) //4 bytes of EC Diffie-Hellman Server Params + pubkey
   try {
    var rsa_pubkey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {name: 'RSASSA-PKCS1-v1_5', hash:'SHA-256'},
      true, ["verify"]);
    var result = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', rsa_pubkey, ba2ab(sig), ba2ab(to_be_signed))
   } catch (e) {
     console.log(e, e.name)
     throw(e)
   }
   if (!result) return false
   else return true;
}


async function verifyNotarySig(sigDER, pkPEM, signed_data_ba){
  var sig_p1363 = sigDER2p1363(sigDER)
  var notaryPubkey_ba = pubkeyPEM2raw(pkPEM)
  try {
    var notary_pk_CryptoKey = await crypto.subtle.importKey(
      "raw", ba2ab(notaryPubkey_ba), {name: 'ECDSA', namedCurve:'P-256'}, true, ["verify"]);
    var result = await crypto.subtle.verify(
      {'name':'ECDSA', 'hash':'SHA-256'}, notary_pk_CryptoKey, ba2ab(sig_p1363), ba2ab(signed_data_ba))
    if (!result) throw('notary signature verification failed')
  } catch (e) {
    console.log(e, e.name)
    throw(e)
  }
  return true;
}

if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    computeCommitHash,
    decrypt_tls_responseV4,
    start_audit,
    verifyECParamsSig,
    verifyNotarySig,
    getExpandedKeys
  }
}