/* global keepAliveAgent */

import {ba2hex, assert, getRandom, bytesToBits, concatTA, int2ba, str2ba,
  innerHash, xor, eq, sha256, ba2int, splitIntoChunks, bitsToBytes,
  pubkeyPEM2raw, checkExpiration, wait} from '../utils.js';
import {Garbler}     from './Garbler.js';
import {Evaluator}   from './Evaluator.js';
import {Paillier2PC} from './Paillier2PC.js';
import {GCWorker}    from './GCWorker.js';
import {globals}     from './../globals.js';
import {OTSender}    from './OTSender.js';
import {OTReceiver}  from './OTReceiver.js';
import {GHASH}       from './GHASH.js';


export class TWOPC {
  constructor(notary, plaintextLen, circuits, progressMonitor) {
    // notary is an object {'IP':<notary IP address>, 'pubkeyPEM':<notary pubkey in PEM format>}
    this.notary = notary;
    // number of client request encr counter blocks to produce
    const noOfAESBlocks = Math.ceil(plaintextLen/16);
    // const noOfGctrBlocks = Math.ceil(noOfAESBlocks /8)
    const noOfGctrBlocks = 1;
    // C5Count is the number of c5 circuit executions
    this.C5Count = noOfAESBlocks;
    console.log('need to evaluate ', this.C5Count, ' c5 circuits');
    this.C6Count = noOfGctrBlocks;
    // shares of TLS session keys
    this.cwkShare = null;
    this.swkShare = null;
    this.sivShare = null;
    this.civShare = null;
    this.innerState_MS = null; // HMAC inner sha256 state for MS
    this.g = new Garbler(this);
    this.e = new Evaluator(this);
    this.pm = progressMonitor;
    // uid is used for communication with the notary
    this.uid = Math.random().toString(36).slice(-10);
    // cs is an array of circuits, where each circuit is an object with the fields:
    // gatesBlob, gatesCount, wiresCount, notaryInputSize, clientInputSize,
    // outputSize, andGateCount
    this.cs = Object.keys(circuits).map(k => circuits[k]);
    // start count of circuits with 1, push an empy element to index 0
    this.cs.splice(0, 0, undefined);
    // output is the output of the circuit as array of bytes
    this.output = Array(this.cs.length);
    // Commits are used to ensure malicious security of garbled circuits
    // if client's and notary's commits match, then both parties can be assured
    // that no malicious garbling took place.
    // hisSaltedCommit is a salted hash of the circuit's output from the notary
    this.hisSaltedCommit = Array(this.cs.length);
    // myCommit is a (unsalted) hash of the circuit's output
    this.myCommit = Array(this.cs.length);
    // workers are GCWorker class for each circuit
    this.workers = Array(this.cs.length);
    this.preComputed = false; // will set to true after preCompute() was run
    // clientKey is a symmetric key used to encrypt messages to the notary
    this.clientKey = null;
    // notaryKey is a symmetric key used to decrypt messages from the notary
    this.notaryKey = null;
    // ephemeralKey is an ephemeral key used by notary to sign this session
    this.ephemeralKey = null;
    // eValidFrom and eValidUntil are times from/until which the ephemeralKey is valid
    this.eValidFrom = null;
    this.eValidUntil = null;
    // eSigByMasterKey is a signature (in p1363 format) made by notary's masterkey over
    // eValidFrom|eValidUntil|ephemeralKey
    this.eSigByMasterKey = null;
    // clientPMSShare is Client's share of TLS the pre-master secret
    this.clientPMSShare = null;
    // client_random is a 32-byte random value from Client Hello
    this.client_random = null;
    // server_random is a 32-byte random value from Server Hellp
    this.server_random = null;
    // allHandshakes is a concatenation of all handshake messages up to this point.
    // This is only data visible at the handshake layer and does not include record layer headers
    this.allHandshakes = null;
    // hs_hash is a sha256 hash of allHandshakes
    this.hs_hash = null;
    // ghash is used when computing an MAC (tag) on the request
    // we need GHASH to first tell OTReceiver how many OTs will be needed,
    // then we pass the OTReceiver to GHASH
    this.ghash = new GHASH(noOfAESBlocks);
    // otCountRecv is how many OTs the receiver needs. The client plays OT
    // receiver for each bit of his inputs to the circuits + OTs for GHASH
    this.otCountRecv = this.ghash.otCount;
    // otCountSend is how many OTs the sender should expect. The client plays
    // OT sender for each bit of notary's circuits' inputs
    this.otCountSend = 0;
    // exeCount is how many executions of each circuit we need. Circuit numbering
    // starts from 1
    const exeCount = [0, 1, 1, 1, 1, this.C5Count, this.C6Count];
    for (let i=1; i < this.cs.length; i++){
      this.otCountRecv += this.cs[i].clientInputSize * exeCount[i];
      this.otCountSend += this.cs[i].notaryInputSize * exeCount[i];
    }
    console.log('otCountRecv/otCountSend', this.otCountRecv, this.otCountSend);
    // otR is the receiver of Oblivious Transfer
    this.otR = new OTReceiver(this.otCountRecv);
    // otS is the sender of Oblivious Transfer
    this.otS = new OTSender(this.otCountSend);
    this.ghash.setOTReceiver(this.otR);
  }

  // destroy de-registers listeners, terminates workers
  destroy(){
    if (this.pm) this.pm.destroy();
    for (let i=1; i < this.workers.length; i++){
      const gcworker = this.workers[i];
      for (let j=0; j < gcworker.workers.length; j++){
        gcworker.workers[j].terminate();
      }
    }
  }

  async getECDHShare(x, y){
    const paillier = new Paillier2PC(x, y);
    const step1Resp = await this.send('step1', paillier.step1());
    const step2Promise = this.send('step2', paillier.step2(step1Resp), true);
    // while Notary is responding to step2 we can do some more computations
    paillier.step2async();
    const step2Resp = await step2Promise;
    const step3Resp = await this.send('step3', paillier.step3(step2Resp));
    await this.send('step4', paillier.step4(step3Resp));
    return paillier.final();
  }

  // pass client/server random, handshake (to derive verify_data), pms share
  // returns encrypted Client Finished (CF), authentication tag for CF, verify_data for CF
  async run(cr, sr, allHandshakes, pmsShare) {
    this.clientPMSShare = pmsShare;
    this.client_random = cr;
    this.server_random = sr;
    this.allHandshakes = allHandshakes;
    this.hs_hash = await(sha256(allHandshakes));

    // if pre-fetching / pre-computation was not done, now it's too late for that
    if (! this.preComputed){
      console.log('pre-computation was not done before the session started');
      throw('pre-computation was not done before the session started');
    }

    const c1Mask = getRandom(32);
    const c1Out = await this.runCircuit([this.clientPMSShare, c1Mask], 1);
    // unmask the output
    const innerState1Masked = c1Out[0].slice(0, 32);
    const innerState1 = xor(innerState1Masked, c1Mask);

    const [c2_p2, c2_p1inner] = await this.phase2(innerState1);
    const c2Mask = getRandom(32);
    const input2 = [c2_p1inner, c2_p2.subarray(0, 16), c2Mask];
    const c2Out = await this.runCircuit(input2, 2);
    // unmask the output
    const innerState2Masked = c2Out[0].slice(0, 32);
    const innerState2 = xor(innerState2Masked, c2Mask);

    const [c3_p1inner_vd, c3_p2inner, c3_p1inner] = await this.phase3(innerState2);
    // for readability, mask indexing starts from 1
    const masks3 = [0, 16, 16, 4, 4, 16, 16, 16, 12].map(x => getRandom(x));
    const input3 = [c3_p1inner, c3_p2inner, c3_p1inner_vd, ...masks3.slice(1)];
    const c3Out = await this.runCircuit(input3, 3);
    const [encFinished, tag, verify_data] = await this.phase4(c3Out, masks3);
    return [encFinished, tag, verify_data];
  }

  // checkServerFinished takes encrypted Server Finished with nonce and authentication tag
  // and checks its correctness in 2PC
  async checkServerFinished(encSFWithNonceAndTag, allHandshakes) {
    const sf_nonce = encSFWithNonceAndTag.slice(0, 8);
    // sf_pure is encrypted SF without the nonce and without the tag
    const sf_pure = encSFWithNonceAndTag.slice(8, -16);
    const sf_tag = encSFWithNonceAndTag.slice(-16);
    const hshash = await sha256(allHandshakes);

    const seed = concatTA(str2ba('server finished'), hshash);
    const a0 = seed;
    const a1inner = innerHash(this.innerState_MS, a0);
    const a1 = await this.send('c4_pre1', a1inner);
    const p1inner = innerHash(this.innerState_MS, concatTA(a1, seed));

    // for readability, mask indexing starts from 1
    const masks4 = [0, 16, 16, 16, 12].map(x => getRandom(x));
    const input4 = [p1inner, this.swkShare, this.sivShare, sf_nonce,
      ...masks4.slice(1)];
    const outArray = await this.runCircuit(input4, 4);
    const c4_output = outArray[0];
    console.log('c4Output.length', c4_output.length);

    let o = 0; // offset
    const verify_dataMasked = c4_output.slice(o, o+=12);
    const verify_data = xor(verify_dataMasked, masks4[4]);
    const encCounterMasked = c4_output.slice(o, o+=16);
    const encCounter = xor(encCounterMasked, masks4[3]);
    const gctrSFMasked = c4_output.slice(o, o+=16);
    const gctrShare = xor(gctrSFMasked, masks4[2]);
    const H1MaskedTwice = c4_output.slice(o, o+=16);
    // H1 xor-masked by notary is our share of H^1, the mask is notary's share of H^1
    const H1share = xor(H1MaskedTwice, masks4[1]);
    const sf = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);
    const encSF = xor(sf, encCounter);
    assert(eq(sf_pure, encSF));

    const ghashSF = new GHASH(1);
    ghashSF.setOTReceiver(this.otR);
    const otReq = await ghashSF.buildFinRequest(H1share);
    const step3resp = await this.send('c4_step3', concatTA(encSF, otReq));
    assert(step3resp.length == 16 + 256*32);
    o = 0;
    const notaryTagShare = step3resp.slice(o, o+=16);
    const otResp = step3resp.slice(o, o+=(256*32));

    const aad = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0]);
    // lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
    const lenAlenC = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128]);
    const tagShare = ghashSF.processFinResponse(otResp, [aad, encSF, lenAlenC]);
    // notary's gctr share is already included in notaryTagShare
    const tagFromPowersOfH = xor(xor(notaryTagShare, tagShare), gctrShare);
    assert (eq(sf_tag, tagFromPowersOfH));
  }

  // runs circuit 5
  async getEncryptedCounters() {
    const masks5 = [];
    let input5 = [];
    // we only send 1 TLS record with a fixed nonce 2
    const fixedNonce = int2ba(2, 2);
    for (let i = 0; i < this.C5Count; i++) {
      const counter = int2ba(2 + i, 2);
      masks5[i] = getRandom(16);
      input5 = [].concat(input5, [this.cwkShare, this.civShare, masks5[i],
        fixedNonce, 10, counter, 10]);
    }
    const outArray = await this.runCircuit(input5, 5);
    const encCounters = [];
    for (let i=0; i < this.C5Count; i++){
      encCounters.push(xor(outArray[i], masks5[i]));
    }
    return encCounters;
  }

  // note that getGctrBlocks does not actually output gctr function's output but only
  // client's gctr share. The notary's gctr share is already xored into the output
  // of getTagFromPowersOfH
  async getGctrBlocks(){
    const masks6 = [];
    let input6 = [];
    for (let i = 0; i < this.C6Count; i++) {
      const nonce = int2ba(2 + i, 2);
      masks6.push(getRandom(16));
      input6 = [].concat(input6, [this.cwkShare, this.civShare, masks6[i], nonce]);
    }
    const outArray = await this.runCircuit(input6, 6);
    const c6CommitSalt = await this.send('checkC6Commit', this.myCommit[6]);
    // the commit which notary computed on their side must be equal to our commit
    const saltedCommit = await sha256(concatTA(this.myCommit[6], c6CommitSalt));
    assert (eq(saltedCommit, this.hisSaltedCommit[6]));

    const gctrBlocks = [];
    for (let i=0; i < this.C6Count; i++){
      gctrBlocks.push(xor(outArray[i], masks6[i]));
    }
    return gctrBlocks;
  }

  // getTagFromPowersOfH receives an array of encrypted request blocks and computes
  // an authentication tag over them
  async getTagFromPowersOfH(erb){
    // prepare ghash inputs
    const ghashInputs = [];
    // last block may be less than 16 bytes
    const recordLen = (erb.length-1)*16+erb[erb.length-1].length;
    const seqNum = int2ba(1, 8);
    const recordLenBytes = int2ba(recordLen, 2);
    const aad = concatTA(seqNum, new Uint8Array([23, 3, 3]), recordLenBytes);
    // right-pad with zeroes if needed
    let aadPadding = [];
    if (aad.length % 16 > 0) {
      aadPadding = Array(16-(aad.length%16)).fill(0);
    }
    ghashInputs.push(concatTA(aad, new Uint8Array(aadPadding)));
    ghashInputs.push(...erb.slice(0, -1));
    let ctPadding = [];
    if (erb[erb.length-1].length%16 > 0) {
      ctPadding = Array(16-(erb[erb.length-1].length%16)).fill(0);
    }
    ghashInputs.push(concatTA(erb[erb.length-1], new Uint8Array(ctPadding)));
    const lenA = int2ba(aad.length*8, 8);
    const lenC = int2ba(recordLen*8, 8);
    ghashInputs.push(concatTA(lenA, lenC));

    const resp1 = await this.send('ghash_step1', await this.ghash.buildStep1());
    this.ghash.processOTResponse(resp1);
    if (this.ghash.isStep2Needed()){
      const resp2 = await this.send('ghash_step2', await this.ghash.buildStep2());
      this.ghash.processOTResponse(resp2);
    }
    const req3 = concatTA(...ghashInputs, await this.ghash.buildStep3(ghashInputs));
    const resp3 = await this.send('ghash_step3', req3);
    const tagShare = this.ghash.processStep3Response(resp3);
    return [[tagShare], concatTA(...ghashInputs)];
  }


  // send data to the notary
  async send(cmd, data = new Uint8Array(0), returnPromise = false, willEncrypt = true){
    let to_be_sent;
    if (willEncrypt){
      to_be_sent = await this.encryptToNotary(this.clientKey, data);
    }
    else {
      to_be_sent = data;
    }

    function timeout(ms, promise) {
      return new Promise(function(resolve, reject) {
        setTimeout(function() {
          reject(new Error('Timed out while while transfering data.'));
        }, ms);
        promise.then(resolve, reject);
      });
    }

    const fetchPromise = fetch(
      'http://'+this.notary.IP+':'+globals.defaultNotaryPort+'/'+cmd+'?'+this.uid,
      {
        method: 'POST',
        mode: 'cors',
        cache: 'no-store',
        agent: typeof(window) === 'undefined' ? keepAliveAgent : null,
        //keepalive: true, // <-- trips up chrome
        body: to_be_sent.buffer
      });
    const that = this;

    const promise = new Promise((resolve, reject) => {
      timeout(20000, fetchPromise).then(function(resp){
        resp.arrayBuffer().then(function(ab){
          const payload = new Uint8Array(ab);
          if (payload.length !== 0){
            if (willEncrypt){
              that.decryptFromNotary(that.notaryKey, payload).then(function(decrypted){
                resolve(decrypted);
              });
            }
            else {
              resolve(payload);
            }
          }
          else {
            resolve();
          }
        });
      }).catch(err =>{
        reject(err);
      });
    });
    if (returnPromise === true){
      return promise;
    }
    else {
      return await promise;
    }
  }

  // init() should be called before run() is called
  // it does all fetching/pre-computation that can be done in 2PC offline phase
  async init() {
    if (this.preComputed) {
      return;
    }

    // asyncly garble while the rest of the setup is running
    await this.setupWorkers();
    const garbleAllPromise =  this.g.garbleAll();

    const [A, seedCommit] = await this.otR.setupStep1();
    const [pubBytes, privKey] = await this.generateECKeypair();
    const init1Blob = await this.send('init1', concatTA(
      pubBytes,
      int2ba(this.C5Count, 2),
      int2ba(this.C6Count, 2),
      int2ba(this.otCountRecv, 4),
      int2ba(this.otCountSend, 4),
      A,
      seedCommit), false, false);

    let o = 0;
    this.eValidFrom = init1Blob.slice(o, o+=4);
    this.eValidUntil = init1Blob.slice(o, o+=4);
    this.ephemeralKey = init1Blob.slice(o, o+=65);
    this.eSigByMasterKey = init1Blob.slice(o, o+=64);
    const encrypted = init1Blob.slice(o);

    console.log(this.notary.pubkeyPEM);
    const notaryKey = pubkeyPEM2raw(this.notary.pubkeyPEM);
    const notaryCryptoKey = await crypto.subtle.importKey(
      'raw', notaryKey.buffer, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
    const tbs = concatTA(this.eValidFrom, this.eValidUntil, this.ephemeralKey);
    const result = await crypto.subtle.verify(
      {'name': 'ECDSA', 'hash': 'SHA-256'},
      notaryCryptoKey,
      this.eSigByMasterKey.buffer,
      tbs.buffer);
    assert(result === true, 'Error verifying ephemeral keys from notary.');
    assert(checkExpiration(this.eValidFrom, this.eValidUntil) === true,
      'Error verifying ephemeral key validity.');

    // generate symmetric encryption keys for communication with the notary
    const [ck, nk] = await this.generateSymmetricKeys(privKey, this.ephemeralKey);
    this.clientKey = ck;
    this.notaryKey = nk;
    const init1Resp = await this.decryptFromNotary(nk, encrypted);
    o = 0;
    const hisReceiverA = init1Resp.slice(o, o+=32);
    const hisReceiverCommit = init1Resp.slice(o, o+=32);
    const hisSenderallBs = init1Resp.slice(o, o+=128*32);
    const hisSenderSeedShare = init1Resp.slice(o, o+=16);
    const totalBytes = ba2int(init1Resp.slice(o, o+=4));
    assert(init1Resp.length == o);

    // as soon as communication keys are established, start downloading
    const that = this;
    const getBlobPromise = new Promise((resolve) => {
      this.getBlobFromNotary(totalBytes)
        .then(function(hisBlob){
          that.blob = that.processBlob(hisBlob);
          resolve();
        });
    });

    const [encryptedColumns, receiverSeedShare, x, t] =
      await this.otR.setupStep2(hisSenderallBs, hisSenderSeedShare);
    const [allBs, senderSeedShare] = this.otS.setupStep1(hisReceiverA, hisReceiverCommit);
    const init2Resp = await this.send('init2', concatTA(
      encryptedColumns, receiverSeedShare, x, t, allBs, senderSeedShare
    ));

    assert(init2Resp.length == 256*this.otS.totalOT/8 + 16 + 16 + 32);
    o = 0;
    const hisReceiverEncryptedColumns = init2Resp.slice(o, o+=256*this.otS.totalOT/8);
    const hisReceiverSeedShare = init2Resp.slice(o, o+=16);
    const hisReceiverX = init2Resp.slice(o, o+=16);
    const hisReceiverT = init2Resp.slice(o, o+=32);
    await this.otS.setupStep2(hisReceiverEncryptedColumns, hisReceiverSeedShare,
      hisReceiverX, hisReceiverT);

    await garbleAllPromise;
    let blobOut = [];
    for (let i=1; i < this.cs.length; i++){
      blobOut.push(this.g.garbledC[i].tt);
      blobOut.push(this.g.garbledC[i].ol);
    }

    // start blob upload as soon as download finishes
    await getBlobPromise;
    await this.sendBlobToNotary(concatTA(...blobOut));
    this.preComputed = true;
  }

  // sendBlobToNotary uploads a blob to the notary and periodically publishes the download progress
  // to the UI. Upload is in 1MB chunks.
  async sendBlobToNotary(blob){
    const that = this;
    let sentSoFar = 0;
    let oneMB = 1024*1024;
    let chunkCount = Math.ceil(blob.length / oneMB);
    for (let i=0; i < chunkCount; i++){
      if (i % 10 == 0){
        // dont monopolize the upload bandwidth, allow preComputeOT to squeeze in some data
        await wait(200);
      }
      let chunk = blob.slice(sentSoFar, sentSoFar + oneMB);
      await that.send('setBlobChunk', chunk);
      sentSoFar += chunk.length;
      if (that.pm) that.pm.update('upload', {'current': i+1, 'total': chunkCount});
    }
    that.send('setBlobChunk', str2ba('magic: no more data'));
  }

  // getNotaryBlob downloads a blob from notary in 1 MB chunks publishes the download progress
  // to the UI.
  async getBlobFromNotary (totalBytes){
    const allChunks = [];
    console.log('totalBytes is', totalBytes);

    let soFarBytes = 0;
    while (soFarBytes < totalBytes){
      let needBytes = 1024*1024;
      if (needBytes + soFarBytes > totalBytes){
        needBytes = totalBytes - soFarBytes;
      }
      let chunk = await this.send('getBlobChunk', int2ba(needBytes, 4));
      allChunks.push(chunk);
      soFarBytes += chunk.length;
      if (this.pm) this.pm.update('download', {'current': soFarBytes, 'total': totalBytes});
    }
    const rv = concatTA(...allChunks);
    assert(rv.length === totalBytes);
    return rv;
  }

  async decryptFromNotary (key, enc){
    try{
      const IV = enc.slice(0, 12);
      const ciphertext = enc.slice(12);
      return new Uint8Array(await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: IV.buffer},
        key,
        ciphertext.buffer));
    } catch (err){
      throw('Error while decrypting data from the notary.');
    }
  }

  async encryptToNotary(key, plaintext){
    try{
      const IV = getRandom(12);
      const enc = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: IV.buffer},
        key,
        plaintext.buffer);
      return concatTA(IV, new Uint8Array(enc));
    } catch(err){
      throw('Error while encrypting data for the notary.');
    }
  }

  async setupWorkers(){
    const maxWorkerCount = 3; // only needed for c5
    const workerCount = [0, 1, 1, 1, 1, maxWorkerCount, 1];
    for (let i=1; i < this.cs.length; i++){
      this.workers[i] = new GCWorker(workerCount[i], this.pm);
      this.workers[i].parse(this.cs[i]);
    }
  }

  async phase2(innerStateUint8) {

    const innerState = new Int32Array(8);
    for (let i = 0; i < 8; i++) {
      var hex = ba2hex(innerStateUint8).slice(i * 8, (i + 1) * 8);
      innerState[i] = `0x${hex}`;
    }

    // python code for reference:
    // seed = str.encode("master secret") + self.client_random + self.server_random
    // a0 = seed
    // a1 = hmac.new(secret , a0, hashlib.sha256).digest()
    // a2 = hmac.new(secret , a1, hashlib.sha256).digest()
    // p2 = hmac.new(secret, a2+seed, hashlib.sha256).digest()
    // p1 = hmac.new(secret, a1+seed, hashlib.sha256).digest()
    // ms = (p1+p2)[0:48]

    const seed = concatTA(str2ba('master secret'), this.client_random, this.server_random);
    const a1inner = innerHash(innerState, seed);
    const a1 = await this.send('c1_step3', a1inner);
    const a2inner = innerHash(innerState, a1);
    const a2 = await this.send('c1_step4', a2inner);
    const p2inner = innerHash(innerState, concatTA(a2, seed));
    const p2 = await this.send('c1_step5', p2inner);
    const p1inner = innerHash(innerState, concatTA(a1, seed));

    return [p2, p1inner];
  }

  async phase3(innerState) {
    // hash state for MS
    this.innerState_MS = new Int32Array(8);
    for (var i = 0; i < 8; i++) {
      var hex = ba2hex(innerState).slice(i * 8, (i + 1) * 8);
      this.innerState_MS[i] = `0x${hex}`;
    }

    // python code for reference
    // seed = str.encode("key expansion") + self.server_random + self.client_random
    // a0 = seed
    // a1 = hmac.new(ms , a0, hashlib.sha256).digest()
    // a2 = hmac.new(ms , a1, hashlib.sha256).digest()
    // p1 = hmac.new(ms, a1+seed, hashlib.sha256).digest()
    // p2 = hmac.new(ms, a2+seed, hashlib.sha256).digest()
    // ek = (p1 + p2)[:40]

    const seed = concatTA(str2ba('key expansion'), this.server_random, this.client_random);
    // at the same time also compute verify_data for Client Finished
    const seed_vd = concatTA(str2ba('client finished'), this.hs_hash);

    const a1inner = innerHash(this.innerState_MS, seed);
    const a1inner_vd = innerHash(this.innerState_MS, seed_vd);
    const resp4 = await this.send('c2_step3', concatTA(a1inner, a1inner_vd));
    const a1 = resp4.subarray(0, 32);
    const a1_vd = resp4.subarray(32, 64);

    const a2inner = innerHash(this.innerState_MS, a1);
    const p1inner_vd = innerHash(this.innerState_MS, concatTA(a1_vd, seed_vd));
    const resp5 = await this.send('c2_step4', concatTA(a2inner, p1inner_vd));
    const a2 = resp5.subarray(0, 32);

    const p1inner = innerHash(this.innerState_MS, concatTA(a1, seed));
    const p2inner = innerHash(this.innerState_MS, concatTA(a2, seed));

    return [p1inner_vd, p2inner, p1inner];
  }

  async phase4(outArray, masks3) {
    const c3_output = outArray[0];
    let o = 0; // offset
    const verify_dataMasked = c3_output.slice(o, o+=12);
    const verify_data = xor(verify_dataMasked, masks3[8]);
    const encCounterMasked = c3_output.slice(o, o+=16);
    const encCounter = xor(encCounterMasked, masks3[7]);
    const gctrMaskedTwice = c3_output.slice(o, o+=16);
    const myGctrShare = xor(gctrMaskedTwice, masks3[6]);
    const H1MaskedTwice = c3_output.slice(o, o+=16);
    const civMaskedTwice = c3_output.slice(o, o+=4);
    this.civShare = xor(civMaskedTwice, masks3[4]);
    const sivMaskedTwice = c3_output.slice(o, o+=4);
    this.sivShare = xor(sivMaskedTwice, masks3[3]);
    const cwkMaskedTwice = c3_output.slice(o, o+=16);
    const swkMaskedTwice = c3_output.slice(o, o+=16);
    this.cwkShare = xor(cwkMaskedTwice, masks3[2]);
    this.swkShare = xor(swkMaskedTwice, masks3[1]);

    // H1 xor-masked by notary is our (i.e. the client's) share of H^1,
    // notary's mask is his share of H^1.
    const H1share = xor(H1MaskedTwice, masks3[5]);
    const clientFinished = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);
    const encCF = xor(clientFinished, encCounter);
    const otReq = await this.ghash.buildFinRequest(H1share);
    const step3resp = await this.send('c3_step3', concatTA(encCF, otReq));
    assert(step3resp.length === 16 + 256*32);
    o = 0;
    const notaryTagShare = step3resp.slice(o, o+=16);
    const otResp = step3resp.slice(o, o+=(256*32));

    const aad = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0]);
    // lenA (before padding) == 13*8 == 104, lenC (before padding)  == 16*8 == 128
    const lenAlenC = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128]);
    const tagShare = this.ghash.processFinResponse(otResp, [aad, encCF, lenAlenC]);
    // notary's gctr share is already included in notaryTagShare
    const tagFromPowersOfH = xor(xor(notaryTagShare, tagShare), myGctrShare);
    return [encCF, tagFromPowersOfH, verify_data];
  }

  // getClientFinishedResumed runs a circuit to obtain data needed to construct the
  // Client Finished messages for cases when we need TLS session resumption
  // TODO: this is wip, not yet fully implemented
  async getClientFinishedResumed(hs_hash){
    const seed = concatTA(str2ba('client finished'), hs_hash);
    const a1inner = innerHash(this.innerState_MS, seed);
    const a1 = await this.send('c7_step1', a1inner);
    const p1inner = innerHash(this.innerState_MS, a1);
    // p1inner is the client's input to c7
    const mask1 = getRandom(16);
    const mask2 = getRandom(12);
    const nonFixedBits = bytesToBits(concatTA(
      mask2, mask2, this.civShare, this.cwkShare, p1inner));
  }

  // getServerKeyShare returns client's xor share of server_write_key
  // and server_write_iv
  getKeyShares(){
    return [this.cwkShare, this.civShare,
      this.swkShare, this.sivShare];
  }

  getEphemeralKey(){
    return [this.ephemeralKey, this.eValidFrom, this.eValidUntil, this.eSigByMasterKey];
  }

  // eslint-disable-next-line class-methods-use-this
  // optionally send extra data
  async runCircuit(inputs, cNo, extraData = new Uint8Array(0)) {
    console.log('in runCircuit', cNo);
    // inputs is an array of inputs in the order in which the inputs appear in the c*.casm files.
    // The circuit expects the least bit of the input to be the first bit
    let inputBits = [];
    for (let i=0; i < inputs.length; i++){
      let bits = bytesToBits(inputs[i]);
      if (typeof(inputs[i+1]) == 'number'){
        // sometimes we need an amount of bits which is not a multiple of 8
        // in such cases the input we be followed by a number of bits to slice
        bits = bits.slice(0, inputs[i+1]);
        i += 1;
      }
      inputBits = [].concat(inputBits, bits);
    }
    const c = this.cs[cNo];
    // how many times to repeat evaluation (> 1 only for circuits 5&7 )
    const repeatCount = [0, 1, 1, 1, 1, this.C5Count, 1, this.C6Count][cNo];

    // for circuit 1, there was no previous commit
    const prevCommit = cNo > 1 ? this.myCommit[cNo-1] : new Uint8Array(0);
    const otReq = this.otR.createRequest(inputBits);
    const blob1 = await this.send(`c${cNo}_step1`, concatTA(prevCommit, otReq, extraData));

    let o = 0;
    if (cNo > 1){
      const prevCommitSalt = blob1.slice(o, o += 32);
      // the hash to which the notary committed must be equal to our commit
      const saltedCommit = await sha256(concatTA(this.myCommit[cNo-1], prevCommitSalt));
      assert (eq(saltedCommit, this.hisSaltedCommit[cNo-1]));
    }

    // all notary's labels
    const allNotaryLabels = blob1.slice(o, o += c.notaryInputSize*16*repeatCount);
    const hisOtResp = blob1.slice(o, o += inputBits.length*32);
    // we may need to drop some bits if their amount is not a multiple of 8
    const hisOtReq = blob1.slice(o, o += 1+ c.notaryInputSize/8*repeatCount);
    assert(blob1.length == o);

    const allClientLabels = this.otR.parseResponse(inputBits, hisOtResp);
    const senderMsg = this.g.getNotaryLabels(cNo);
    const otResp = this.otS.processRequest(hisOtReq, senderMsg);
    const clientLabels = this.g.getClientLabels(inputBits, cNo);
    const sendPromise = this.send(`c${cNo}_step2`, concatTA(otResp, clientLabels), true);

    // collect batch of evaluation
    const batch = [];
    const clBatch = splitIntoChunks(allClientLabels, c.clientInputSize*16);
    const nlBatch = splitIntoChunks(allNotaryLabels, c.notaryInputSize*16);
    const ttBatch = splitIntoChunks(this.blob[`c${cNo}_tt`], c.andGateCount * 48);
    for (let r=0; r < repeatCount; r++){
      batch.push([concatTA(nlBatch[r], clBatch[r]), ttBatch[r]]);
    }

    // perform evaluation
    console.time('evaluateBatch');
    const evalOutputLabelsBatch = await this.e.evaluateBatch(batch, cNo);
    console.timeEnd('evaluateBatch');

    // process evaluation outputs
    const output = [];
    // garbOutputLabelsBatch is output labels which the garbler sent to us
    assert(this.blob[`c${cNo}_ol`].length === c.outputSize*32*repeatCount);
    const garbOutputLabelsBatch = splitIntoChunks(this.blob[`c${cNo}_ol`], c.outputSize*32);
    for (let r=0; r < repeatCount; r++){
      const evalOL = splitIntoChunks(evalOutputLabelsBatch[r], 16);
      const garbOL = splitIntoChunks(garbOutputLabelsBatch[r], 16);
      const bits = [];
      for (let i = 0; i < c.outputSize; i++) {
        if (eq(evalOL[i], garbOL[i*2])) {
          bits.push(0);
        } else if (eq(evalOL[i], garbOL[i*2+1])) {
          bits.push(1);
        } else {
          console.log('evaluator output does not match the garbled outputs');
        }
      }
      const out = bitsToBytes(bits);
      this.output[cNo] = out;
      output.push(out);
    }
    console.log('output is', output);
    this.myCommit[cNo] = await sha256(concatTA(...output));

    const cStep2Out = await sendPromise;
    this.hisSaltedCommit[cNo] = cStep2Out.subarray(0, 32);
    const extraDataOut = cStep2Out.subarray(32);
    output.push(extraDataOut);
    return output;
  }


  // eslint-disable-next-line class-methods-use-this
  processBlob(blob) {
    // split up blob into [truth table + output labels] for each circuit
    const obj = {};
    let offset = 0;
    for (let i=1; i < this.cs.length; i++){
      let truthTableSize = this.cs[i].andGateCount *48;
      let outputLabelsSize = this.cs[i].outputSize *32;
      if (i === 5){
        truthTableSize = this.C5Count * truthTableSize;
        outputLabelsSize = this.C5Count * outputLabelsSize;
      }
      else if ( i == 6 ){
        truthTableSize = this.C6Count * truthTableSize;
        outputLabelsSize = this.C6Count * outputLabelsSize;
      }
      console.log('truthtable for ', i, ' is size: ', truthTableSize);
      obj['c'+String(i)+'_tt'] = blob.subarray(offset, offset+truthTableSize);
      offset += truthTableSize;
      console.log('ol for ', i, ' is size: ', outputLabelsSize);
      obj['c'+String(i)+'_ol'] = blob.subarray(offset, offset+outputLabelsSize);
      offset += outputLabelsSize;
    }
    assert(blob.length === offset);
    return obj;
  }

  // generateSymmetricKeys generates ECDH shared secret given a raw pubkey of another party.
  // Returns 2 symmetric keys in CryptoKey format: client_key and notary_key
  // client_key is used to encrypt TO notary
  // notary_key is used to decrypt FROM notary
  async generateSymmetricKeys(privKeyCryptoKey, pubkeyRaw){
    const hisPubKey = await crypto.subtle.importKey(
      'raw',
      pubkeyRaw.buffer,
      {name: 'ECDH', namedCurve: 'P-256'},
      true,
      []);

    const Secret = await crypto.subtle.deriveBits(
      {'name': 'ECDH', 'public': hisPubKey },
      privKeyCryptoKey,
      256);

    const clientKey = await crypto.subtle.importKey(
      'raw',
      Secret.slice(0, 16),
      'AES-GCM', true, ['encrypt']);

    const notaryKey = await crypto.subtle.importKey(
      'raw',
      Secret.slice(16, 32),
      'AES-GCM', true, ['decrypt']);

    return [clientKey, notaryKey];
  }

  async generateECKeypair(){
    const keyPair = await crypto.subtle.generateKey(
      {'name': 'ECDH', 'namedCurve': 'P-256'},
      true,
      ['deriveBits']);

    const pubBytes = new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey)).slice(1);
    return [pubBytes, keyPair.privateKey];
  }
}
