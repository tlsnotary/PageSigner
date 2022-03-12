/* global keepAliveAgent */

import {ba2hex, assert, getRandom, bytesToBits, concatTA, int2ba, str2ba,
  innerHash, xor, eq, sha256, ba2int, splitIntoChunks, bitsToBytes,
  pubkeyPEM2raw, checkExpiration, AESCTRdecrypt} from '../utils.js';
import {Garbler}     from './Garbler.js';
import {Evaluator}   from './Evaluator.js';
import {Paillier2PC} from './Paillier2PC.js';
import {GCWorker}    from './GCWorker.js';
import {globals}     from './../globals.js';
import {OTSender}    from './OTSender.js';
import {OTReceiver}  from './OTReceiver.js';
import {GHASH}       from './GHASH.js';

// class TWOPC implement two-party computation techniques used in the TLSNotary
// session. Paillier 2PC, Gabrled Circuits, Oblivious Transfer.

// The description of each step of the TLS PRF computation, both inside the
// garbled circuit and outside of it:
// [REF 1] https://github.com/tlsnotary/circuits/blob/master/README

export class TWOPC {
  constructor(notary, plaintextLen, circuits, progressMonitor) {
    // notary is an object {'IP':<notary IP address>, 'pubkeyPEM':<notary pubkey in PEM format>}
    this.notary = notary;
    // number of client request encr counter blocks to produce
    const noOfAESBlocks = Math.ceil(plaintextLen/16);
    // C6Count is the number of c6 circuit executions
    this.C6Count = noOfAESBlocks;
    console.log('need to evaluate ', this.C6Count, ' c6 circuits');
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
    // outputSize, andGateCount, outputsSizes. Count starts at 1
    this.cs = Object.keys(circuits).map(k => circuits[k]);
    // we start the circuit count with 1, so we push an empty element to index 0
    this.cs.splice(0, 0, undefined);
    // The output of a circuit is actually multiple concatenated values. We need
    // to know how many bits each output value has in order to parse the output
    this.cs[1]['outputsSizes'] = [256, 256];
    this.cs[2]['outputsSizes'] = [256, 256];
    this.cs[3]['outputsSizes'] = [128, 128, 32, 32];
    this.cs[4]['outputsSizes'] = [128, 128, 128];
    this.cs[5]['outputsSizes'] = [128, 128, 128, 96];
    this.cs[6]['outputsSizes'] = [128];
    this.cs[7]['outputsSizes'] = [128];
    // encodedOutput is the encoded output of the circuit (before the decoding
    // tables are known)
    this.encodedOutput = Array(this.cs.length);
    // output is the plaintext output of the circuit as array of bytes (this is
    // encodedOutput decoded with the notary's decoding table)
    this.output = Array(this.cs.length);

    // Commitments are used to check that no malicious garbling took place.
    // Client commits to her (salted) encoded outputs and her decoding table after
    // which the Notary reveals his encoded outputs and his decoding table. After
    // decoding, both parties' plaintext outputs must match.

    // salt is 32-byte salt for each commitment
    this.salt = Array(this.cs.length);
    // encodedOutput is the encoded output of each execution of the given
    // circuit
    this.encodedOutput = Array(this.cs.length);

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
    const exeCount = [0, 1, 1, 1, 1, 1, this.C6Count, 1];
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
    this.blobSize = this.getBlobSize();
    // decrLabels are decrypted input labels corresponding to client_write_key
    // (cwk) and client_write_iv (civ) for circuit 4 (c4) and circuit 6 (c6).
    // It is a two-dimensional array [A][B], where A is an array of 160 elements
    // (each element corresponding to the bit of [cwk|civ]) and B contains as
    // many elements as there are executions of c4 + c6. Each element of B is a
    // 16-byte input label. B[0] are labels for c4.
    this.decrLabels = [];
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

  // serverEcPubkey is webserver's ephemeral pubkey from the Server Key Exchange
  async getECDHShare(serverEcPubkey){
    const serverX = serverEcPubkey.slice(1, 33);
    const serverY = serverEcPubkey.slice(33, 65);
    const paillier = new Paillier2PC(serverX, serverY);
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
    // [REF 1] Step 2
    const c1Out = (await this.runCircuit([this.clientPMSShare, c1Mask], 1))[0];
    // unmask only the outputs relevant to the client
    const pmsInnerHashState = xor(c1Out.slice(32, 64), c1Mask);
    // [REF 1] Steps 3,5,7,9
    const [c2_p2, c2_p1inner] = await this.phase2(pmsInnerHashState);
    const c2Mask = getRandom(32);
    const input2 = [c2_p1inner, c2_p2.subarray(0, 16), c2Mask];
    // [REF 1] Step 10, 12
    const c2Out = (await this.runCircuit(input2, 2))[0];
    // unmask the output
    const msInnerHashState = xor(c2Out.slice(32, 64), c2Mask);
    // [REF 1] Steps 13,15,17,20,22
    const [verify_data, c3_p2inner, c3_p1inner] = await this.phase3(msInnerHashState);
    // for readability, indexing of masks starts from 1
    const masks3 = [0, 16, 16, 4, 4].map(x => getRandom(x));
    const input3 = [c3_p1inner, c3_p2inner, ...masks3.slice(1)];
    const c3Out = (await this.runCircuit(input3, 3))[0];
    await this.phase4(c3Out, masks3);
    const masks4 = [0, 16, 16, 16].map(x => getRandom(x));
    const input4 = [this.swkShare, this.cwkShare, this.sivShare, this.civShare,
      ...masks4.slice(1)];

    const c4Out = (await this.runCircuit(input4, 4))[0];
    const [encFinished, tag] = await this.phase5(c4Out, masks4, verify_data);
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
    // [REF 1] Step 25
    const a1inner = innerHash(this.innerState_MS, a0);
    const a1 = await this.send('c5_pre1', a1inner);
    // [REF 1] Step 27
    const p1inner = innerHash(this.innerState_MS, concatTA(a1, seed));

    // for readability, mask indexing starts from 1
    const masks5 = [0, 16, 16, 16, 12].map(x => getRandom(x));
    const input5 = [p1inner, this.swkShare, this.sivShare, sf_nonce,
      ...masks5.slice(1)];
    // [REF 1] Step 28
    const c5out = (await this.runCircuit(input5, 5))[0];
    let o = 0; // offset
    // parse outputs
    const H1MaskedTwice = c5out.slice(o, o+=16);
    const gctrSFMasked = c5out.slice(o, o+=16);
    const encCounterMasked = c5out.slice(o, o+=16);
    const verify_dataMasked = c5out.slice(o, o+=12);
    // unmask outputs
    // H1 xor-masked by notary is our share of H^1, the mask is notary's share of H^1
    const H1share = xor(H1MaskedTwice, masks5[1]);
    const gctrShare = xor(gctrSFMasked, masks5[2]);
    const encCounter = xor(encCounterMasked, masks5[3]);
    const verify_data = xor(verify_dataMasked, masks5[4]);

    const sf = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);
    const encSF = xor(sf, encCounter);
    assert(eq(sf_pure, encSF));

    const ghashSF = new GHASH(1);
    ghashSF.setOTReceiver(this.otR);
    const otReq = await ghashSF.buildFinRequest(H1share);
    const step3resp = await this.send('c5_step3', concatTA(
      this.getDecommitment(5),
      encSF,
      otReq));
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

  // runs circuit 6
  async getEncryptedCounters() {
    const masks6 = [];
    let input6 = [];
    // we only send 1 TLS record with a fixed nonce 2
    const fixedNonce = int2ba(2, 2);
    for (let i = 0; i < this.C6Count; i++) {
      const counter = int2ba(2 + i, 2);
      masks6[i] = getRandom(16);
      input6 = [].concat(input6, [
        this.cwkShare,
        this.civShare,
        masks6[i],
        fixedNonce, 10, counter, 10]);
    }
    const c6out = await this.runCircuit(input6, 6);
    // c6 outputs are masked by the Client.
    const encCounters = [];
    for (let i=0; i < this.C6Count; i++){
      encCounters.push(xor(c6out[i], masks6[i]));
    }
    return encCounters;
  }

  // note that getGctrBlocks does not actually output gctr function's output but only
  // client's gctr share. The notary's gctr share is already xored into the output
  // of getTagFromPowersOfH
  async getGctrBlocks(){
    const mask7 = getRandom(16);
    let input7 = [];
    const nonce = int2ba(2, 2);
    input7 = [].concat(input7, [this.cwkShare, this.civShare, mask7, nonce]);
    const c7out = await this.runCircuit(input7, 7);
    const gctrBlocks = [];
    gctrBlocks.push(xor(c7out[0], mask7));
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

    const resp1 = await this.send('ghash_step1', concatTA(
      // send decommitment to the previous circuit
      this.getDecommitment(7),
      await this.ghash.buildStep1()));
    if (this.ghash.isStep1ResponseExpected()){
      this.ghash.processOTResponse(resp1);
    }
    if (this.ghash.isStep2Needed()){
      const resp2 = await this.send('ghash_step2', await this.ghash.buildStep2());
      this.ghash.processOTResponse(resp2);
    }
    const req3 = concatTA(...ghashInputs, await this.ghash.buildStep3(ghashInputs));
    const resp3 = await this.send('ghash_step3', req3);
    const tagShare = this.ghash.processStep3Response(resp3);
    return [[tagShare], concatTA(...ghashInputs)];
  }


  // send sends a command with data to the notary.
  // returnPromise if set to true, will return a promise
  // (instead of data resolved from the promise).
  // willEncrypt if set to true, will encrypt the request to notary.
  // willDecrypt if set to true, will decrypt the response from the notary.
  // downloadProgress if set to true, will update the progress monitor with
  // noTimeout if set to true, will not timeout if the remote takes too long
  // to respond (the caller must take care of the timeout)
  // the amount of data already downloaded.
  async send(cmd, data = new Uint8Array(0), returnPromise = false, willEncrypt = true,
    willDecrypt = true, downloadProgress = false, noTimeout = false){
    let to_be_sent;
    if (willEncrypt && data.length > 0){
      to_be_sent = await this.encryptToNotary(this.clientKey, data);
    }
    else {
      to_be_sent = data;
    }

    const fetchPromise = fetch(
      'http://'+this.notary.IP+':'+globals.defaultNotaryPort+'/'+cmd+'?'+this.uid,
      {
        method: 'POST',
        mode: 'cors',
        cache: 'no-store',
        // agent: is only used when running in nodejs
        agent: typeof(window) === 'undefined' ? keepAliveAgent : null,
        //keepalive: true, // <-- trips up Chrome
        body: to_be_sent.buffer
      });

    async function timeout(ms, promise) {
      return new Promise(function(resolve, reject) {
        setTimeout(function() {
          reject(new Error('Timed out while while transfering data.'));
        }, ms);
        promise.then(resolve, reject);
      });
    }

    const that = this;
    // eslint-disable-next-line no-async-promise-executor
    const promise = new Promise(async function(resolve, reject) {
      let payload;
      if (downloadProgress) {
        // for big downloads, we will reject if we spend 10 sec without data
        let dataLastSeen = Date.now()/1000;
        const interval = setInterval(function(){
          const now = Date.now()/1000;
          if (now-dataLastSeen > 10)  {
            reject('Timed out while while transfering data.');
          }
        }, 10000);

        const resp = await fetchPromise;
        const reader = resp.body.getReader();
        let soFarBytes = 0;
        let chunks = [];
        // lastUpdateTime is when we last sent progress update. We don't want
        // to send the update more often than every 1 sec. Set initial value so
        // that the very first update triggers immediately.
        let lastUpdateTime = (Date.now()/1000) - 1;
        let done2;
        do {
          const {done, value} = await reader.read();
          done2 = done;
          if (done) break;
          chunks.push(value);
          soFarBytes += value.length;
          const now = (Date.now()/1000);
          dataLastSeen = now;
          if (now - lastUpdateTime > 1){
            if (that.pm) that.pm.update('download', {'current': soFarBytes, 'total': that.blobSize});
            lastUpdateTime = now;
          }
        } while (!done2);
        payload = new Uint8Array(soFarBytes);
        let position = 0;
        for(let chunk of chunks) {
          payload.set(chunk, position);
          position += chunk.length;
        }
        clearInterval(interval);
      }
      else {
        let resp;
        if (noTimeout) {
          resp = await fetchPromise;
        } else {
          // for small downloads we have 20 sec total to finish
          resp = await timeout(20000, fetchPromise);
        }
        const ab = await resp.arrayBuffer();
        payload = new Uint8Array(ab);
      }
      if (payload.length == 0){
        resolve();
        return;
      }
      if (!willDecrypt) {
        resolve(payload);
        return;
      }
      const decrypted = await that.decryptFromNotary(that.notaryKey, payload);
      resolve(decrypted);
      return;
    }).catch(err => {
      throw(err);
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
      int2ba(this.C6Count, 2),
      int2ba(this.otCountRecv, 4),
      int2ba(this.otCountSend, 4),
      A,
      seedCommit), false, false, false);

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
    assert(init1Resp.length == o);

    // as soon as communication keys are established, start downloading
    // and uploading
    const that = this;
    // eslint-disable-next-line no-async-promise-executor
    const blobTransferPromise = new Promise(async function(resolve){
      const blob = await that.getBlobFromNotary();
      that.blob = that.processBlob(blob);
      await garbleAllPromise;
      let blobOut = new Uint8Array(0);
      // proceed to upload truth tables
      for (let i=1; i < that.cs.length; i++){
        blobOut = concatTA(blobOut, that.g.garbledC[i].tt);
      }
      await that.sendBlobToNotary(blobOut);
      resolve();
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

    await blobTransferPromise;
    this.preComputed = true;
  }

  // getBlobSize returns the size of all truth tables and encoding tables for
  // all garbled circuits executions
  getBlobSize(){
    let total = 0;
    for (let i=1; i < this.cs.length; i++){
      let truthTablesSize = this.cs[i].andGateCount *48;
      let decryptionTableSize = Math.ceil(this.cs[i].outputSize/8);
      if (i === 6){
        truthTablesSize = this.C6Count * truthTablesSize;
        decryptionTableSize = this.C6Count * decryptionTableSize;
      }
      total += ( truthTablesSize + decryptionTableSize);
    }
    return total;
  }

  async sendBlobToNotary(blob){
    const uploadPromise =  this.send('setBlob', blob, true, false, true, false, true);
    let uploadFinished = false;
    const that = this;

    // since fetch() does not implement upload progress, we continuously query
    // the server about upload progress

    // make sure we are not stuck waiting forever
    let dataLastSeen = Date.now()/1000;
    const lastSeenInterval = setInterval(function(){
      const now = Date.now()/1000;
      if (now-dataLastSeen > 10)  {
        throw('Timed out while while transfering data.');
      }
    }, 10000);

    const interval = setInterval(async function(){
      if (uploadFinished == true) {
        clearInterval(interval);
        return;
      }
      const progress = await that.send('getUploadProgress');
      dataLastSeen = Date.now()/1000;
      const byteCount = ba2int(progress);
      if (that.pm) that.pm.update('upload', {'current': byteCount, 'total': blob.length});
      console.log('returned progress ', byteCount, blob.length);
    }, 1000);

    await uploadPromise;
    clearInterval(lastSeenInterval);
    uploadFinished = true;
    if (this.pm) this.pm.update('upload', {'current': blob.length, 'total': blob.length});
  }

  // getBlobFromNotary downloads truth tables and decoding table from notary
  // with a progress monitor
  async getBlobFromNotary (){
    const rv =  await this.send('getBlob', new Uint8Array(0), false, false, false, true);
    // set download progress to 100%
    if (this.pm) this.pm.update('download', {'current': this.blobSize, 'total': this.blobSize});
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
    const maxWorkerCount = 2; // only needed for circuit 6
    const workerCount = [0, 1, 1, 1, 1, 1, maxWorkerCount, 1];
    for (let i=1; i < this.cs.length; i++){
      this.workers[i] = new GCWorker(workerCount[i], this.pm);
      await this.workers[i].parse(this.cs[i]);
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
    // [REF 1] Step 3
    const a1inner = innerHash(innerState, seed);
    const a1 = await this.send('c1_step3', concatTA(this.getDecommitment(1), a1inner));
    // [REF 1] Step 5
    const a2inner = innerHash(innerState, a1);
    const a2 = await this.send('c1_step4', a2inner);
    // [REF 1] Step 7
    const p2inner = innerHash(innerState, concatTA(a2, seed));
    const p2 = await this.send('c1_step5', p2inner);
    // [REF 1] Step 9
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
    // [REF 1] Step 13
    const a1inner = innerHash(this.innerState_MS, seed);
    // [REF 1] Step 20
    const a1inner_vd = innerHash(this.innerState_MS, seed_vd);
    const resp4 = await this.send('c2_step3', concatTA(
      this.getDecommitment(2),
      a1inner,
      a1inner_vd));
    const a1 = resp4.subarray(0, 32);
    const a1_vd = resp4.subarray(32, 64);
    // [REF 1] Step 15
    const a2inner = innerHash(this.innerState_MS, a1);
    // [REF 1] Step 22
    const p1inner_vd = innerHash(this.innerState_MS, concatTA(a1_vd, seed_vd));
    const resp5 = await this.send('c2_step4', concatTA(a2inner, p1inner_vd));
    const a2 = resp5.subarray(0, 32);
    const verify_data = resp5.subarray(32, 44);
    // [REF 1] Step 17
    const p1inner = innerHash(this.innerState_MS, concatTA(a1, seed));
    const p2inner = innerHash(this.innerState_MS, concatTA(a2, seed));
    return [verify_data, p2inner, p1inner];
  }

  async phase4(c3out, masks3) {
    let o = 0; // offset
    // parse all outputs
    const swkMaskedTwice = c3out.slice(o, o+=16);
    const cwkMaskedTwice = c3out.slice(o, o+=16);
    const sivMaskedTwice = c3out.slice(o, o+=4);
    const civMaskedTwice = c3out.slice(o, o+=4);
    // unmask all outputs
    this.swkShare = xor(swkMaskedTwice, masks3[1]);
    this.cwkShare = xor(cwkMaskedTwice, masks3[2]);
    this.sivShare = xor(sivMaskedTwice, masks3[3]);
    this.civShare = xor(civMaskedTwice, masks3[4]);
  }

  async phase5(c4out, masks4, verify_data) {
    let o = 0; // offset
    // parse all outputs
    const H1MaskedTwice = c4out.slice(o, o+=16);
    const gctrMaskedTwice = c4out.slice(o, o+=16);
    const encCounterMasked = c4out.slice(o, o+=16);
    // unmask all outputs
    const myGctrShare = xor(gctrMaskedTwice, masks4[2]);
    const encCounter = xor(encCounterMasked, masks4[3]);

    // H1 xor-masked by notary is our (i.e. the client's) share of H^1,
    // notary's mask is his share of H^1.
    const H1share = xor(H1MaskedTwice, masks4[1]);
    const clientFinished = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);
    const encCF = xor(clientFinished, encCounter);
    const otReq = await this.ghash.buildFinRequest(H1share);
    const step3resp = await this.send('c4_step3', concatTA(
      this.getDecommitment(4),
      encCF,
      otReq));
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
    return [encCF, tagFromPowersOfH];
  }

  // getClientFinishedResumed runs a circuit to obtain data needed to construct the
  // Client Finished messages for cases when we need TLS session resumption
  // TODO: this is wip, not yet fully implemented
  // async getClientFinishedResumed(hs_hash){
  //   const seed = concatTA(str2ba('client finished'), hs_hash);
  //   const a1inner = innerHash(this.innerState_MS, seed);
  //   const a1 = await this.send('c7_step1', a1inner);
  //   const p1inner = innerHash(this.innerState_MS, a1);
  //   // p1inner is the client's input to c7
  //   const mask1 = getRandom(16);
  //   const mask2 = getRandom(12);
  //   const nonFixedBits = bytesToBits(concatTA(
  //     mask2, mask2, this.civShare, this.cwkShare, p1inner));
  // }

  // getServerKeyShare returns client's xor share of server_write_key
  // and server_write_iv
  getKeyShares(){
    return [this.cwkShare, this.civShare,
      this.swkShare, this.sivShare];
  }

  getEphemeralKey(){
    return [this.ephemeralKey, this.eValidFrom, this.eValidUntil, this.eSigByMasterKey];
  }

  // getDecommitment returns a blob containing decommitment for circuit cNo.
  // The commitment made earlier by the Client was part of the dual execution
  // garbling protocol.
  getDecommitment(cNo){
    return concatTA(
      this.encodedOutput[cNo],
      this.g.garbledC[cNo].dt,
      this.salt[cNo]);
  }

  // runCircuit evaluates a circuit and returns the circuit's output. It exchanges
  // OT messages in order to get it's input labels and send to notary his input labels.
  // The notary is also evaluating this circuit on his end.
  async runCircuit(inputs, cNo) {
    console.log('in runCircuit', cNo);
    // inputBitsE is an array of inputs for Client-the-Evaluator in the order
    // in which the inputs appear in the c*.casm files.
    // The circuit expects the least bit of the input to be the first bit
    let inputBitsE = [];
    for (let i=0; i < inputs.length; i++){
      let bits = bytesToBits(inputs[i]);
      if (typeof(inputs[i+1]) == 'number'){
        // sometimes we need an amount of bits which is not a multiple of 8
        // in such cases the input we be followed by a number of bits to slice
        bits = bits.slice(0, inputs[i+1]);
        i += 1;
      }
      inputBitsE = [].concat(inputBitsE, bits);
    }
    // inputBitsG is an array of inputs for Client-the-Garbler
    const inputBitsG = inputBitsE.slice();
    // c is circuit
    const c = this.cs[cNo];
    // how many evaluation of the same circuit to execute
    const exeCount = [0, 1, 1, 1, 1, 1, this.C6Count, 1][cNo];

    if (cNo==6){
      // here we remove inputs this.cwkShare and this.civShare (first 160 bits)
      // because we already have active labels for those bits for each circuit 6
      // execution. We obtained them when we were running circuit 4.
      let newInputBits = [];
      const chunkSize = inputBitsE.length/this.C6Count;
      for (let i=0; i < this.C6Count; i++){
        newInputBits = [].concat(newInputBits, inputBitsE.slice(i*chunkSize+160, (i+1)*chunkSize));
      }
      inputBitsE = newInputBits;
    }
    // some circuits may need to piggy-back on the next circuit's message (to
    // save a round-trip) to send decommitment data.
    let decommit = new Uint8Array(0);
    if (cNo == 4 || cNo == 7){ decommit = this.getDecommitment(cNo-1); }

    const otReq = this.otR.createRequest(inputBitsE);
    const blob1 = await this.send(`c${cNo}_step1`, concatTA(decommit, otReq));

    let o = 0;
    // all notary's labels
    const allNotaryLabels = blob1.slice(o, o += c.notaryInputSize*16*exeCount);
    let hisOtResp = blob1.slice(o, o += inputBitsE.length*32);
    const hisOtReq = blob1.slice(o, o += 1+ c.notaryInputSize/8*exeCount);

    const notaryLabels = this.g.getNotaryLabels(cNo);
    const otResp = this.otS.processRequest(hisOtReq, notaryLabels);
    const clientLabels = this.g.getClientLabels(inputBitsG, cNo);
    let step2Payload = concatTA(otResp, clientLabels);
    let pre2Promise;
    if (cNo == 6){
      // usually we send step2Payload after the evaluation when the commitment
      // is known. But for circuit 6 which usually has a lot of executions, it
      // makes sense to tell Notary to start evaluation asap. We call it
      // "pre-step2".
      pre2Promise = this.send('c6_pre2', concatTA(step2Payload), true);
      // zero out the data so that it doesn't get sent in step2
      step2Payload = new Uint8Array(0);
    }

    let allClientLabels;
    if (cNo == 4){
      const encryptedLabels = blob1.slice(o, o += 160*2*16*(1+this.C6Count));
      assert(blob1.length == o);
      allClientLabels = await this.processC4Labels(inputBitsE, hisOtResp, encryptedLabels);
    }
    else {
      assert(blob1.length == o);
      allClientLabels = this.otR.parseResponse(inputBitsE, hisOtResp);
    }
    if (cNo == 6){
      allClientLabels = this.processC6Labels(allClientLabels);
    }

    // collect batch for evaluation
    const batch = [];
    const clBatch = splitIntoChunks(allClientLabels, c.clientInputSize*16);
    const nlBatch = splitIntoChunks(allNotaryLabels, c.notaryInputSize*16);
    const ttBatch = splitIntoChunks(this.blob[`c${cNo}_tt`], c.andGateCount * 48);
    for (let r=0; r < exeCount; r++){
      batch.push([concatTA(nlBatch[r], clBatch[r]), ttBatch[r]]);
    }

    // perform evaluation
    console.time('evaluateBatch');
    const allEncodedOutputs = await this.e.evaluateBatch(batch, cNo);
    console.timeEnd('evaluateBatch');
    this.encodedOutput[cNo] = concatTA(...allEncodedOutputs);
    this.salt[cNo] = getRandom(32);

    // Client commits first, then Notary will reveal his encoded outputs and
    // decoding table and then the Client will decommit.
    const commit = await sha256(this.getDecommitment(cNo));
    if (cNo == 6){
      // make sure Notary responded to pre-step2
      await pre2Promise;
    }
    const step2Resp = await this.send(`c${cNo}_step2`,
      concatTA(step2Payload, commit));
    o = 0;
    const hisEncodedOutput = step2Resp.slice(o, o+=c.outputSize/8*exeCount);
    const hisDecodingTable = step2Resp.slice(o, o+=c.outputSize/8*exeCount);
    // decode his output with my decoding table
    const hisOutput = xor(this.g.garbledC[cNo].dt, hisEncodedOutput);
    // decode my output with his decoding table
    const myOutput = xor(hisDecodingTable, this.encodedOutput[cNo]);
    // compare outputs
    assert(eq(hisOutput, myOutput));
    // parse my output
    const outputChunks = splitIntoChunks(myOutput, myOutput.length/exeCount);
    // process evaluation outputs
    const plaintextOutput = [];
    for (let r=0; r < exeCount; r++){
      // plaintext has a padding in MSB to make it a multiple of 8 bits. We
      // decompose into bits and drop the padding
      const bits = bytesToBits(outputChunks[r]).slice(0, c.outputSize);
      const out = this.parseOutputBits(cNo, bits);
      plaintextOutput.push(out);
    }
    return plaintextOutput;
  }

  async processC4Labels(inputBits, hisOtResp, encryptedLabels){
    assert(encryptedLabels.length % 320 == 0);
    // notary also sends input labels for client_write_key and
    // client_write_iv for c4 and c6. Each set of labels corresponding
    // to the same input bit is encrypted with a unique key.

    // replace the labels for cwk/ciw with zeroes. Then the value returned by
    // parseResponse() in places of the zeroes will be the decryption keys
    // needed to decrypt each encrypted set of labels.
    const newOtResp = concatTA(
      hisOtResp.slice(0, 128*32),
      new Uint8Array(128*32).fill(0),
      hisOtResp.slice(256*32, 288*32),
      new Uint8Array(32*32).fill(0),
      hisOtResp.slice(320*32));

    const allClientLabels = this.otR.parseResponse(inputBits, newOtResp);

    // now allClientLabels in cwk/civ position have keys needed to decrypt labels
    const decrKeys = splitIntoChunks(concatTA(
      allClientLabels.slice(128*16, 256*16),
      allClientLabels.slice(288*16, 320*16)), 16);

    const encrLabels = splitIntoChunks(encryptedLabels, encryptedLabels.length/320);
    // choiceBits for cwk/civ
    const choiceBits = [].concat(inputBits.slice(128, 256), inputBits.slice(288, 320));
    for (let i=0; i < 160; i++){
      // the decryption key only decrypts labels corresponding to our choice bit
      let toDecrypt;
      if (choiceBits[i] == 0){
        toDecrypt = encrLabels[i*2];
      } else {
        toDecrypt = encrLabels[i*2+1];
      }
      this.decrLabels[i] = splitIntoChunks(await AESCTRdecrypt(decrKeys[i], toDecrypt), 16);
    }

    // insert decrypted labels for c4 (they are at index 0),
    // the rest of the labels will be used for circuit 6
    const newLabels = concatTA(
      allClientLabels.slice(0, 128*16),
      concatTA(...this.decrLabels.slice(0, 128).map(function(arr){return arr[0];})),
      allClientLabels.slice(256*16, 288*16),
      concatTA(...this.decrLabels.slice(128, 160).map(function(arr){return arr[0];})),
      allClientLabels.slice(320*16));
    return newLabels;
  }

  processC6Labels(allClientLabels){
    // insert the labels for client_write_key and client_write_iv which we got
    // during circuit 4 execution (see func processC4Labels)
    const labelsPerExecution = splitIntoChunks(allClientLabels, allClientLabels.length/this.C6Count);
    const updatedLabels = [];
    for (let i=0; i < this.C6Count; i++) {
      updatedLabels.push(concatTA(
        ...this.decrLabels.map(function(arr){return arr[i+1];}),
        labelsPerExecution[i]));
    }
    return concatTA(...updatedLabels);
  }


  // parseOutputBits converts the output bits of the circuit number "cNo" into
  // a slice of output values in the same order as they appear in the *.casm files
  parseOutputBits(cNo, outBits){
    let o = 0; //offset
    let outBytes = new Uint8Array(0);
    for (const outSize of this.cs[cNo]['outputsSizes']){
      outBytes = concatTA(outBytes, bitsToBytes(outBits.slice(o, o+=outSize)));
    }
    assert(o == this.cs[cNo].outputSize);
    return outBytes;
  }


  // eslint-disable-next-line class-methods-use-this
  // blob contains truth tables for all consecutive circuit execution
  processBlob(blob) {
    const obj = {};
    let offset = 0;
    for (let i=1; i < this.cs.length; i++){
      let truthTablesSize = this.cs[i].andGateCount *48;
      if (i === 6){
        truthTablesSize = this.C6Count * truthTablesSize;
      }
      obj['c'+String(i)+'_tt'] = blob.subarray(offset, offset+truthTablesSize);
      offset += truthTablesSize;
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
