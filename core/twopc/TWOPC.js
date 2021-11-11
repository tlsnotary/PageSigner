/* eslint-disable no-bitwise */
/* eslint-disable class-methods-use-this */
/* eslint-disable max-len */

import {ba2hex, sortKeys, assert, getRandom, bytesToBits, concatTA, int2ba,
  str2ba, innerHash, xor, blockMult, eq, sha256, getXTable, ba2int, splitIntoChunks,
  bitsToBytes, pubkeyPEM2raw, checkExpiration, wait}      from '../utils.js';
import {Garbler}    from './Garbler.js';
import {Evaluator}  from './Evaluator.js';
import {OT}         from './OT.js';
import {Paillier2PC} from './Paillier2PC.js';
import {GCWorker}   from './GCWorker.js';
import {global} from './../globals.js';


// class C is initialized once and then it is a read-only struct
// accessed by both garbler and evaluator
class C{
  constructor( notaryInputSize, notaryNonFixedInputSize,
    clientInputSize, clientNonFixedInputSize, circuitOutputSize, circuit, masks, fixedInputs){

    this.notaryInputSize = notaryInputSize;
    this.clientInputSize = clientInputSize;
    this.circuitOutputSize = circuitOutputSize;
    // nonFixedInputs are inputs the value of which is not known in the offline phase
    // as opposed to fixed inputs like masks which can be chosen in an offline phase
    // the order of inputs is: non-fixed inputs first, then fixed inputs 
    this.notaryNonFixedInputSize = notaryNonFixedInputSize;
    this.clientNonFixedInputSize = clientNonFixedInputSize;
    this.notaryFixedInputSize = this.notaryInputSize - this.notaryNonFixedInputSize;
    this.clientFixedInputSize = this.clientInputSize - this.clientNonFixedInputSize;
    // circuit is a serialized circuit with metadata
    this.circuit = circuit;
    // what each mask does for each circuit is explained in c*.casm files
    this.masks = masks;
    // fixedInputs is an array A of arrays B, where
    // arrayA's length is equal to the amount of circuits
    // arrayB consists of 0 and 1, item at idx==0 is the first input to the circuit
    this.fixedInputs = fixedInputs;
  }
}



// eslint-disable-next-line no-unused-vars
export class TWOPC {
  // notary is an object {'IP':<notary IP address>, 'pubkeyPEM':<notary pubkey in PEM format>}
  notary;
  // clientKey is a symmetric key used to encrypt messages to the notary
  clientKey;
  // notaryKey is a symmetric key used to decrypt messages from the notary
  notaryKey;
  constructor(notary, plaintextLen, circuits, progressMonitor) {
    this.notary = notary;
    // number of client request encr counter blocks to produce
    const noOfAESBlocks = Math.ceil(plaintextLen/16);
    // const noOfGctrBlocks = Math.ceil(noOfAESBlocks /8)
    const noOfGctrBlocks = 1;
    this.C5Count = noOfAESBlocks;
    this.C6Count = noOfGctrBlocks;
    this.cwkMaskedByNotary = null;
    this.swkMaskedByNotary = null;
    this.sivMaskedByNotary = null;
    this.civMaskedByNotary = null;
    this.innerState_MS = null; // HMAC inner sha256 state for MS
    this.g = new Garbler(this);
    this.e = new Evaluator(this);
    this.ot = new OT();
    this.pm = progressMonitor;
    // uid is used for communication with the notary
    this.uid = Math.random().toString(36).slice(-10);

    const [masks, fixedInputs] = this.initInputs();
    this.cs = [];
    this.cs[1] = new C(512, 256,  512, 256, 512, circuits[1], masks[1], fixedInputs[1]);
    this.cs[2] = new C(512, 256,  640, 384, 512, circuits[2], masks[2], fixedInputs[2]);
    this.cs[3] = new C(832, 256, 1568, 768, 800, circuits[3], masks[3], fixedInputs[3]);
    this.cs[4] = new C(672, 416,  960, 480, 480, circuits[4], masks[4], fixedInputs[4]);
    this.cs[5] = new C(160,   0,  308, 160, 128, circuits[5], masks[5], fixedInputs[5]);
    this.cs[6] = new C(288,   0,  304, 160, 128, circuits[6], masks[6], fixedInputs[6]);

    // fixedLabels contains a label for each fixed input bit
    this.fixedLabels = Array(this.cs.length);
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

    console.log('need to evaluate ', this.C5Count, ' c5 circuits');
 
    this.preComputed = false; // will set to true after preCompute() was run
    // powersOfH is an array of client's shares of powers of H, starting with H^1 at index 1
    this.powersOfH = []; 

    // maxPowerNeeded is the maximum power of H that we'll need in order to compute the GHASH
    // function. This doesn't mean that the parties will compute shares of this power. It just 
    // shows the upper bound of H. 
    this.maxPowerNeeded = Math.ceil(plaintextLen /16) + 2;
    // maxOddPowerNeeded is the maximum odd power for which the parties must compute their shares
    this.maxOddPowerNeeded = this.initMaxOddPower(this.maxPowerNeeded);
    // ghashOTNeeded is how many bits the receiver of Oblivious Transfer will have
    // in order to compute the GHASH function
    this.ghashOTNeeded = this.initGhashOTNeeded(this.maxPowerNeeded, this.maxOddPowerNeeded);

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
  }

  // destroy de-registers listeners, terminates workers
  destroy(){
    this.pm.destroy();
    for (let i=1; i < this.workers.length; i++){
      const gcworker = this.workers[i];
      for (let j=0; j < gcworker.workers.length; j++){
        gcworker.workers[j].terminate();
      }
    }
    for (const w of this.ot.worker.workers){
      w.terminate();
    }
  }

  // compute how many bits need OT for ghash-OT method
  initGhashOTNeeded(maxPowerNeeded, maxOddPowerNeeded){
    const strategies = {
      5: [4,1],
      7: [4,3],
      9: [8,1],
      11: [8,3],
      13: [12,1],
      15: [12,3],
      17: [16,1],
      19: [16,3],
      21: [17,4],
      23: [17,6],
      25: [17,8],
      27: [19,8],
      29: [17,12],
      31: [19,12],
      33: [17,16],
      35: [19,16]};

    // add powers 1,2,3 which the client will already have
    const allPowers = []; // all shares of powers which the client has
    allPowers[1] = true;
    allPowers[2] = true;
    allPowers[3] = true;

    // will contain unique powers for which we compute shares directly
    // each power requires the client to prepare 256 OT bits
    const uniquePowers = [];
    for (const k of sortKeys(strategies)){
      if (k <= maxOddPowerNeeded){
        allPowers[k] = true;
        const v = strategies[k];
        if (! uniquePowers.includes(v[0])){
          uniquePowers.push(v[0]);
        }
        if (! uniquePowers.includes(v[1])){
          uniquePowers.push(v[1]);
        }
      }
    }

    // and perform "free squaring" on all powers    
    for (let i=1; i < allPowers.length; i++){
      if (allPowers[i] == undefined){
        continue;
      }
      let power = i;
      while (power <= maxPowerNeeded){
        power = power * 2;
        if (allPowers[power] != undefined){
          continue;
        }
        allPowers[power] = true;
      }
    }

    // how many auxillary powers will be needed for the block aggregation method
    // each aux power requires 128 OT bits from client
    const auxPowers = [];
    for (let i=1; i <= maxPowerNeeded; i++){
      if (allPowers[i] != undefined){
        // for this power the client has a share of H, no need for the block aggregation method
        continue;
      }
      // a is the smaller power
      const [a,b] = this.findSum(allPowers, i);
      if (! auxPowers.includes(a)){
        auxPowers.push(a);
      }
    }

    return uniquePowers.length * 256 + auxPowers.length*128;
  }

  initMaxOddPower(maxPowerNeeded){
    assert(maxPowerNeeded <= 1026);

    // maxHTable = {<key>:<value>}. <value> shows (when using the block aggregation method)
    // how many powers of H can be obtained if we:
    // A) have all the sequential powers starting with 1 up to <key> AND
    // B) have performed OT with the notary on all those sequential powers.
    // e.g. {5:29} means that if we have powers 1,2,3,4,5 then using the block aggregation method we can obtain
    // up to and including H^29.
    // max TLS record size of 16KB requires 1026 powers of H
    const maxHTable = {0: 0, 3: 19, 5: 29, 7: 71, 9: 89, 11: 107, 13: 125, 15: 271, 17: 305, 19: 339, 21: 373,
      23: 407, 25: 441, 27: 475, 29: 509, 31: 1023, 33: 1025, 35: 1027};

    let maxOddPowerNeeded = null;
    for (const key of sortKeys(maxHTable)){
      const maxH = maxHTable[key];
      if (maxH >= maxPowerNeeded){
        maxOddPowerNeeded = key;
        break;
      }
    }
    return maxOddPowerNeeded;
  }
  
  // set all masks and fixed inputs for each circuit
  initInputs(){
    const masks = [];
    const fixedInputs = [];

    masks[1] = [];
    masks[1][1] = getRandom(32);
    fixedInputs[1] = bytesToBits(masks[1][1]);
    
    masks[2] = [];
    masks[2][1] = getRandom(32);
    fixedInputs[2] = bytesToBits(masks[2][1]);
    
    masks[3] = [];
    const maskSizes3 = [0,16,16,4,4,16,16,16,12];
    for (let i=1; i < maskSizes3.length; i++){
      masks[3][i] = getRandom(maskSizes3[i]);
    }
    fixedInputs[3] = bytesToBits(concatTA(...masks[3].slice(1).reverse()));

    masks[4] = [];
    const maskSizes4 = [0,16,16,16,12];
    for (let i=1; i < maskSizes4.length; i++){
      masks[4][i] = getRandom(maskSizes4[i]);
    }
    fixedInputs[4] = bytesToBits(concatTA(...masks[4].slice(1).reverse()));

    masks[5] = [];
    for (let i = 0; i < this.C5Count; i++) {
      masks[5].push(getRandom(16));
    }
    const totalBits = [];
    // we only send 1 TLS record with a fixed nonce 2
    const nonce = 2; 
    for (let i = 0; i < this.C5Count; i++) {
      const counter = 2 + i;
      const counterBits = bytesToBits(int2ba(counter, 2)).slice(0, 10);
      const nonceBits = bytesToBits(int2ba(nonce, 2)).slice(0, 10);
      const maskBits = bytesToBits(masks[5][i]);
      totalBits.push([].concat(maskBits, nonceBits, counterBits));
    }
    fixedInputs[5] = [].concat(...totalBits);

    masks[6] = [];
    for (let i = 0; i < this.C6Count; i++) {
      masks[6].push(getRandom(16));
    }
    // for gctr blocks
    let totalParsed6 = [];
    for (let i = 0; i < this.C6Count; i++) {
      // nonce starts with 2
      const nonce = 2 + i;
      const parsedNonce = bytesToBits(int2ba(nonce, 2)).slice(0, 16);
      const mask = bytesToBits(masks[6][i]);
      totalParsed6.push([].concat(mask, parsedNonce));
    }
    fixedInputs[6] = [].concat(...totalParsed6);

    return [masks, fixedInputs];
  }

  async getECDHShare(x, y){
    const paillier = new Paillier2PC(this, x, y);
    return await paillier.run();
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
  
    const nonFixedBits = bytesToBits(this.clientPMSShare);
    const c1Output = await this.runCircuit(nonFixedBits, 1);

    const c2_output = await this.phase2(c1Output);
    const c3_output = await this.phase3(c2_output);
    const [encFinished, tag, verify_data] = await this.phase4(c3_output);
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

    const nonFixedBits = bytesToBits(concatTA(
      new Uint8Array(sf_nonce),
      new Uint8Array(this.sivMaskedByNotary),
      new Uint8Array(this.swkMaskedByNotary),
      p1inner));

    const outArray = await this.runCircuit(nonFixedBits, 4);
    const c4_output = outArray[0];
    console.log('c4Output.length', c4_output.length);

    let o = 0; // offset 
    const verify_dataMasked = c4_output.slice(o, o+=12);
    const verify_data = xor(verify_dataMasked, this.cs[4].masks[4]);
    const sf = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);

    const encCounterMasked = c4_output.slice(o, o+=16);
    const encCounter = xor(encCounterMasked, this.cs[4].masks[3]);

    const gctrSFMasked = c4_output.slice(o, o+=16);
    const gctrShare = xor(gctrSFMasked, this.cs[4].masks[2]);

    const H1MaskedTwice = c4_output.slice(o, o+=16);
    const H1 = xor(H1MaskedTwice, this.cs[4].masks[1]);
    const H2 = blockMult(H1, H1);
    const H1H2 = blockMult(H1, H2);

    // OT starts with the highest bit
    const h1Bits = bytesToBits(H1).reverse();
    const [idxArray1, otKeys1] = this.ot.getIndexesFromPool(h1Bits);
    const h2Bits = bytesToBits(H2).reverse();
    const [idxArray2, otKeys2] = this.ot.getIndexesFromPool(h2Bits);

    const encSF = xor(sf, encCounter);
    assert(eq(sf_pure, encSF));

    const step3resp = await this.send('c4_step3', concatTA(encSF, idxArray1, idxArray2));
    assert(step3resp.length === 16 + 128*32 + 128*32);
    o = 0;
    const Snotary = step3resp.slice(o, o+=16);
    const encEntries1 = step3resp.slice(o, o+=(128*32));
    const encEntries2 = step3resp.slice(o, o+=(128*32));

    let H3share = H1H2;
    for (let i = 0; i < h1Bits.length; i += 1) {
      const bit = h1Bits[i];
      const ct = encEntries2.slice(i * 32, (i+1) * 32);
      const maskedEntry = this.ot.decryptWithKey(ct, bit, otKeys1[i]);
      H3share = xor(H3share, maskedEntry);
    }
    for (let i = 0; i < h2Bits.length; i += 1) {
      const bit = h2Bits[i];
      const ct = encEntries1.slice(i * 32, (i+1) * 32);
      const maskedEntry = this.ot.decryptWithKey(ct, bit, otKeys2[i]);
      H3share = xor(H3share, maskedEntry);
    }

    const aad = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0]);
    // lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
    const lenAlenC = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128]);

    const s1share = blockMult(aad, H3share);
    const s2share = blockMult(encSF, H2);
    const s3share = blockMult(lenAlenC, H1);
    const Sclient = xor(xor(xor(s1share, s2share), s3share), gctrShare);

    const tagFromPowersOfH = xor(Snotary, Sclient);
    assert (eq(sf_tag, tagFromPowersOfH));
  }

  async getEncryptedCounters() {
    const nonFixedBits = bytesToBits(concatTA(this.civMaskedByNotary, this.cwkMaskedByNotary));
    const outArray = await this.runCircuit(nonFixedBits, 5);
    const results = [];
    for (let i=0; i < this.C5Count; i++){
      const encCounter = xor(outArray[i], this.cs[5].masks[i]);
      results.push(encCounter);   
    }
    return results;
  }

  // note that getGctrBlocks does not actually output gctr function's output but only
  // client's gctr share. The notary's gctr share is already xored into the output
  // of getTagFromPowersOfH
  async getGctrBlocks(){
    const nonFixedBits = bytesToBits(concatTA(this.civMaskedByNotary, this.cwkMaskedByNotary));
    const outArray = await this.runCircuit(nonFixedBits, 6);

    const c6CommitSalt = await this.send('checkC6Commit', this.myCommit[6]);
    // the commit which notary computed on their side must be equal to our commit
    const saltedCommit = await sha256(concatTA(this.myCommit[6], c6CommitSalt));
    assert (eq(saltedCommit, this.hisSaltedCommit[6]));
  
    const results = [];
    for (let i=0; i < this.C6Count; i++){
      const gctrBlock = xor(outArray[i], this.cs[6].masks[i]);
      results.push(gctrBlock);   
    }
    return results;
  }

  async getTagFromPowersOfH(encRequestBlocks){
    // prepare ghash inputs
    const ghashInputs = [];
    // last block may not be 16 bytes
    const recordLen = (encRequestBlocks.length-1)*16+encRequestBlocks[encRequestBlocks.length-1].length;
    const seqNum = int2ba(1, 8);
    const recordLenBytes = int2ba(recordLen, 2);
    const aad = concatTA(seqNum, new Uint8Array([23,3,3]), recordLenBytes);
    // right-pad with zeroes if needed
    let aadPadding = [];
    if (aad.length % 16 > 0) {
      aadPadding = Array(16-(aad.length%16)).fill(0);
    }
    ghashInputs.push(concatTA(aad, new Uint8Array(aadPadding)));
    ghashInputs.push(...encRequestBlocks.slice(0,-1));
    let ctPadding = []; 
    if (encRequestBlocks[encRequestBlocks.length-1].length%16 > 0) {
      ctPadding = Array(16-(encRequestBlocks[encRequestBlocks.length-1].length%16)).fill(0);
    }
    ghashInputs.push(concatTA(encRequestBlocks[encRequestBlocks.length-1], new Uint8Array(ctPadding)));
    const lenA = int2ba(aad.length*8, 8);
    const lenC = int2ba(recordLen*8, 8);
    ghashInputs.push(concatTA(lenA, lenC));

    // fill this.powersOfH with needed H shares
    await this.getOddPowers(this.maxPowerNeeded);
    const directSum = this.useDirectHShares(ghashInputs);
    const indirectSum = await this.useIndirectHShares(ghashInputs);
    return [[xor(directSum, indirectSum)], concatTA(...ghashInputs)];

  }

  // multiply direct H shares with corresponding ciphertext blocks
  useDirectHShares(ghashInputs){
    let res = int2ba(0, 16);
    // this.powersOfH is a sparse array, its .length is the max index
    for (let i=1; i < this.powersOfH.length; i++){
      if (i > ghashInputs.length){
        // we will have more powers than the input blocks
        break;
      }
      if (this.powersOfH[i] == undefined){
        continue;
      }
      const h = this.powersOfH[i];
      const x = ghashInputs[ghashInputs.length-i];
      res = xor(res, blockMult(h,x));
    }
    return res;
  }

  // for those shares of powers which are not in powersOfH, we do not compute the shares of
  // powers, but instead we compute the share of X*H
  // e.g. if we need H^21*X and we have shares of H^19 and H^2, we compute it as follows:
  // (H19_a + H19_b)(H2_a + H2_b)X == H19_aH2_aX + H19_aXH2_b + H19_bXH2_a + H19_bH2_bX
  // only the 2 middle cross-terms need to be computed using OT
  // A will send OT for H19_aX to B
  // B will send OT for H19_bX to A
  // all other powers where one of the factors is H^2 like eg H^25 == H^23*H^2
  // can be collapsed into the terms above e.g. H23_aX2 can be collapsed into H19_aX

  async useIndirectHShares(ghashInputs){
    let res = int2ba(0, 16); // this is the xor of all my X*H shares 
    let sumForPowers = {};
    for (let i=4; i < this.powersOfH.length; i++){
      if (i > ghashInputs.length){
        // we will have more powers than the input blocks
        break;
      }
      if (this.powersOfH[i] != undefined){
        continue;
      }
      // found a hole in our sparse array, we need X*H for this missing power
      // a is the smaller power
      const [a,b] = this.findSum(this.powersOfH, i);
      const x = ghashInputs[ghashInputs.length-i];
      const h_small = this.powersOfH[a];
      const h_big = this.powersOfH[b];
      res = xor(res, blockMult(blockMult(h_small, h_big), x));
      const hx = blockMult(h_big, x);
      if (sumForPowers.hasOwnProperty(a)){
        sumForPowers[a] = xor(sumForPowers[a], hx);
      }
      else {
        sumForPowers[a] = hx;
      }
    }
    
    // send OT for all sums in sumForPowers in ascending order
    const sortedKeys = sortKeys(sumForPowers);
    let allBits = [];
    for (const key of sortedKeys){
      const bytes = sumForPowers[key];
      // OT starts with the highest bit
      const bits = bytesToBits(new Uint8Array(bytes)).reverse();
      allBits = [].concat(allBits, bits);
    }
    const [idxArray, otKeys] = this.ot.getIndexesFromPool(allBits);
    
    const payload = concatTA(...ghashInputs, idxArray);
    const step5resp = await this.send('ghash_step5', payload);
    let o = 0;
    const encEntries = step5resp.slice(o, o+idxArray.length/2 * 32);
    o += idxArray.length/2 * 32;
    const hisIndexes = step5resp.slice(o, o+idxArray.length);
    o += idxArray.length;
    assert(step5resp.length === o);

    for (let i = 0; i < allBits.length; i += 1) {
      const bit = allBits[i];
      const ct = encEntries.slice(i * 32, (i+1) * 32);
      const maskedEntry = this.ot.decryptWithKey(ct, bit, otKeys[i]);
      res = xor(res, maskedEntry);
    }
 
    // get his indexes and send his encrypted masked entries
    let maskSum = int2ba(0, 16);
    let totalOffset = 0;
    const myEncEntries = [];
    for (let i=0; i < sortedKeys.length; i++){
      const xTable = getXTable(this.powersOfH[sortedKeys[i]]);
      for (let i=0; i < 128; i++){
        const idx = ba2int(hisIndexes.slice(totalOffset, totalOffset+2));
        totalOffset += 2;
        const mask = getRandom(16);
        maskSum = xor(maskSum, mask);
        const m0 = mask;
        const m1 = xor(xTable[i], mask);
        myEncEntries.push(this.ot.encryptWithKeyAtIndex(m0, m1, idx));
      }

    }
    res = xor(res, maskSum);
    const hisTagShare = await this.send('ghash_step6',  concatTA(...myEncEntries));
    return xor(res, hisTagShare);
  }


  // draw from the OT pool and send to notary OT step1
  getOTIndexArray(powersForOT, powersOfH){
    // prepare OT data for each bit of each power
    const idxArrays = [];
    for (const power of sortKeys(powersForOT)){
      const bits = bytesToBits(powersOfH[power]).reverse();
      powersForOT[power]['bits'] =  bits;
      const [idxArray, otKeys] = this.ot.getIndexesFromPool(bits);
      powersForOT[power]['otKeys'] = otKeys; 
      idxArrays.push(idxArray);
    }
    return idxArrays;
  }


  // decrypt OT from notary and compute shares of powers listed in strategies
  // modifies PowersOfH in-place
  getPowerShares(strategies, powersForOT, encEntriesBlob, powersOfH){
    const stratKeys = sortKeys(strategies);
    assert(encEntriesBlob.length === stratKeys.length*256*32);

    for (let j=0; j < stratKeys.length; j++){
      const oddPower = stratKeys[j];
      let xorSum = int2ba(0, 16); // start with 0 sum
      for (let round=0; round < 2; round++){
        // first factor is always notary's, second factor is always client's
        // on first round factor at strategies[key][0] is notary's
        // on second round factor at strategies[key][1] is notary's
        let f2 = round === 0 ? strategies[oddPower][1] : strategies[oddPower][0];
        const encEntries = encEntriesBlob.slice((j*256+round*128)*32, (j*256+(round+1)*128)*32);
        for (let i = 0; i < 128; i += 1) {
          const bit = powersForOT[f2].bits[i];
          const ct = encEntries.slice(i * 32, (i+1) * 32);
          const maskedEntry = this.ot.decryptWithKey(ct, bit, powersForOT[f2].otKeys[i]);
          xorSum = xor(xorSum, maskedEntry);
        }
      }
      const Cx = powersOfH[strategies[oddPower][0]];
      const Cy = powersOfH[strategies[oddPower][1]];
      const CxCy = blockMult(Cx,Cy);
      powersOfH[oddPower] = xor(xorSum, CxCy);
    }
  }


  // Use oblivious transfer with the notary to compute the necessary amount of odd powers
  // we will later call powersPlusOne with these odd powers to compute X*H.
  // Note: when OT-extension is implemented, we're not gonna need all these optimizations. 
  // We will be able to compute all powers directly with OT-extenion. But for now, since
  // we use base-OT which is expensive, we resort to optimizations.

  async getOddPowers(maxPowerNeeded){
    console.log('maxPowerNeeded is', maxPowerNeeded);
    assert(maxPowerNeeded <= 1026);

    if (this.maxOddPowerNeeded === 3){
      return; // already have power 3
    }

    // perform free squaring of shares H^2 and H^3 which we have from client finished
    this.freeSquare(this.powersOfH, maxPowerNeeded);
    
    // strategies shows what existing powers we will be multiplying to obtain other odd powers
    // max sequential odd power that we can obtain on first round is 19
    // Note that "sequential" is a keyword here. We can't obtain 21 but we indeed can obtain
    // 25==24+1, 33==32+1 etc. However with 21 missing, we will not be able to obtain more powers
    // with the X*H method, even if we have 25,33,etc.  
    const strategies = {
      5: [4,1],
      7: [4,3],
      9: [8,1],
      11: [8,3],
      13: [12,1],
      15: [12,3],
      17: [16,1],
      19: [16,3]};
    const powersForOT1 = {1: {},3: {},4: {},8: {},12: {},16: {}};

    // TODO send only those powers which we actually need 
    const idxArrays1 = this.getOTIndexArray(powersForOT1, this.powersOfH);

    const encEntries1 = await this.send('ghash_step1', concatTA(...idxArrays1, int2ba(maxPowerNeeded, 2)));

    this.getPowerShares(strategies, powersForOT1, encEntries1, this.powersOfH);
    this.freeSquare(this.powersOfH, maxPowerNeeded);

    // we need to perform OT on all powers [1, maxOddPowerNeeded] which we havent performed OT
    // for yet
    const powersLeft = [2,5,6,7,9,10,11,13,14,15,17,18,19];
    const powersForOT2 = {};
    for (const power of powersLeft){
      if (power <= this.maxOddPowerNeeded){
        powersForOT2[power] = {};
      }
    }
    const idxArrays2 = this.getOTIndexArray(powersForOT2, this.powersOfH);
    await this.send('ghash_step2', concatTA(...idxArrays2));

    if (this.maxOddPowerNeeded <= 19){
      return;
    }
    // else we need more odd powers. The max that we'll ever need is 35
    // strategies2 should be canonical for both client and notary
    // Eventually we will send OT for all powers from 1 to 35
    const strategies2 = {
      21: [17,4],
      23: [17,6],
      25: [17,8],
      27: [19,8],
      29: [17,12],
      31: [19,12],
      33: [17,16],
      35: [19,16]};

    const powersForOT3 = {17: {},19: {}};
    const idxArrays3 = this.getOTIndexArray(powersForOT3, this.powersOfH);
    const step3resp = await this.send('ghash_step3', concatTA(...idxArrays3));
    this.getPowerShares(strategies2, powersForOT3, step3resp, this.powersOfH);
    this.freeSquare(this.powersOfH, maxPowerNeeded);
    // we need to perform OT on all powers [1, maxOddPowerNeeded] which we havent performed OT
    // for yet
    const powersLeft2 = [20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35];
    const powersForOT4 = {};
    for (let i=0; i < powersLeft2.length; i++){
      if (powersLeft2[i] <= this.maxOddPowerNeeded){
        powersForOT4[i] = {};
      }
    }
    const idxArrays4 = this.getOTIndexArray(powersForOT4, this.powersOfH);
    await this.send('ghash_step4', concatTA(...idxArrays4));
  }

  // those powers which were not set are undefined
  findSum(powers, sumNeeded){
    for (let i=1; i < powers.length; i++){
      if (powers[i] == undefined){
        continue;
      }
      for (let j=1; j < powers.length; j++){
        if (powers[j] == undefined){
          continue;
        }
        if (i+j === sumNeeded){
          return [i,j];
        }
      }
    }
    // this should never happen because we always call 
    // findSum() knowing that the sum can be found
    throw('sum not found');
  }

  // Perform squaring of each share of odd power up to maxPower.
  // "powers" is an array where idx is the power (or undefined if not set) and item at that idx
  // if client's share of H^power 
  // modifies "powers" in-place
  // e.g if "powers" contains 1,2,3 and maxPower==19, then upon return "powers"
  // will contain 1,2,3,4,6,8,12,16   
  freeSquare(powers, maxPower){
    for (let i=0; i < powers.length; i++){
      if (powers[i] == undefined || i % 2 === 0){
        continue;
      }
      if (i > maxPower){
        return;
      }
      let power = i;
      while (power <= maxPower){
        power = power * 2;
        if (powers.includes(power)){
          continue;
        }
        powers[power] = blockMult(powers[power/2], powers[power/2]);
      }
    }
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
      'http://'+this.notary.IP+':'+global.defaultNotaryPort+'/'+cmd+'?'+this.uid, 
      {
        method: 'POST',
        mode: 'cors',
        cache: 'no-store',
        // keepalive: true, <-- trips up chrome
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

  async preComputeOT(){ 
    
    const allFixedInputs = [];
    let allNonFixedInputsCount = 0;
    let allFixedInputsCount = 0;
    for (let i=1; i < this.cs.length; i++){
      allFixedInputs.push(this.cs[i].fixedInputs);
      allNonFixedInputsCount += this.cs[i].clientNonFixedInputSize;
    }
    allNonFixedInputsCount += (256 + 256); // for powers of H OT for ClFin and SerFin
    allFixedInputsCount = [].concat(...allFixedInputs).length;

    console.log('allFixedInputs.length', allFixedInputsCount);
    console.log('precomputePool size', allNonFixedInputsCount + this.ghashOTNeeded);
   
    this.pm.update('last_stage', {'current': 1, 'total': 10});
    const receiverBs = await this.ot.saveDecryptionKeys([].concat(...allFixedInputs));
    await this.ot.precomputePool(allNonFixedInputsCount + this.ghashOTNeeded);

    const OTpayload = concatTA(...receiverBs, ...this.ot.getRandomizedPool());
    console.log('sending payload of size', OTpayload.length);
    const resp_ot_AllB = await this.send('ot_AllB', OTpayload);
    console.log('returned from ot_AllB');
    const fixedOTBlob = resp_ot_AllB.slice(0, allFixedInputsCount*32);
    const OTFromNotaryEval = resp_ot_AllB.slice(allFixedInputsCount*32);
    console.time('getAllB');
    const encLabelsBlob = await this.g.getAllB(OTFromNotaryEval);
    console.timeEnd('getAllB');
    this.send('ot_encLabelsForEval', encLabelsBlob);

    // get evaluator's fixed labels and keep them
    let idx = 0;
    for (let i=1; i < this.cs.length; i++){
      this.fixedLabels[i] = [];
      for (let j=0; j < this.cs[i].fixedInputs.length; j++){
        const ct = fixedOTBlob.slice(idx*32, (idx+1)*32);
        const bit = this.cs[i].fixedInputs[j];
        const inputLabel = this.ot.decryptWithKeyFromIndex(ct, bit, idx);
        idx += 1;
        this.fixedLabels[i].push(inputLabel);
      }
    }
    assert(fixedOTBlob.length === idx*32);
    this.pm.update('last_stage', {'current': 2, 'total': 10});
  }

  // preCompute() should be called before run() is called
  // it does all fetching/pre-computation that can be done in 2PC offline phase
  async preCompute() {
    if (this.preComputed) {
      return;
    }

    const [pubBytes, privKey] = await this.generateECKeypair();

    const preInitBlob = await this.send('preInit', concatTA(
      pubBytes,
      int2ba(this.C5Count, 2),
      int2ba(this.C6Count, 2),
      int2ba(this.ghashOTNeeded, 2),
      this.ot.getSenderA()), false, false); 

    let o = 0;
    this.eValidFrom = preInitBlob.slice(o, o+=4);
    this.eValidUntil = preInitBlob.slice(o, o+=4);
    this.ephemeralKey = preInitBlob.slice(o, o+=65);
    this.eSigByMasterKey = preInitBlob.slice(o, o+=64);
    const encrypted = preInitBlob.slice(o);

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
    const notaryA = await this.decryptFromNotary(nk, encrypted);
    this.ot.setA(notaryA);

    const that = this;
    const getBlobPromise = new Promise((resolve) => {
      this.getBlobFromNotary()
        .then(function(hisBlob){
          that.blob = that.processBlob(hisBlob);
          resolve();
        });
    });
    
    await this.setupWorkers();
    await this.g.garbleAll();
    let blobOut = [];
    for (let i=1; i < this.cs.length; i++){
      blobOut.push(this.g.garbledC[i].tt);
      blobOut.push(this.g.garbledC[i].ol);
    }

    // start blob upload as soon as download finishes
    await getBlobPromise;
    const sendBlobPromise = this.sendBlobToNotary(concatTA(...blobOut));
    await this.preComputeOT();
    await sendBlobPromise;
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
      that.pm.update('upload', {'current': i+1, 'total': chunkCount});
    }
    that.send('setBlobChunk', str2ba('magic: no more data'));
  }

  // getNotaryBlob downloads a blob from notary in 1 MB chunks publishes the download progress
  // to the UI.
  async getBlobFromNotary (){
    const allChunks = [];
    const totalBytes = ba2int(await this.send('init'));
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
      this.pm.update('download', {'current': soFarBytes, 'total': totalBytes});
    }
    const rv = concatTA(...allChunks);
    assert(rv.length === totalBytes);
    return rv;
  }

  async decryptFromNotary (key, enc){
    try{
      const IV = enc.slice(0,12);
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
    const workerCount = [0,1,1,1,1,maxWorkerCount,1];
    for (let i=1; i < this.cs.length; i++){
      this.workers[i] = new GCWorker(workerCount[i], this.pm);
      this.workers[i].parse(this.cs[i].circuit);
    }
  }

  async phase2(outArray) {
    console.log('reached phase2');
    const c1Output = outArray[0];   
    const innerStateMasked = c1Output.slice(0, 32);
    const innerStateUint8 = xor(innerStateMasked, this.cs[1].masks[1]);

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

    const nonFixedBits = bytesToBits(concatTA(p2.subarray(0, 16), p1inner));
    return await this.runCircuit(nonFixedBits, 2);
  }

  async phase3(outArray) {
    const c2_output = outArray[0];
    const innerStateMasked = c2_output.slice(0, 32);
    const innerStateUint8 = xor(innerStateMasked, this.cs[2].masks[1]);

    // hash state for MS
    this.innerState_MS = new Int32Array(8);
    for (var i = 0; i < 8; i++) {
      var hex = ba2hex(innerStateUint8).slice(i * 8, (i + 1) * 8);
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
    const nonFixedBits = bytesToBits(concatTA(p1inner_vd, p2inner, p1inner));
    return await this.runCircuit(nonFixedBits, 3);
  }

  async phase4(outArray) {
    const c3_output = outArray[0];
    let o = 0; // offset 
    const verify_dataMasked = c3_output.slice(o, o+=12);
    const verify_data = xor(verify_dataMasked, this.cs[3].masks[8]);
    const clientFinished = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verify_data);

    const encCounterMasked = c3_output.slice(o, o+=16);
    const encCounter = xor(encCounterMasked, this.cs[3].masks[7]);

    const gctrMaskedTwice = c3_output.slice(o, o+=16);
    const myGctrShare = xor(gctrMaskedTwice, this.cs[3].masks[6]);
 
    const H1MaskedTwice = c3_output.slice(o, o+=16);

    const H1 = xor(H1MaskedTwice, this.cs[3].masks[5]);
    this.powersOfH[1] = H1;
    const H2 = blockMult(H1, H1);
    this.powersOfH[2] = H2;
    const H1H2 = blockMult(H1, H2);

    // OT starts with the highest bit
    const h1Bits = bytesToBits(H1).reverse();
    const [idxArray1, otKeys1] = this.ot.getIndexesFromPool(h1Bits);
    const h2Bits = bytesToBits(H2).reverse();
    const [idxArray2, otKeys2] = this.ot.getIndexesFromPool(h2Bits);

    const civMaskedTwice = c3_output.slice(o, o+=4);
    this.civMaskedByNotary = xor(civMaskedTwice, this.cs[3].masks[4]);
    const sivMaskedTwice = c3_output.slice(o, o+=4);
    this.sivMaskedByNotary = xor(sivMaskedTwice, this.cs[3].masks[3]);

    const cwkMaskedTwice = c3_output.slice(o, o+=16);
    const swkMaskedTwice = c3_output.slice(o, o+=16);
    this.cwkMaskedByNotary = xor(cwkMaskedTwice, this.cs[3].masks[2]);
    this.swkMaskedByNotary = xor(swkMaskedTwice, this.cs[3].masks[1]);

    const encCF = xor(clientFinished, encCounter);
    const step3resp = await this.send('c3_step3', concatTA(encCF, idxArray1, idxArray2));
    assert(step3resp.length === 16 + 128*32 + 128*32);

    o = 0;
    const Snotary = step3resp.slice(o, o+=16);
    const encEntries1 = step3resp.slice(o, o+=(128*32));
    const encEntries2 = step3resp.slice(o, o+=(128*32));

    let H3share = H1H2;
    for (let i = 0; i < h1Bits.length; i += 1) {
      const bit = h1Bits[i];
      const ct = encEntries2.slice(i * 32, (i+1) * 32);
      const maskedEntry = this.ot.decryptWithKey(ct, bit, otKeys1[i]);
      H3share = xor(H3share, maskedEntry);
    }
    for (let i = 0; i < h2Bits.length; i += 1) {
      const bit = h2Bits[i];
      const ct = encEntries1.slice(i * 32, (i+1) * 32);
      const maskedEntry = this.ot.decryptWithKey(ct, bit, otKeys2[i]);
      H3share = xor(H3share, maskedEntry);
    }
    this.powersOfH[3] = H3share;
       
    const aad = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16, 0, 0, 0]);
    // lenA (before padding) == 13*8 == 104, lenC == 16*8 == 128
    const lenAlenC = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 128]);

    const s1share = blockMult(aad, H3share);
    const s2share = blockMult(encCF, H2);
    const s3share = blockMult(lenAlenC, H1);
    const Sclient = xor(xor(xor(s1share, s2share), s3share), myGctrShare);
    const tagFromPowersOfH = xor(Sclient, Snotary);

    return [encCF, tagFromPowersOfH, verify_data];
  }

  // getClientFinishedResumed runs a circuit to obtain data needed to construct the
  // Client Finished messages for cases when we need TLS session resumption 
  async getClientFinishedResumed(hs_hash){
    const seed = concatTA(str2ba('client finished'), hs_hash);
    const a1inner = innerHash(this.innerState_MS, seed);
    const a1 = await this.send('c7_step1', a1inner);
    const p1inner = innerHash(this.innerState_MS, a1);
    // p1inner is the client's input to c7
    const mask1 = getRandom(16)
    const mask2 = getRandom(12)
    const nonFixedBits = bytesToBits(concatTA(
    mask2, mask2, this.civMaskedByNotary, this.cwkMaskedByNotary, p1inner));

  }

  // getServerKeyShare returns client's xor share of server_write_key
  // and server_write_iv  
  getKeyShares(){
    return [this.cwkMaskedByNotary, this.civMaskedByNotary,
      this.swkMaskedByNotary, this.sivMaskedByNotary];
  }

  getEphemeralKey(){
    return [this.ephemeralKey, this.eValidFrom, this.eValidUntil, this.eSigByMasterKey];
  }

  // eslint-disable-next-line class-methods-use-this
  // optionally send extra data
  async runCircuit(nonFixedBits, cNo, extraData) {
    console.log('in runCircuit', cNo);
    if (extraData == undefined){
      extraData = new Uint8Array();
    }
    const c = this.cs[cNo];
    const circuit = c.circuit;
    // how many times to repeat evaluation (> 1 only for circuits 5&7 )
    const repeatCount = [0,1,1,1,1,this.C5Count,1,this.C6Count][cNo];
    const [idxArray, otKeys] = this.ot.getIndexesFromPool(nonFixedBits);

    // for circuit 1, there was no previous commit
    const prevCommit = cNo > 1 ? this.myCommit[cNo-1] : new Uint8Array();

    const blob1 = await this.send(`c${cNo}_step1`, concatTA(prevCommit, idxArray, extraData));

    let offset = 0;
    if (cNo > 1){
      const prevCommitSalt = blob1.slice(offset, offset + 32);
      offset += 32;
      // the hash to which the notary committed must be equal to our commit
      const saltedCommit = await sha256(concatTA(this.myCommit[cNo-1], prevCommitSalt));
      assert (eq(saltedCommit, this.hisSaltedCommit[cNo-1]));
    }
    let notaryInputsCount = circuit.notaryInputSize;
    if (cNo === 6){
      notaryInputsCount = 160 + 128 * this.C6Count;
    }
    const notaryInputsBlob = blob1.slice(offset, offset + notaryInputsCount*16);
    offset += notaryInputsCount*16;
    const encLabels = blob1.slice(offset, offset+nonFixedBits.length*32);
    offset += nonFixedBits.length*32;
    const nonFixedIndexes = blob1.slice(offset, offset+c.notaryNonFixedInputSize*2);
    offset += c.notaryNonFixedInputSize*2;
    assert(blob1.length === offset);

    const nonFixedEncLabels = this.g.getNonFixedEncLabels(nonFixedIndexes, cNo);
    const clientLabels = this.g.getClientLabels(nonFixedBits, cNo);
    const sendPromise = this.send(`c${cNo}_step2`, concatTA(nonFixedEncLabels, clientLabels), true);
    const nonFixedLabels = this.e.getNonFixedLabels(encLabels, otKeys, nonFixedBits);
    const allNotaryLabels = splitIntoChunks(notaryInputsBlob, 16);
  
    // collect batch of evaluation
    const batch = [];
    for (let r=0; r < repeatCount; r++){
      let fixedLabels = this.fixedLabels[cNo];
      let notaryLabels = allNotaryLabels;
      if (cNo === 5){
        fixedLabels = this.fixedLabels[cNo].slice(r*148, r*148+148);
      }
      else if (cNo === 6){
        assert(this.fixedLabels[cNo].length === 144*repeatCount);
        fixedLabels = this.fixedLabels[cNo].slice(r*144, r*144+144);
        const commonNotary = allNotaryLabels.slice(0,160);
        const uniqueNotary = allNotaryLabels.slice(160+r*128, 160+r*128+128);
        notaryLabels = [].concat(commonNotary, uniqueNotary);
      }
      const garbledAssignment = concatTA(...notaryLabels, ...nonFixedLabels, ...fixedLabels);
      const ttSize = circuit.andGateCount * 64;
      const tt = this.blob[`c${cNo}_tt`].slice(r*ttSize, r*ttSize+ttSize);
      batch.push([garbledAssignment, tt]);
    }

    // perform evaluation
    console.time('evaluateBatch');
    const batchOutputLabels = await this.e.evaluateBatch(batch, cNo);
    console.timeEnd('evaluateBatch');
    const output = [];

    // process evaluation outputs
    for (let r=0; r < repeatCount; r++){
      const outputLabelsBlob = batchOutputLabels[r];
      const outputLabels = splitIntoChunks(outputLabelsBlob, 16);

      const outputSize = circuit.outputSize * 32;
      const allOutputLabelsBlob = this.blob[`c${cNo}_ol`].slice(r*outputSize, (r+1)*outputSize);
      assert(allOutputLabelsBlob.length === circuit.outputSize*32);
      const allOutputLabels = splitIntoChunks(allOutputLabelsBlob, 16);

      const bits = [];
      for (let i = 0; i < circuit.outputSize; i++) {
        const out = outputLabels[i];
        if (eq(out, allOutputLabels[i*2])) {
          bits.push(0);
        } else if (eq(out, allOutputLabels[i*2+1])) {
          bits.push(1);
        } else {
          console.log('evaluator output does not match the garbled outputs');
        }
      }
      const out = bitsToBytes(bits);
      this.output[cNo] = out;
      output.push(out);
    }
    this.myCommit[cNo] = await sha256(concatTA(...output));

    const cStep2Out = await sendPromise;
    this.hisSaltedCommit[cNo] = cStep2Out.subarray(0,32);
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
      let truthTableSize = this.cs[i].circuit.andGateCount *64;
      let outputLabelsSize = this.cs[i].circuit.outputSize *32;
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
      Secret.slice(0,16),
      'AES-GCM', true, ['encrypt']);

    const notaryKey = await crypto.subtle.importKey(
      'raw',
      Secret.slice(16,32),
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
