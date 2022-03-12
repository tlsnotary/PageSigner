/* global process, global */

// gcworker.js is a WebWorker which performs garbling and evaluation
// of garbled circuits.
// This is a fixed-key-cipher garbling method from BHKR13
// https://eprint.iacr.org/2013/426.pdf

// eslint-disable-next-line no-undef
var parentPort_;
let circuit = null;
let truthTables = null;
let andGateIdx = null;

// fixedKey is used by randomOracle(). We need a 32-byte key because we use
// Salsa20. The last 4 bytes will be filled with the tweak, i.e. the index of
// the circuit's wire.
const fixedKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 0, 0, 0, 0]);
// sigma is Salsa's constant "expand 32-byte k"
const sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98,
  121, 116, 101, 32, 107]);
// randomPool will be filled with data from getRandom
let randomPool;
// randomPoolOffset will be shifted after data was read from randomPool
let randomPoolOffset = 0;
let garblingAssigment, evaluationAssigment;
var crypto_;

if (typeof(importScripts) !== 'undefined') {
  crypto_ = self.crypto;
  self.onmessage = function(event) {
    processMessage(event.data);
  };
} else {
  // we are in nodejs
  import('module').then((module) => {
    // we cannot use the "import" keyword here because on first pass the browser unconditionaly
    // parses this if clause and will error out if "import" is found
    // using process.argv instead of import.meta.url to get the name of this script
    const filePath = 'file://' + process.argv[1];
    // this workaround allows to require() from ES6 modules, which is not allowed by default
    const require = module.createRequire(filePath);
    const { parentPort } = require('worker_threads');
    parentPort_ = parentPort;
    const { Crypto } = require('@peculiar/webcrypto');
    crypto_ = new Crypto();
    const perf = {'now':function(){return 0;}};
    global.performance = perf;
    parentPort.on('message', msg => {
      processMessage(msg);
    });
  });
}

function processMessage(obj){
  if (obj.msg === 'parse'){
    circuit = obj.circuit;
    garblingAssigment = new Uint8Array(32*(circuit.wiresCount));
    evaluationAssigment = new Uint8Array(16*(circuit.wiresCount));
    postMsg('DONE');
  }
  else if (obj.msg === 'setTruthTables'){
    assert(obj.tt.byteLength == circuit.andGateCount*48);
    truthTables = new Uint8Array(obj.tt);
    // no need to respond to this
  }
  else if (obj.msg === 'garble'){
    if (circuit == null){
      console.log('error: need to parse circuit before garble');
      return;
    }
    console.time('worker_garble');
    const [inputLabels, truthTables, decodingTable] = garble(circuit, garblingAssigment);
    assert (inputLabels.length === circuit.clientInputSize*32 + circuit.notaryInputSize*32);
    assert (truthTables.length === circuit.andGateCount*48);
    assert (decodingTable.length === Math.ceil(circuit.outputSize/8));
    const obj = {'il': inputLabels.buffer, 'tt': truthTables.buffer, 'dt': decodingTable.buffer};
    postMsg(obj, [inputLabels.buffer, truthTables.buffer, decodingTable.buffer]);
    console.timeEnd('worker_garble');
  }
  else if (obj.msg === 'evaluate'){
    if (circuit == null || truthTables == null){
      console.log('error: need to parse circuit and set truth table before evaluate');
      return;
    }
    console.time('worker_evaluate');
    const inputSize = circuit.clientInputSize*16 + circuit.notaryInputSize*16;
    const inputLabels = new Uint8Array(obj.il);
    assert (inputLabels.length === inputSize);
    const encodedOutput = evaluate(circuit, evaluationAssigment, inputLabels, truthTables);
    assert (encodedOutput.length === Math.ceil(circuit.outputSize/8));
    postMsg(encodedOutput.buffer);
    console.timeEnd('worker_evaluate');
  }
  else {
    console.log('Error: unexpected message in worker');
  }
}


function postMsg(value, transferList){
  if (typeof importScripts !== 'function'){
    parentPort_.postMessage({data:value}, transferList);
  } else {
    postMessage(value, transferList);
  }
}


function newR(){
  const R = getRandom(16);
  // set the last bit of R to 1 for point-and-permute
  // this guarantees that 2 labels of the same wire will have the opposite last bits
  R[15] = R[15] | 0x01;
  return R;
}

function generateInputLabels(count, R){
  const newLabels = new Uint8Array(count*32);
  for (let i=0; i < count; i++){
    const label1 = getRandom(16);
    const label2 = xor(label1, R);
    newLabels.set(label1, i*32);
    newLabels.set(label2, i*32+16);
  }
  return newLabels;
}

function garble(circuit, ga){
  const inputCount = circuit.notaryInputSize + circuit.clientInputSize;
  fillRandom((inputCount+1+circuit.andGateCount)*16);
  const R = newR();

  // generate new labels
  const inputLabels = generateInputLabels(inputCount, R);
  ga.set(inputLabels);
  const truthTables = new Uint8Array(circuit.andGateCount*48);

  andGateIdx = 0;
  // garble gates
  for (let i = 0; i < circuit.gatesCount; i++) {
    const gateBlob = circuit.gatesBlob.subarray(i*10, i*10+10);
    const op = ['XOR', 'AND', 'INV'][gateBlob[0]];
    if (op === 'AND') {
      garbleAnd(gateBlob, R, ga, truthTables, andGateIdx, i);
      andGateIdx += 1;
    } else if (op === 'XOR') {
      garbleXor(gateBlob, R, ga);
    } else if (op === 'NOT' || op === 'INV') {
      garbleNot(gateBlob, ga);
    } else {
      throw new Error('Unrecognized gate: ' + op);
    }
  }

  // get decoding table: LSB of label0 for each output wire
  const outLSBs = [];
  for (let i = 0; i < circuit.outputSize; i++){
    outLSBs.push(ga[ga.length-circuit.outputSize*32+i*32+15] & 1);
  }
  const decodingTable = bitsToBytes(outLSBs);
  return [inputLabels, truthTables, decodingTable];
}


const garbleAnd = function (gateBlob, R, ga, tt, andGateIdx, id) {
  // get wire numbers
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const in2 = threeBytesToInt(gateBlob.subarray(4, 7));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));

  // get labels of each wire
  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in1_1 = gaGetIndexG(ga, in1, 1);
  const in2_0 = gaGetIndexG(ga, in2, 0);
  const in2_1 = gaGetIndexG(ga, in2, 1);

  // rows is a truthtable in a canonical order, the third
  // item shows an index of output label
  const rows = [
    [in1_0, in2_0, 0],
    [in1_0, in2_1, 0],
    [in1_1, in2_0, 0],
    [in1_1, in2_1, 1]
  ];

  // GRR3: garbled row reduction
  // We want to reduce a row where both labels' points are set to 1.
  // We first need to encrypt those labels with a dummy all-zero output label. The
  // result X will be the actual value of the output label that we need to set.
  // After we set the output label to X and encrypt again, the result will be 0 (but
  // we don't actually need to encrypt it again, we just know that the result will be 0)

  let outLabels;
  // idxToReduce is the index of the row that will be reduced
  let idxToReduce = -1;
  for (let i=0; i < rows.length; i++){
    if (getPoint(rows[i][0]) == 1 && getPoint(rows[i][1]) == 1){
      const outWire = encrypt(rows[i][0], rows[i][1], id, new Uint8Array(16).fill(0));
      if (i==3){
        outLabels = [xor(outWire, R), outWire];
      } else {
        outLabels = [outWire, xor(outWire, R)];
      }
      idxToReduce = i;
      break;
    }
  }
  gaSetIndexG(ga, out, 0, outLabels[0]);
  gaSetIndexG(ga, out, 1, outLabels[1]);
  assert(idxToReduce != -1);

  for (let i=0; i < rows.length; i++){
    if (i == idxToReduce){
      // not encrypting this row because we already know that its encryption is 0
      // and the sum of its points is 3
      continue;
    }
    const value = encrypt(rows[i][0], rows[i][1], id, outLabels[rows[i][2]]);
    const point = 2 * getPoint(rows[i][0]) + getPoint(rows[i][1]);
    tt.set(value, andGateIdx*48+16*point);
  }
};


const garbleXor = function (gateBlob, R, ga) {
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const in2 = threeBytesToInt(gateBlob.subarray(4, 7));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));

  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in2_0 = gaGetIndexG(ga, in2, 0);

  const label0 = xor(in1_0, in2_0);
  gaSetIndexG(ga, out, 0, label0);
  gaSetIndexG(ga, out, 1, xor(label0, R, true));
};


const garbleNot = function (gateBlob, ga) {
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));

  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in1_1 = gaGetIndexG(ga, in1, 1);
  // careful! don't put the reference back into ga, but a copy of it
  gaSetIndexG(ga, out, 0, in1_1.slice());
  gaSetIndexG(ga, out, 1, in1_0.slice());
};

function evaluate (circuit, ga, inputLabels, truthTables) {
  // set input labels
  ga.set(inputLabels);

  // evaluate one gate at a time
  let numberOfANDGates = 0;
  for (let i = 0; i < circuit.gatesCount; i++) {
    const gateBlob = circuit.gatesBlob.subarray(i*10, i*10+10);
    const op = ['XOR', 'AND', 'INV'][gateBlob[0]];
    if (op === 'AND') {
      evaluateAnd(ga, truthTables, numberOfANDGates, gateBlob, i);
      numberOfANDGates += 1;
    } else if (op === 'XOR') {
      evaluateXor(ga, gateBlob);
    } else if (op === 'INV' || op === 'NOT') {
      evaluateNot(ga, gateBlob);
    } else {
      throw new Error(`Unrecognized gate: ${op}`);
    }
  }

  // get encoded outputs: LSB of label0 for each output wire
  const outLSBs = [];
  for (let i = 0; i < circuit.outputSize; i++){
    outLSBs.push(ga[ga.length-circuit.outputSize*16+i*16+15] & 1);
  }
  return  bitsToBytes(outLSBs);
}

const evaluateAnd = function (ga, tt, andGateIdx, gateBlob, id) {
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const in2 = threeBytesToInt(gateBlob.subarray(4, 7));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));

  const label1 = gaGetIndexE(ga, in1); // ga[in1];
  const label2 = gaGetIndexE(ga, in2); // ga[in2];

  let cipher;
  const point = 2 * getPoint(label1) + getPoint(label2);
  if (point == 3){
    // GRR3: all rows with point sum of 3 have been reduced
    // their encryption is an all-zero bytestring
    cipher = new Uint8Array(16).fill(0);
  } else {
    const offset = andGateIdx*48+16*point;
    cipher = tt.subarray(offset, offset+16);
  }
  gaSetIndexE(ga, out, decrypt(label1, label2, id, cipher));
};


const evaluateXor = function (ga, gateBlob) {
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const in2 = threeBytesToInt(gateBlob.subarray(4, 7));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));

  const v1 = gaGetIndexE(ga, in1);
  const v2 = gaGetIndexE(ga, in2);
  gaSetIndexE(ga, out, xor(v1, v2));
};

const evaluateNot = function (ga, gateBlob) {
  const in1 = threeBytesToInt(gateBlob.subarray(1, 4));
  const out = threeBytesToInt(gateBlob.subarray(7, 10));
  gaSetIndexE(ga, out, gaGetIndexE(ga, in1));
};

// get value at index in the garbled assignment when evaluating
function gaGetIndexE(ga, idx){
  return ga.subarray(idx*16, idx*16+16);
}

// set value at index in the garbled assignment when evaluating
function gaSetIndexE(ga, idx, value){
  ga.set(value, idx*16);
}

// get value at index in the garbled assignment when garbling
// pos is index within idx (either 0 or 1)
function gaGetIndexG(ga, idx, pos){
  return ga.subarray(idx*32+16*pos, idx*32+16*pos+16);
}

// set value at index and (position in index) in the garbled assignment when garbling
// values is an array of two 16-byte values
function gaSetIndexG(ga, idx, pos, value){
  ga.set(value, idx*32+pos*16);
}


function xor(a, b, reuse) {
  assert(a.length == b.length, 'a.length !== b.length');
  let bytes;
  if (reuse === true){
    // in some cases the calling function will have no more use of "a"
    // so we reuse it to return the value
    // saving a few cycles on not allocating a new var
    bytes = a;
  }
  else {
    bytes = a.slice();
  }
  for (let i = 0; i < a.length; i++) {
    bytes[i] = a[i] ^ b[i];
  }
  return bytes;
}

function getPoint(arr) {
  return arr[15] & 0x01;
}

const decrypt = encrypt;

// Based on the the A4 method from Fig.1 and the D4 method in Fig6 of the BHKR13 paper
// (https://eprint.iacr.org/2013/426.pdf)
// Note that the paper doesn't prescribe a specific method to break the symmetry between A and B,
// so we choose a circular byte shift instead of a circular bitshift as in Fig6.
function encrypt(a, b, t, m) {
  // double a
  const a2 = a.slice();
  const leastbyte = a2[0];
  a2.copyWithin(0, 1, 15);  // Logical left shift by 1 byte
  a2[14] = leastbyte;  // Restore old least byte as new greatest (non-pointer) byte
  // quadruple b
  const b4 = b.slice();
  const leastbytes = [b4[0], b4[1]];
  b4.copyWithin(0, 2, 15);  // Logical left shift by 2 byte
  [b4[13], b4[14]] = leastbytes;  // Restore old least two bytes as new greatest bytes

  const k = xor(a2, b4, true);
  const ro = randomOracle(k, t);
  const mXorK = xor(k, m, true);
  return xor(ro, mXorK, true);
}


function randomOracle(m, t) {
  // convert the integer t to a 4-byte big-endian array and append
  // it to fixedKey in-place
  for (let index = 0; index < 4; index++) {
    const byte = t & 0xff;
    fixedKey[31-index] = byte;
    t = (t - byte) / 256;
  }
  return Salsa20(fixedKey, m);
}


function threeBytesToInt(b){
  return b[2] + b[1]*256 + b[0]*65536;
}


function getRandom(count) {
  const rand = randomPool.subarray(randomPoolOffset, randomPoolOffset+count);
  randomPoolOffset += count;
  return rand;
}

// to save time we fill the randomPool in one call and then take
// randomness from that pool. Instead of making 1000s of calls to getRandomValues()
function fillRandom(count){
  // 65536 is the max that API supports
  const randomChunks = [];
  const chunkCount = Math.ceil(count/65536);
  for (let i=0; i < chunkCount; i++){
    randomChunks.push(crypto_.getRandomValues(new Uint8Array(65536)));
  }
  randomPool = concatTA(...randomChunks);
  randomPoolOffset = 0;
}


function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || 'Assertion failed';
  }
}

// concatenate an array of typed arrays (specifically Uint8Array)
function concatTA (...arr){
  let newLen = 0;
  for (const item of arr){
    assert(item instanceof Uint8Array);
    newLen += item.length;
  }
  const newArray = new Uint8Array(newLen);
  let offset = 0;
  for (const item of arr){
    newArray.set(item, offset);
    offset += item.length;
  }
  return newArray;
}

// convert an array of 0/1 (with least bit at index 0) to Uint8Array
function bitsToBytes(arr){
  assert(arr.length % 8 === 0);
  const ba = new Uint8Array(arr.length/8);
  for (let i=0; i < ba.length; i++){
    let sum = 0;
    for (let j=0; j < 8; j++){
      sum += arr[i*8+j] * (2**j);
    }
    ba[ba.length-1-i] = sum;
  }
  return ba;
}

// use Salsa20 as a random permutator. Instead of the nonce, we feed the data that needs
// to be permuted.
function Salsa20(key, data){
  const out = new Uint8Array(16);
  core_salsa20(out, data, key, sigma);
  return out;
}

// copied from https://github.com/dchest/tweetnacl-js/blob/master/nacl-fast.js
// and modified to output only 16 bytes
function core_salsa20(o, p, k, c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff)<<8 | (c[ 2] & 0xff)<<16 | (c[ 3] & 0xff)<<24,
    j1  = k[ 0] & 0xff | (k[ 1] & 0xff)<<8 | (k[ 2] & 0xff)<<16 | (k[ 3] & 0xff)<<24,
    j2  = k[ 4] & 0xff | (k[ 5] & 0xff)<<8 | (k[ 6] & 0xff)<<16 | (k[ 7] & 0xff)<<24,
    j3  = k[ 8] & 0xff | (k[ 9] & 0xff)<<8 | (k[10] & 0xff)<<16 | (k[11] & 0xff)<<24,
    j4  = k[12] & 0xff | (k[13] & 0xff)<<8 | (k[14] & 0xff)<<16 | (k[15] & 0xff)<<24,
    j5  = c[ 4] & 0xff | (c[ 5] & 0xff)<<8 | (c[ 6] & 0xff)<<16 | (c[ 7] & 0xff)<<24,
    j6  = p[ 0] & 0xff | (p[ 1] & 0xff)<<8 | (p[ 2] & 0xff)<<16 | (p[ 3] & 0xff)<<24,
    j7  = p[ 4] & 0xff | (p[ 5] & 0xff)<<8 | (p[ 6] & 0xff)<<16 | (p[ 7] & 0xff)<<24,
    j8  = p[ 8] & 0xff | (p[ 9] & 0xff)<<8 | (p[10] & 0xff)<<16 | (p[11] & 0xff)<<24,
    j9  = p[12] & 0xff | (p[13] & 0xff)<<8 | (p[14] & 0xff)<<16 | (p[15] & 0xff)<<24,
    j10 = c[ 8] & 0xff | (c[ 9] & 0xff)<<8 | (c[10] & 0xff)<<16 | (c[11] & 0xff)<<24,
    j11 = k[16] & 0xff | (k[17] & 0xff)<<8 | (k[18] & 0xff)<<16 | (k[19] & 0xff)<<24,
    j12 = k[20] & 0xff | (k[21] & 0xff)<<8 | (k[22] & 0xff)<<16 | (k[23] & 0xff)<<24,
    j13 = k[24] & 0xff | (k[25] & 0xff)<<8 | (k[26] & 0xff)<<16 | (k[27] & 0xff)<<24,
    j14 = k[28] & 0xff | (k[29] & 0xff)<<8 | (k[30] & 0xff)<<16 | (k[31] & 0xff)<<24,
    j15 = c[12] & 0xff | (c[13] & 0xff)<<8 | (c[14] & 0xff)<<16 | (c[15] & 0xff)<<24;

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
    x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
    x15 = j15, u;

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0;
    x4 ^= u<<7 | u>>>(32-7);
    u = x4 + x0 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x4 | 0;
    x12 ^= u<<13 | u>>>(32-13);
    u = x12 + x8 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x1 | 0;
    x9 ^= u<<7 | u>>>(32-7);
    u = x9 + x5 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x9 | 0;
    x1 ^= u<<13 | u>>>(32-13);
    u = x1 + x13 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x6 | 0;
    x14 ^= u<<7 | u>>>(32-7);
    u = x14 + x10 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x14 | 0;
    x6 ^= u<<13 | u>>>(32-13);
    u = x6 + x2 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x11 | 0;
    x3 ^= u<<7 | u>>>(32-7);
    u = x3 + x15 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x3 | 0;
    x11 ^= u<<13 | u>>>(32-13);
    u = x11 + x7 | 0;
    x15 ^= u<<18 | u>>>(32-18);

    u = x0 + x3 | 0;
    x1 ^= u<<7 | u>>>(32-7);
    u = x1 + x0 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x1 | 0;
    x3 ^= u<<13 | u>>>(32-13);
    u = x3 + x2 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x4 | 0;
    x6 ^= u<<7 | u>>>(32-7);
    u = x6 + x5 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x6 | 0;
    x4 ^= u<<13 | u>>>(32-13);
    u = x4 + x7 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x9 | 0;
    x11 ^= u<<7 | u>>>(32-7);
    u = x11 + x10 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x11 | 0;
    x9 ^= u<<13 | u>>>(32-13);
    u = x9 + x8 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x14 | 0;
    x12 ^= u<<7 | u>>>(32-7);
    u = x12 + x15 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x12 | 0;
    x14 ^= u<<13 | u>>>(32-13);
    u = x14 + x13 | 0;
    x15 ^= u<<18 | u>>>(32-18);
  }
  x0 =  x0 +  j0 | 0;
  x1 =  x1 +  j1 | 0;
  x2 =  x2 +  j2 | 0;
  x3 =  x3 +  j3 | 0;
  x4 =  x4 +  j4 | 0;
  x5 =  x5 +  j5 | 0;
  x6 =  x6 +  j6 | 0;
  x7 =  x7 +  j7 | 0;
  x8 =  x8 +  j8 | 0;
  x9 =  x9 +  j9 | 0;
  x10 = x10 + j10 | 0;
  x11 = x11 + j11 | 0;
  x12 = x12 + j12 | 0;
  x13 = x13 + j13 | 0;
  x14 = x14 + j14 | 0;
  x15 = x15 + j15 | 0;

  o[ 0] = x0 >>>  0 & 0xff;
  o[ 1] = x0 >>>  8 & 0xff;
  o[ 2] = x0 >>> 16 & 0xff;
  o[ 3] = x0 >>> 24 & 0xff;

  o[ 4] = x1 >>>  0 & 0xff;
  o[ 5] = x1 >>>  8 & 0xff;
  o[ 6] = x1 >>> 16 & 0xff;
  o[ 7] = x1 >>> 24 & 0xff;

  o[ 8] = x2 >>>  0 & 0xff;
  o[ 9] = x2 >>>  8 & 0xff;
  o[10] = x2 >>> 16 & 0xff;
  o[11] = x2 >>> 24 & 0xff;

  o[12] = x3 >>>  0 & 0xff;
  o[13] = x3 >>>  8 & 0xff;
  o[14] = x3 >>> 16 & 0xff;
  o[15] = x3 >>> 24 & 0xff;
  // we only need 16 bytes of the output
}
