// gcworker.js is a WebWorker which performs garbling and evaluation
// of garbled circuits

// eslint-disable-next-line no-undef
importScripts('./../../third-party/nacl-fast.js');

let circuit = null;
let truthTable = null;
let timeEvaluating = 0;

// sha0 is used by randomOracle
const sha0 = new Uint8Array( hex2ba('da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8'));
// byteArray is used by randomOracle
const byteArray = new Uint8Array(24);
// randomPool will be filled with data from getRandom
let randomPool; 
// randomPoolOffset will be moved after data was read from randomPool
let randomPoolOffset = 0; 
let garbledAssigment; 

self.onmessage = function(event) {
  const msg = event.data.msg;
  const data = event.data.data;
  if (msg === 'parse'){
    circuit = data;
    garbledAssigment = new Uint8Array(32*(circuit.wiresCount));
    // no need to respond to this message
  }
  else if (msg === 'setTruthTable'){
    assert(data.byteLength == circuit.andGateCount*64);
    truthTable = new Uint8Array(data);
  }
  else if (msg === 'garble'){
    console.log('in garble with circuit', circuit);
    if (circuit == null){
      console.log('error: need to parse circuit before garble');
      return;
    }
    console.time('garbling done in');
    const reuseLabels = (data == undefined) ? undefined : data.reuseLabels;
    const reuseIndexes = (data == undefined) ? undefined : data.reuseIndexes;
    const reuseR = (data == undefined) ? undefined : data.reuseR;

    const [truthTable, inputLabels, outputLabels, R] = garble(circuit, garbledAssigment, reuseLabels, reuseIndexes, reuseR);
    assert (truthTable.length === circuit.andGateCount*64);
    assert (inputLabels.length === circuit.clientInputSize*32 + circuit.notaryInputSize*32);
    assert (outputLabels.length === circuit.outputSize*32);
    const obj = {'tt': truthTable.buffer, 'il': inputLabels.buffer, 'ol': outputLabels.buffer, 'R': R};
    console.timeEnd('garbling done in');
    postMessage(obj, [truthTable.buffer, inputLabels.buffer, outputLabels.buffer]);
  }
  else if (msg === 'evaluate'){
    if (circuit == null || truthTable == null){
      console.log('error: need to parse circuit and set truth table before evaluate');
      return;
    }
    const garbledAssigment = new Uint8Array(16*(circuit.wiresCount));
    const inputLabels = new Uint8Array(data);
    assert (inputLabels.length === circuit.clientInputSize*16 + circuit.notaryInputSize*16);
    const outputLabels = evaluate(circuit, garbledAssigment, truthTable, inputLabels);
    assert (outputLabels.length === circuit.outputSize*16);
    postMessage(outputLabels.buffer);
  }
  else {
    console.log('Error: unexpected message in worker');
  }
};

function newR(){
  const R = getRandom(16);
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

function garble(circuit, ga, reuseLabels = new Uint8Array(0) , reuseIndexes = [], R){
  
  const inputCount = circuit.notaryInputSize + circuit.clientInputSize;
  fillRandom((inputCount+1+circuit.andGateCount)*16);
  R = R || newR();
  
  // generate new labels
  const newLabels = generateInputLabels(inputCount - reuseIndexes.length, R);

  // set both new and reused labels into ga
  let reusedCount = 0;    // how many reused inputs were already put into ga
  let newInputsCount = 0; // how many new inputs were already put into ga

  for (let i = 0; i < inputCount; i++) {
    if (reuseIndexes.includes(i)) {
      ga.set(reuseLabels.subarray(reusedCount*32, reusedCount*32+32), i*32);
      reusedCount += 1;
    }
    else {
      ga.set(newLabels.subarray(newInputsCount*32, newInputsCount*32+32), i*32);
      newInputsCount += 1;
    }
  }
 
  const truthTable = new Uint8Array(circuit.andGateCount*64);
  let andGateIdx = 0;
  // garble gates
  for (let i = 0; i < circuit.gatesCount; i++) {
    const gateBlob = circuit.gatesBlob.subarray(i*10, i*10+10);
    const op = ['XOR', 'AND', 'INV'][gateBlob[0]];
    if (op === 'AND') {
      garbleAnd(gateBlob, R, ga, truthTable, andGateIdx, i);
      andGateIdx += 1;
    } else if (op === 'XOR') {
      garbleXor(gateBlob, R, ga);
    } else if (op === 'NOT' || op === 'INV') {
      garbleNot(gateBlob, ga);
    } else {
      throw new Error('Unrecognized gate: ' + op);
    }
  }
  
  return [truthTable, ga.slice(0, inputCount*32), ga.slice(-circuit.outputSize*32), R];
     
}

const garbleAnd = function (gateBlob, R, ga, tt, andGateIdx, id) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const in2 = threeBytesToInt(gateBlob.subarray(4,7));
  const out = threeBytesToInt(gateBlob.subarray(7,10));
  
  const randomLabel = getRandom(16);

  gaSetIndexG(ga, out, 0, randomLabel);
  gaSetIndexG(ga, out, 1, xor(randomLabel, R, true));

  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in1_1 = gaGetIndexG(ga, in1, 1);
  const in2_0 = gaGetIndexG(ga, in2, 0);
  const in2_1 = gaGetIndexG(ga, in2, 1);
  const out_0 = gaGetIndexG(ga, out, 0);
  const out_1 = gaGetIndexG(ga, out, 1);

  const values = [
    encrypt(in1_0, in2_0, id, out_0),
    encrypt(in1_0, in2_1, id, out_0),
    encrypt(in1_1, in2_0, id, out_0),
    encrypt(in1_1, in2_1, id, out_1)
  ];
  
  const points = [
    2 * getPoint(in1_0) + getPoint(in2_0),
    2 * getPoint(in1_0) + getPoint(in2_1),
    2 * getPoint(in1_1) + getPoint(in2_0),
    2 * getPoint(in1_1) + getPoint(in2_1)
  ];

  tt.set(values[0], andGateIdx*64+16*points[0]);
  tt.set(values[1], andGateIdx*64+16*points[1]);
  tt.set(values[2], andGateIdx*64+16*points[2]);
  tt.set(values[3], andGateIdx*64+16*points[3]);
};


const garbleXor = function (gateBlob, R, ga) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const in2 = threeBytesToInt(gateBlob.subarray(4,7));
  const out = threeBytesToInt(gateBlob.subarray(7,10));

  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in1_1 = gaGetIndexG(ga, in1, 1);
  const in2_0 = gaGetIndexG(ga, in2, 0);
  const in2_1 = gaGetIndexG(ga, in2, 1);

  gaSetIndexG(ga, out, 0, xor(in1_0, in2_0));
  gaSetIndexG(ga, out, 1, xor(xor(in1_1, in2_1), R, true));
};
  

const garbleNot = function (gateBlob, ga) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const out = threeBytesToInt(gateBlob.subarray(7,10));

  const in1_0 = gaGetIndexG(ga, in1, 0);
  const in1_1 = gaGetIndexG(ga, in1, 1);
  // careful! don't put the reference back into ga, but a copy of it
  gaSetIndexG(ga, out, 0, in1_1.slice());
  gaSetIndexG(ga, out, 1, in1_0.slice());
};

function evaluate (circuit, ga, tt, inputLabels) {
  // set input labels
  ga.set(inputLabels);

  // evaluate one gate at a time
  let numberOfANDGates = 0;
  const t0 = performance.now();
  console.time('worker_evaluate');
  for (let i = 0; i < circuit.gatesCount; i++) {
    const gateBlob = circuit.gatesBlob.subarray(i*10, i*10+10);
    const op = ['XOR', 'AND', 'INV'][gateBlob[0]];
    if (op === 'AND') {
      evaluateAnd(ga, tt, numberOfANDGates, gateBlob, i);
      numberOfANDGates += 1;
    } else if (op === 'XOR') {
      evaluateXor(ga, gateBlob);
    } else if (op === 'INV' || op === 'NOT') {
      evaluateNot(ga, gateBlob);
    } else {
      throw new Error(`Unrecognized gate: ${op}`);
    }
  }
  console.timeEnd('worker_evaluate');
  const t1 = performance.now();
  timeEvaluating += (t1 - t0);

  return ga.slice((circuit.wiresCount-circuit.outputSize)*16, circuit.wiresCount*16);
}

const evaluateAnd = function (ga, tt, andGateIdx, gateBlob, id) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const in2 = threeBytesToInt(gateBlob.subarray(4,7));
  const out = threeBytesToInt(gateBlob.subarray(7,10));
  
  const label1 = gaGetIndexE(ga, in1); // ga[in1];
  const label2 = gaGetIndexE(ga, in2); // ga[in2];
  
  const point = 2 * getPoint(label1) + getPoint(label2);
  const offset = andGateIdx*64+16*point;
  const cipher = tt.subarray(offset, offset+16);
  
  gaSetIndexE(ga, out, decrypt(label1, label2, id, cipher));
};

const evaluateXor = function (ga, gateBlob) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const in2 = threeBytesToInt(gateBlob.subarray(4,7));
  const out = threeBytesToInt(gateBlob.subarray(7,10));
    
  const v1 = gaGetIndexE(ga, in1);
  const v2 = gaGetIndexE(ga, in2);
  gaSetIndexE(ga, out, xor(v1, v2));
};
    
const evaluateNot = function (ga, gateBlob) {
  const in1 = threeBytesToInt(gateBlob.subarray(1,4));
  const out = threeBytesToInt(gateBlob.subarray(7,10));  
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
  if (a.length !== b.length){
    console.log('a.length !== b.length');
    throw('a.length !== b.length');
  }
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

let a2;
let b4;
function encrypt(a, b, t, m) {
  // double a 
  a2 = a.slice();
  const leastbyte = a2[0];
  a2.copyWithin(0,1,15);  // Logical left shift by 1 byte
  a2[14] = leastbyte;  // Restore old least byte as new greatest (non-pointer) byte
  // quadruple b
  b4 = b.slice();
  const leastbytes = [b4[0], b4[1]];
  b4.copyWithin(0,2,15);  // Logical left shift by 2 byte
  [b4[13], b4[14]] = leastbytes;  // Restore old least two bytes as new greatest bytes
  
  const k = xor(a2, b4, true);
  const ro = randomOracle(k, t);
  const mXorK = xor(k, m, true);
  return xor(ro, mXorK, true);
}

function randomOracle(m, t) {
  return self.nacl.secretbox(
    m,
    longToByteArray(t),
    sha0,
  ).subarray(0,16);
}

function longToByteArray(long) {
  // we want to represent the input as a 24-bytes array
  for (let index = 0; index < byteArray.length; index++) {
    const byte = long & 0xff;
    byteArray[index] = byte;
    long = (long - byte) / 256;
  }
  return byteArray;
}

function threeBytesToInt(b){
  return b[2] + b[1]*256 + b[0]*65536;
}

// convert a hex string into byte array
function hex2ba(str) {
  var ba = [];
  // pad with a leading 0 if necessary
  if (str.length % 2) {
    str = '0' + str;
  }
  for (var i = 0; i < str.length; i += 2) {
    ba.push(parseInt('0x' + str.substr(i, 2)));
  }
  return ba;
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
    randomChunks.push(self.crypto.getRandomValues(new Uint8Array(65536)));
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