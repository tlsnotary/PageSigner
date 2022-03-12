/* global process, global */

// gcworker_wasm.js is a WebWorker which performs garbling and evaluation
// of garbled circuits.
// This is a fixed-key-cipher garbling method from BHKR13 https://eprint.iacr.org/2013/426.pdf

// eslint-disable-next-line no-undef
let parentPort_;
let loadFile;
let module;
let circuit = null;
let truthTables = null;


// offsets are set once for the life of the wasm module
let malloc_ptr;
// cryptographically random data
let randOffset, randSize;
// output (for garbler this is decoding table,
// for evaluator this is encoded output)
let outOffset, outSize;
// truth tables
let ttOffset, ttSize;
// input labels
let ilOffset, ilSize;
let wasm = null;

// fixedKey is used by randomOracle(). We need a 32-byte key because we use Salsa20. The last 4
// bytes will be filled with the index of the circuit's wire.
const fixedKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]);
// sigma is Salsa's constant "expand 32-byte k"
const sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98,
  121, 116, 101, 32, 107]);
var crypto_;

if (typeof(importScripts) !== 'undefined') {
  crypto_ = self.crypto;
  crypto_.getRandomValues = function(arr){
    return new Uint8Array([...Array(arr.length).keys()]);
  };
  loadFile = loadFileBrowser;
  self.onmessage = function(event) {
    processMessage(event.data);
  };
} else {
  // we are in nodejs
  import('module').then((mod) => {
    module = mod;
    // we cannot use the "import" keyword here because on first pass the browser unconditionaly
    // parses this if clause and will error out if "import" is found.
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
    loadFile = loadFileNode;
    parentPort.on('message', msg => {
      processMessage(msg);
    });
  });
}

async function loadFileBrowser(path) {
  const bytes = await fetch(path);
  return bytes.arrayBuffer();
}

async function loadFileNode(file) {
  const filePath = 'file://' + process.argv[1];
  // this workaround allows to require() from ES6 modules, which is not allowed by default
  const require = module.createRequire(filePath);
  const path = require('path');
  const dir = path.dirname(process.argv[1]);
  const fs = require('fs');
  const data = fs.readFileSync(path.join(dir, file));
  return data;
}

function processMessage(obj){
  const msg = obj.msg;
  // parse is called only once for the duration of the wasm module, even if
  // multiple garbling executions will be made.
  if (msg === 'parse'){
    circuit = obj.circuit;

    loadFile('garbler.wasm').then(async function(ab){
      // we don't need to allocate any heap memory
      const memory = new WebAssembly.Memory({initial:0, maximum:0});
      const module = await WebAssembly.instantiate(ab, { js: {memory: memory}});
      wasm = module.instance.exports;
      assert(circuit.gatesBlob.length == circuit.gatesCount*10);
      malloc_ptr = wasm.initAll(
        circuit.gatesCount,
        circuit.wiresCount,
        circuit.notaryInputSize,
        circuit.clientInputSize,
        circuit.outputSize,
        circuit.andGateCount
      );
      let offset = malloc_ptr;
      // ipc1 and ipc2
      offset += (20+48);

      const gateSize = circuit.gatesCount*10;
      const gatesBytesArr = new Uint8Array(wasm.memory.buffer, offset, gateSize);
      offset += gateSize;
      gatesBytesArr.set(circuit.gatesBlob);
      console.time('parse blob');
      wasm.parseGatesBlob();
      console.timeEnd('parse blob');

      randOffset = offset;
      randSize = (circuit.notaryInputSize + circuit.clientInputSize + 1)*16;
      offset += randSize;

      outOffset = offset;
      outSize = Math.ceil(circuit.outputSize/8);
      offset += outSize;

      ttOffset = offset;
      ttSize = circuit.andGateCount*48;
      offset += ttSize;

      ilOffset = offset;
      ilSize = (circuit.notaryInputSize + circuit.clientInputSize)*32;
      offset += ilSize;
      postMsg('DONE');
    });
  }
  else if (msg === 'setTruthTables'){
    assert(obj.tt.byteLength == circuit.andGateCount*48);
    truthTables = new Uint8Array(obj.tt);
  }
  else if (msg === 'garble'){
    if (circuit == null){
      console.log('error: need to parse circuit before garble');
      return;
    }
    console.time('garbling done in');
    let randArr = new Uint8Array(wasm.memory.buffer, randOffset, randSize);
    randArr.set(crypto_.getRandomValues(new Uint8Array(randSize)));
    const dataBuf = new Uint8Array(wasm.memory.buffer, malloc_ptr, 16);
    const tweak = new Uint8Array(wasm.memory.buffer, malloc_ptr+16, 4);
    const in1 = new Uint8Array(wasm.memory.buffer, malloc_ptr+20, 16);
    const in2 = new Uint8Array(wasm.memory.buffer, malloc_ptr+20+16, 16);
    const in3 = new Uint8Array(wasm.memory.buffer, malloc_ptr+20+32, 16);
    wasm.startGarbler();
    for (let i=0; i < circuit.andGateCount; i++){
      wasm.resumeGarbler_0();
      Salsa20(dataBuf, tweak);
      wasm.resumeGarbler_1();
      Salsa20(in1, tweak);
      Salsa20(in2, tweak);
      Salsa20(in3, tweak);
    }
    wasm.finishGarbler();
    const inputLabels = new Uint8Array(wasm.memory.buffer, ilOffset, ilSize).slice();
    const truthTables = new Uint8Array(wasm.memory.buffer, ttOffset, ttSize).slice();
    const decodingTable = new Uint8Array(wasm.memory.buffer, outOffset, outSize).slice();
    const obj = {'il': inputLabels.buffer, 'tt': truthTables.buffer, 'dt': decodingTable.buffer};
    console.timeEnd('garbling done in');
    postMsg(obj, [inputLabels.buffer, truthTables.buffer, decodingTable.buffer]);
  }
  else if (msg === 'evaluate'){
    if (circuit == null || truthTables == null){
      console.log('error: need to parse circuit and set truth table before evaluate');
      return;
    }
    const inputLabels = new Uint8Array(obj.il);
    assert (inputLabels.length === circuit.clientInputSize*16 + circuit.notaryInputSize*16);
    const ilArr = new Uint8Array(wasm.memory.buffer, ilOffset, inputLabels.length);
    ilArr.set(inputLabels);
    const ttArr = new Uint8Array(wasm.memory.buffer, ttOffset, ttSize);
    ttArr.set(truthTables);
    const dataBuf = new Uint8Array(wasm.memory.buffer, malloc_ptr, 16);
    const tweak = new Uint8Array(wasm.memory.buffer, malloc_ptr+16, 4);
    wasm.startEvaluator();
    for (let i=0; i < circuit.andGateCount; i++){
      wasm.resumeEvaluator_0();
      Salsa20(dataBuf, tweak);
    }
    wasm.finishEvaluator();
    const encodedOutput = new Uint8Array(wasm.memory.buffer, outOffset, outSize).slice();
    postMsg(encodedOutput.buffer);
    truthTables == null;
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





function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || 'Assertion failed';
  }
}


// use Salsa20 as a random permutator. Instead of the nonce, we feed the data that needs
// to be permuted. The output will be placed into data;
function Salsa20(data, t){
  core_salsa20(data, fixedKey, t, sigma);
  return data;
}

// copied from https://github.com/dchest/tweetnacl-js/blob/master/nacl-fast.js
// and modified to reuse input (p) as output and to output only 16 bytes. Also allows
// to input a 28-byte key (k) and a 4-byte tweak (t).
// modified parts are commented out
// function core_salsa20(o, p, k, c) {
function core_salsa20(p, k, t, c) {
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
    //j14 = k[28] & 0xff | (k[29] & 0xff)<<8 | (k[30] & 0xff)<<16 | (k[31] & 0xff)<<24,
    // the commented out line was replaced with the line below
    j14 = t[0] & 0xff  | (t[1] & 0xff)<<8  | (t[2] & 0xff)<<16  | (t[3] & 0xff)<<24,
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
  // x4 =  x4 +  j4 | 0;
  // x5 =  x5 +  j5 | 0;
  // x6 =  x6 +  j6 | 0;
  // x7 =  x7 +  j7 | 0;
  // x8 =  x8 +  j8 | 0;
  // x9 =  x9 +  j9 | 0;
  // x10 = x10 + j10 | 0;
  // x11 = x11 + j11 | 0;
  // x12 = x12 + j12 | 0;
  // x13 = x13 + j13 | 0;
  // x14 = x14 + j14 | 0;
  // x15 = x15 + j15 | 0;

  p[ 0] = x0 >>>  0 & 0xff;
  p[ 1] = x0 >>>  8 & 0xff;
  p[ 2] = x0 >>> 16 & 0xff;
  p[ 3] = x0 >>> 24 & 0xff;

  p[ 4] = x1 >>>  0 & 0xff;
  p[ 5] = x1 >>>  8 & 0xff;
  p[ 6] = x1 >>> 16 & 0xff;
  p[ 7] = x1 >>> 24 & 0xff;

  p[ 8] = x2 >>>  0 & 0xff;
  p[ 9] = x2 >>>  8 & 0xff;
  p[10] = x2 >>> 16 & 0xff;
  p[11] = x2 >>> 24 & 0xff;

  p[12] = x3 >>>  0 & 0xff;
  p[13] = x3 >>>  8 & 0xff;
  p[14] = x3 >>> 16 & 0xff;
  p[15] = x3 >>> 24 & 0xff;
  // we only need 16 bytes of the output

  // o[ 0] = x0 >>>  0 & 0xff;
  // o[ 1] = x0 >>>  8 & 0xff;
  // o[ 2] = x0 >>> 16 & 0xff;
  // o[ 3] = x0 >>> 24 & 0xff;

  // o[ 4] = x1 >>>  0 & 0xff;
  // o[ 5] = x1 >>>  8 & 0xff;
  // o[ 6] = x1 >>> 16 & 0xff;
  // o[ 7] = x1 >>> 24 & 0xff;

  // o[ 8] = x2 >>>  0 & 0xff;
  // o[ 9] = x2 >>>  8 & 0xff;
  // o[10] = x2 >>> 16 & 0xff;
  // o[11] = x2 >>> 24 & 0xff;

  // o[12] = x3 >>>  0 & 0xff;
  // o[13] = x3 >>>  8 & 0xff;
  // o[14] = x3 >>> 16 & 0xff;
  // o[15] = x3 >>> 24 & 0xff;

  // o[16] = x4 >>>  0 & 0xff;
  // o[17] = x4 >>>  8 & 0xff;
  // o[18] = x4 >>> 16 & 0xff;
  // o[19] = x4 >>> 24 & 0xff;

  // o[20] = x5 >>>  0 & 0xff;
  // o[21] = x5 >>>  8 & 0xff;
  // o[22] = x5 >>> 16 & 0xff;
  // o[23] = x5 >>> 24 & 0xff;

  // o[24] = x6 >>>  0 & 0xff;
  // o[25] = x6 >>>  8 & 0xff;
  // o[26] = x6 >>> 16 & 0xff;
  // o[27] = x6 >>> 24 & 0xff;

  // o[28] = x7 >>>  0 & 0xff;
  // o[29] = x7 >>>  8 & 0xff;
  // o[30] = x7 >>> 16 & 0xff;
  // o[31] = x7 >>> 24 & 0xff;

  // o[32] = x8 >>>  0 & 0xff;
  // o[33] = x8 >>>  8 & 0xff;
  // o[34] = x8 >>> 16 & 0xff;
  // o[35] = x8 >>> 24 & 0xff;

  // o[36] = x9 >>>  0 & 0xff;
  // o[37] = x9 >>>  8 & 0xff;
  // o[38] = x9 >>> 16 & 0xff;
  // o[39] = x9 >>> 24 & 0xff;

  // o[40] = x10 >>>  0 & 0xff;
  // o[41] = x10 >>>  8 & 0xff;
  // o[42] = x10 >>> 16 & 0xff;
  // o[43] = x10 >>> 24 & 0xff;

  // o[44] = x11 >>>  0 & 0xff;
  // o[45] = x11 >>>  8 & 0xff;
  // o[46] = x11 >>> 16 & 0xff;
  // o[47] = x11 >>> 24 & 0xff;

  // o[48] = x12 >>>  0 & 0xff;
  // o[49] = x12 >>>  8 & 0xff;
  // o[50] = x12 >>> 16 & 0xff;
  // o[51] = x12 >>> 24 & 0xff;

  // o[52] = x13 >>>  0 & 0xff;
  // o[53] = x13 >>>  8 & 0xff;
  // o[54] = x13 >>> 16 & 0xff;
  // o[55] = x13 >>> 24 & 0xff;

  // o[56] = x14 >>>  0 & 0xff;
  // o[57] = x14 >>>  8 & 0xff;
  // o[58] = x14 >>> 16 & 0xff;
  // o[59] = x14 >>> 24 & 0xff;

  // o[60] = x15 >>>  0 & 0xff;
  // o[61] = x15 >>>  8 & 0xff;
  // o[62] = x15 >>> 16 & 0xff;
  // o[63] = x15 >>> 24 & 0xff;
}
