// otworker.js is a WebWorker where most of the heavy computations for
// Oblivious Transfer happen. Based on Chou-Orlandi "Simplest OT"

var sodium
var parentPort_;


if (typeof(importScripts) === 'undefined'){
  // we are in nodejs
  import('module').then((module) => {
    // we cannot use the "import" keyword here because on first pass the browser unconditionaly
    // parses this if clause and will error out if "import" is found
    // using process.argv instead of import.meta.url to get the name of this script
    const filePath = 'file://' + process.argv[1];
    // this workaround allows to require() from ES6 modules, which is not allowed by default 
    const require = module.createRequire(filePath)
    const { parentPort } = require('worker_threads');
    parentPort_ = parentPort
    sodium = require('libsodium-wrappers-sumo');
    parentPort.on('message', msg => {
      processMessage(msg);
    })
  })
} else {
  importScripts('./../../third-party/sodium.js');
  self.onmessage = function(event) {
    processMessage(event.data);
  };
}


function processMessage(obj){
  const msg = obj.msg;
  const data = obj.data;
  if (msg === 'saveDecryptionKeys'){
    const bytes = new Uint8Array(data.bytes);
    const A = new Uint8Array(data.A);
    const rv = saveDecryptionKeys(bytes, A);
    postMsg({'blob': rv.buffer});

  }
  else if (msg === 'precomputePool'){
    const count = data.count;
    const A = new Uint8Array(data.A);
    const rv = precomputePool(count, A);
    postMsg({'blob': rv.buffer});
  }
  else if (msg === 'prepareEncryptionKeys'){
    const bytes = new Uint8Array(data.bytes);
    const a = new Uint8Array(data.a, data.A);
    const A = new Uint8Array(data.A);
    const rv = prepareEncryptionKeys(bytes, a, A);
    postMsg({'blob': rv.buffer});
  }
}


function postMsg(value, transferList){
  if (typeof importScripts !== 'function'){
    parentPort_.postMessage({data:value}, transferList)
  } else {
    postMessage(value, transferList);
  }
}


function prepareEncryptionKeys(bytes, a, A){
  const blob = [];
  const Bcount = bytes.length/32;
  for (let i=0; i < Bcount; i++){
    const B = bytes.slice(i*32, (i+1)*32);
    const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(a, B)); 
    const sub = sodium.crypto_core_ristretto255_sub(B, A);
    const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(a, sub)); 
    blob.push(k0);
    blob.push(k1);
  }
  return concatTA(...blob);
}

function saveDecryptionKeys(bytes, A){
  const bits = bytesToBits(bytes);
  const blob = [];
  for (const bit of bits){
    if (bit === 0){
      const b0 = sodium.crypto_core_ristretto255_scalar_random();
      const B0 = sodium.crypto_scalarmult_ristretto255_base(b0);
      const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b0, A));
      blob.push(k0);
      blob.push(B0);
    }
    else {
      const b1 = sodium.crypto_core_ristretto255_scalar_random();
      const gb1 = sodium.crypto_scalarmult_ristretto255_base(b1);
      const B1 = sodium.crypto_core_ristretto255_add(A, gb1);
      const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b1, A));
      blob.push(k1);
      blob.push(B1);
    }
  }
  return concatTA(...blob);
}

function precomputePool(count, A){
  const blob = [];
  for (let i = 0; i < count ; i++){
    const b0 = sodium.crypto_core_ristretto255_scalar_random();
    const B0 = sodium.crypto_scalarmult_ristretto255_base(b0);
    const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b0, A));
    blob.push(k0);
    blob.push(B0);
  }
  for (let i = 0; i < count; i++){
    const b1 = sodium.crypto_core_ristretto255_scalar_random();
    const gb1 = sodium.crypto_scalarmult_ristretto255_base(b1);
    const B1 = sodium.crypto_core_ristretto255_add(A, gb1);
    const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b1, A));
    blob.push(k1);
    blob.push(B1);
  }
  return concatTA(...blob);
}

// convert Uint8Array into an array of 0/1 where least bit has index 0
function bytesToBits (ba){
  assert(ba instanceof Uint8Array);
  const bitArr = Array(ba.length*8);
  let idx = 0;
  for (let i=ba.length-1; i >= 0; i--){
    for (let j=0; j < 8; j++){
      bitArr[idx] = (ba[i] >> j) & 0x01;
      idx++;
    }
  }
  return bitArr;
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