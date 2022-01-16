/* global process*/

// Serializes the circuit into a compact representation

if (typeof(importScripts) === 'undefined'){
  // we are in nodejs
  import('module').then((module) => {
    // we cannot use the "import" keyword here because on first pass the browser unconditionaly
    // parses this if clause and will error out if "import" is found
    // using process.argv instead of import.meta.url to get the name of this script
    const filePath = 'file://' + process.argv[1];
    // this workaround allows to require() from ES6 modules, which is not allowed by default
    const require = module.createRequire(filePath);
    const { parentPort } = require('worker_threads');
    parentPort.on('message', msg => {
      const text = msg.text;
      const [obj, blob] = serializeCircuit(text);
      parentPort.postMessage({data: {'obj': obj, blob: blob.buffer}});
    });
  });
}
else {
  self.onmessage = function(event) {
    const text = event.data.text;
    const [obj, blob] = serializeCircuit(text);
    postMessage({'obj': obj, blob: blob.buffer});
  };
}


function serializeCircuit(text){
  const obj = {};
  // we don't do any sanity/formatting checks because the circuits
  // were output by casm.js and have a well-defined structure
  const rows = text.split('\n');
  obj['gatesCount'] = Number(rows[0].split(' ')[0]);
  console.log('obj[\'gatesCount\']', obj['gatesCount']);
  obj['wiresCount'] = Number(rows[0].split(' ')[1]);
  obj['notaryInputSize'] = Number(rows[1].split(' ')[1]);
  obj['clientInputSize'] = Number(rows[1].split(' ')[2]);
  obj['outputSize'] = Number(rows[2].split(' ')[1]);

  // each gate is serialized as
  // 1 byte: gate type XOR==0 AND==1 INV==2
  // 3 bytes: 1st input wire number
  // 3 bytes: 2nd input wire number
  // 3 bytes: output wire number
  const gateByteSize = 10;
  const opBytes = {'XOR': 0, 'AND': 1, 'INV': 2};
  // first 3 rows are not gates but metadata
  const blob = new Uint8Array((rows.length-3)*gateByteSize);
  let blobOffset = 0;
  let andCount = 0;
  for (let i=0; i < (rows.length-3); i++){
    const gate = rows[3+i];
    const tokens = gate.split(' ');
    const op = tokens[tokens.length-1];
    const opByte = opBytes[op];
    blob.set([opByte], blobOffset);
    blobOffset+=1;
    if (op === 'XOR' || op === 'AND'){
      const in1 = intToThreeBytes(tokens[tokens.length-4]);
      const in2 = intToThreeBytes(tokens[tokens.length-3]);
      const out = intToThreeBytes(tokens[tokens.length-2]);
      blob.set(in1, blobOffset);
      blobOffset+=3;
      blob.set(in2, blobOffset);
      blobOffset+=3;
      blob.set(out, blobOffset);
      blobOffset+=3;
      if (op == 'AND'){
        andCount+=1;
      }
    }
    else if (op === 'INV'){
      const in1 = intToThreeBytes(tokens[tokens.length-3]);
      const out = intToThreeBytes(tokens[tokens.length-2]);
      blob.set(in1, blobOffset);
      blobOffset+=3;
      blob.set([0, 0, 0], blobOffset);
      blobOffset+=3;
      blob.set(out, blobOffset);
      blobOffset+=3;
    }
    else {
      throw('unknown op');
    }
  }
  obj['andGateCount'] = andCount;
  return [obj, blob];
}

function intToThreeBytes(i){
  const byteArray = Array(3);
  byteArray[0] = (i >> 16) & 0xFF;
  byteArray[1] = (i >> 8) & 0xFF;
  byteArray[2] = i & 0xFF;
  return byteArray;
}
