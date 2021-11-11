import {wait} from './utils.js';

// class FakeFS imitates node.js's fs.readFileSync() by
// reading the files in advance and outputting their content when readFileSync() is called
class FakeFS{
  constructor(){
    this.fileList = {};   // {fileName: <text string>} 
  }
    
  // on init we read all .casm and .txt files in core/twopc/circuits
  async init(){
    const that = this;
    await new Promise(function(resolve) {
      chrome.runtime.getPackageDirectoryEntry(function(root){
        root.getDirectory('core/twopc/circuits', {create: false}, function(dir) {
          dir.createReader().readEntries(async function(results) {
            for (let i=0; i < results.length; i+=1){
              const e = results[i];
              if (e.name.endsWith('.casm') || e.name.endsWith('.txt')){
                const url = chrome.extension.getURL('core/twopc/circuits/'+e.name);
                const resp = await fetch(url);
                const text = await resp.text();
                that.fileList[e.name] = text;
              }
            }
            resolve();
          });
        });
      });
    });
  }

  // feed back all data read in init()
  // eslint-disable-next-line no-unused-vars
  readFileSync(path, _unused){
    return this.fileList[path];
  }
}


// FirstTimeSetup.start() is invoked once on first install. It assembles the circuits,
// serializes them into a compact binary format and stores them in the browser cache.
// All future invocations of Pagesigner use these serialized cached circuits.  
export class FirstTimeSetup{
  async start(pm){
    const worker = new Worker(chrome.extension.getURL('core/twopc/webWorkers/serializeCircuits.js'));
    console.log('parsing circuits, this is done only once on first launch and will take ~30 secs');
    console.time('parsing raw circuits');
    const obj = {};
    const oldfs = window['fs']; 
    window['fs'] = new FakeFS();
    await window['fs'].init();
    // start from the last circuits in order to give the user a quicker initial update
    for (let n=1; n < 7; n++){
      const i = 7-n; 
      const text = CASM.parseAndAssemble('c'+i+'.casm');
      const newobj = await new Promise(function(resolve) {
        worker.onmessage = function(event) {
          let newobj = event.data.obj;
          newobj['gatesBlob'] = new Uint8Array(event.data.blob);
          resolve(newobj);
        };
        worker.postMessage({'text': text});
      });
      obj[i] = newobj;
      pm.update('first_time', {'current': n, 'total': 6});
      await wait(100); // make sure update reaches popup 
    }
    window['fs'] = oldfs;
    console.timeEnd('parsing raw circuits');
    return obj;
  }

  parseCircuitFirstTime(text){
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
        const in1 = this.intToThreeBytes(tokens[tokens.length-4]);
        const in2 = this.intToThreeBytes(tokens[tokens.length-3]);
        const out = this.intToThreeBytes(tokens[tokens.length-2]);
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
        const in1 = this.intToThreeBytes(tokens[tokens.length-3]);
        const out = this.intToThreeBytes(tokens[tokens.length-2]);
        blob.set(in1, blobOffset);
        blobOffset+=3;
        blob.set([0,0,0], blobOffset);
        blobOffset+=3;
        blob.set(out, blobOffset);
        blobOffset+=3;
      }
      else {
        throw('unknown op');
      }
    }
    obj['andGateCount'] = andCount;
    obj['gatesBlob'] = blob;
    return obj;
  }

  intToThreeBytes(i){
    const byteArray = Array(3);
    byteArray[0] = (i >> 16) & 0xFF;
    byteArray[1] = (i >> 8) & 0xFF;
    byteArray[2] = i & 0xFF;
    return byteArray;
  }
}