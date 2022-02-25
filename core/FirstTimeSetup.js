/* global chrome, CASM*/

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
    const url = chrome.extension.getURL('core/twopc/webWorkers/serializeCircuits.js');
    const worker = new Worker(url);
    console.log('Parsing circuits. This is done only once on first launch and will take ~30 secs');
    console.time('time_to_parse');
    const obj = {};
    if (typeof(window) !== 'undefined') {
      // we are in the browser; init a fake filesystem
      window['fs'] = new FakeFS();
      await window['fs'].init();
    }
    // start from the last circuits in order to give the user a quicker initial update
    for (let n=1; n < 8; n++){
      const i = 8-n;
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
      if (pm) pm.update('first_time', {'current': n, 'total': 7});
      await wait(100); // make sure update reaches popup
    }
    console.timeEnd('time_to_parse');
    return obj;
  }
}
