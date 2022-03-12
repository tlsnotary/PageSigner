/* global chrome */

import WorkerPool from './WorkerPool.js';

export class GCWorker extends WorkerPool{
  // class CGWorker provides convenience functions to speak to the web worker
  constructor(numWorkers, processMonitor, ){
    // you can replace gcworker_wasm.js with gcworker_purejs.js on systems where
    // WebAssembly is not available
    super(numWorkers, chrome.extension.getURL('core/twopc/webWorkers/gcworker_wasm.js'));
    //super(numWorkers, chrome.extension.getURL('core/twopc/webWorkers/gcworker_purejs.js'));
    // pm is an instance of ProcessMonitor
    this.pm = processMonitor;
  }

  // parse text circuit of ArrayBuffer type for all workers
  async parse(circuit_ab){
    const allPromises = [];
    for (let i=0; i < this.workers.length; i++){
      const worker = this.workers[i];
      allPromises.push(new Promise(function(resolve) {
        worker.onmessage = function(event) {
          if (event.data === 'DONE'){
            resolve();
          }
          else {
            throw('unexpected response from worker');
          }
        };
        const obj = {msg: 'parse', circuit: circuit_ab};
        worker.postMessage(obj);
      }));
    }
    return Promise.all(allPromises);
  }

  // garble a circuit (which must have already been parsed)
  async garble(obj){
    const worker = this.workers[0];
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        resolve(event.data);
      };
      worker.postMessage( {msg: 'garble', data: obj});
    });
  }

  // pm is an instance of ProgressMonitor
  async garbleBatch(count){
    const batch = [];
    for (let i=0; i < count; i++){
      // we dont pass any args when garbling
      batch.push({});
    }
    const output = await this.workerPool(batch, this.garbleBatchDoWork, this.pm, 'garbling');
    return output;
  }

  // batchItem is empty because we dont pass any args
  garbleBatchDoWork(batchItem, worker){
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data);
      };
      worker.postMessage( {msg: 'garble'});
    });
  }

  async evaluateBatch(batch){
    return await this.workerPool(batch, this.evaluateBatchDoWork);
  }

  evaluateBatchDoWork(batchItem, worker){
    const il = batchItem[0];
    const tt = batchItem[1];
    const obj = {msg: 'setTruthTables', tt: tt.buffer};
    worker.postMessage(obj);
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data);
      };
      const obj = {msg: 'evaluate', il: il.buffer};
      worker.postMessage(obj);
    });
  }

}