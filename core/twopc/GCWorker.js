/* global chrome */

import WorkerPool from './WorkerPool.js';

export class GCWorker extends WorkerPool{
  // class CGWorker provides convenience functions to speak to the web worker
  constructor(numWorkers, processMonitor){
    super(numWorkers, chrome.extension.getURL('core/twopc/webWorkers/gcworker.js'));
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
            console.log('unexpected response from worker');
            throw('unexpected response from worker');
          }
        };
        const obj = {msg: 'parse', data: circuit_ab};
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
  async garbleBatch(count, obj){
    const batch = [];
    for (let i=0; i < count; i++){
      batch.push(obj);
    }
    const output = await this.workerPool(batch, this.garbleBatchDoWork, this.pm, 'garbling');
    return output;
  }

  garbleBatchDoWork(batchItem, worker){
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data);
      };
      worker.postMessage( {msg: 'garble', data: batchItem});
    });
  }

  async evaluateBatch(batch){
    //const output = await this.workerPool(batch, this.evaluateBatchDoWork, this.pm, 'evaluating');
    const output = await this.workerPool(batch, this.evaluateBatchDoWork);
    return output;
  }

  evaluateBatchDoWork(batchItem, worker){
    const ga = batchItem[0];
    const tt = batchItem[1];
    const obj = {msg: 'setTruthTable', data: tt.buffer};
    worker.postMessage(obj);
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data);
      };
      const obj = {msg: 'evaluate', data: ga.buffer};
      worker.postMessage(obj);
    });
  }

}