// note that unlike with GCWorker class, the caller of OTWorker's methods doesn't have
// to manage the worker pool. We manage them internally inside the class.
import {bitsToBytes, concatTA, assert} from './../utils.js';

import WorkerPool from './WorkerPool.js';

export class OTWorker extends WorkerPool{
  constructor(numWorkers){
    super(numWorkers, chrome.extension.getURL('core/twopc/webWorkers/otworker.js'));
  }

  async saveDecryptionKeys(bits, A){
    let padCount = 0;
    if (bits.length % 8 > 0){
      // make bits length a multiple of 8
      padCount = 8 - bits.length % 8;
      bits.push(...Array(padCount).fill(0));
    }
    const bytes = bitsToBytes(bits);
    // put chunks of 128 bytes into a batch
    const batch = [];
    const chunkSize = 128;
    for (let i=0; i < Math.ceil(bytes.length/chunkSize); i++){
      batch.push([bytes.slice(i*chunkSize, (i+1)*chunkSize), A]);
    }
    const outputs = await this.workerPool(batch, this.saveDecryptionKeysDoWork);
    const arrOutput = [];
    for (let i=0; i < batch.length; i++){
      arrOutput[i] = new Uint8Array(outputs[batch.length-1-i]);
    }
    const dataBlob = concatTA(...arrOutput);
    assert(dataBlob.length === bits.length*48);
    // deserialize data
    const entries = [];
    for (let i=0; i < bits.length; i++){
      const k = dataBlob.slice(i*48, i*48+16);
      const B = dataBlob.slice(i*48+16, i*48+48);
      entries.push([k,B]);
    }
    return entries.slice(0, entries.length-padCount);
  }

  async precomputePool(count, A){
    // chunk up into 512 items and put chunks into a batch
    const batch = [];
    const chunkSize = 512;
    const chunkCount = Math.ceil(count/chunkSize);
    const lastChunkSize = count - (chunkSize * (chunkCount-1));
    for (let i=0; i < chunkCount; i++){
      if (i === chunkCount-1){
        batch.push([lastChunkSize, A]);    
      }
      else{
        batch.push([chunkSize, A]);    
      }
    }
    const outputs = await this.workerPool(batch, this.precomputePoolDoWork);
    const arrOutput = [];
    for (let i=0; i < batch.length; i++){
      arrOutput[i] = new Uint8Array(outputs[i]);
    }
    // deserialize data
    const entries0 = [];
    const entries1 = [];
    for (let i=0; i < arrOutput.length; i++){
      const size = (i < (chunkCount-1)) ? chunkSize : lastChunkSize; 
      const batch = arrOutput[i];
      for (let j=0; j < size*2; j++){
        const k = batch.slice(j*48, j*48+16);
        const B = batch.slice(j*48+16, j*48+48);
        if (j < size){
          entries0.push([k,B]);
        }
        else {
          entries1.push([k,B]);
        }   
      }
    }
    const allEntries = [].concat(entries0, entries1);
    assert(allEntries.length === count*2);
    return allEntries;
  }

  async prepareEncryptionKeys(arrOfB, a, A){
    const batch = [];
    const chunkSize = 1024;
    const chunkCount = Math.ceil(arrOfB.length/chunkSize);
    for (let i=0; i < chunkCount; i++){
      batch.push([concatTA(...arrOfB.slice(i*chunkSize, (i+1)*chunkSize)), a, A]);    
    }
    const outputs = await this.workerPool(batch, this.prepareEncryptionKeysDoWork);
    const arrOutput = [];
    for (let i=0; i < batch.length; i++){
      arrOutput[i] = new Uint8Array(outputs[i]);
    }
    const dataBlob = concatTA(...arrOutput);
    assert(dataBlob.length === arrOfB.length*32);
    // deserialize data
    const entries = [];
    for (let i=0; i < arrOfB.length; i++){
      const k0 = dataBlob.slice(i*32, i*32+16);
      const k1 = dataBlob.slice(i*32+16, i*32+32);
      entries.push([k0,k1]);
    }
    return entries;
  }

  prepareEncryptionKeysDoWork(batchItem, worker){
    const bytes = batchItem[0];
    const a = batchItem[1];
    const A = batchItem[2];
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data.blob);
      };
      const obj = {msg:'prepareEncryptionKeys', data:{bytes:bytes.buffer, a:a.buffer, A:A.buffer}};
      worker.postMessage(obj);
    });
  }

  precomputePoolDoWork(batchItem, worker){
    const count = batchItem[0];
    const A = batchItem[1];
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data.blob);
      };
      const obj = {msg:'precomputePool', data:{count:count, A:A.buffer}};
      worker.postMessage(obj);
    });
  }

  saveDecryptionKeysDoWork(batchItem, worker){
    const bytes = batchItem[0];
    const A = batchItem[1];
    return new Promise(function(resolve) {
      worker.onmessage = function(event) {
        worker['isResolved'] = true;
        resolve(event.data.blob);
      };
      const obj = {msg:'saveDecryptionKeys', data:{bytes:bytes.buffer, A:A.buffer}};
      worker.postMessage(obj);
    });
  }
}