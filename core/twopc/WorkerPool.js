// class WorkerPool assigns work from a batch to multiple Web Workers

export default class WorkerPool{
  constructor(numWorkers, url){
    this.workers = [];
    for (let i=0; i < numWorkers; i++){
      this.workers[i] = new Worker(url);
      this.setIsResolved(i, true);
      this.setRoundNo(i, -1);
    }
  }
  // for each item in batch call the function doWork which has a signature
  // doWork(batchItem, worker) where batchItem is the next item of batch
  // and worker is a free worker from the pool. doWork must return a promise
  // which resolves to the output
  // optional arguments are:
  // pm is in instance of ProgressMonitor
  // pmtype is the type of progress monitoring. Can be either 'garbling' or 'evaluating'
  async workerPool(batch, doWork, pm, pmtype){
    const promises = [];
    const outputs = {};
    const workerCount = this.workers.length;
    for (let c = 0; c < workerCount; c++){
      // start with Promises in resolved state
      promises.push(Promise.resolve('empty'));
    }
    for (let i=0; i < batch.length; i++){
      // console.log('round ', i);
      // wait until we have a free worker
      const out = await Promise.any(promises);
      if (pm){pm.update(pmtype, {'current': i+1, 'total': batch.length});}
      // find which worker resolved
      let worker = null;
      let idx = null;
      for (idx = 0; idx < workerCount; idx++){
        if (this.getIsResolved(idx) === true){
          worker = this.workers[idx];
          break;
        }
      }
      if (worker === null){
        throw('panic: no worker is marked as resolved');
      }
      // save the worker's output
      outputs[this.getRoundNo(idx)] = out;
      // give the worker new work
      this.setIsResolved(idx, false);
      this.setRoundNo(idx, i);
      const promise = doWork(batch[i], worker);
      promises[idx] = promise;
    }
    // waiting for last "workerCount" workers to finish
    const rv = await Promise.all(promises);
    for (let idx = 0; idx < workerCount; idx++){
      outputs[this.getRoundNo(idx)] = rv[idx];
    }
    return outputs;
  }

  setIsResolved(idx, flag){
    this.workers[idx]['isResolved'] = flag;
  }

  getIsResolved(idx){
    return this.workers[idx]['isResolved'];
  }

  setRoundNo(idx, no){
    this.workers[idx]['roundNo'] = no;
  }

  getRoundNo(idx){
    return this.workers[idx]['roundNo'];
  }

}
