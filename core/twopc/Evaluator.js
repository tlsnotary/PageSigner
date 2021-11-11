export class Evaluator{
  constructor(parent){
    // s is the current session
    this.s = parent;
  }
    
  getNonFixedLabels(encLabels, otKeys, nonFixedBits){
    const nonFixedLabels = [];
    for (let i = 0; i < nonFixedBits.length; i += 1) {
      const bit = nonFixedBits[i];
      const ct = encLabels.slice(i * 32, (i+1) * 32);
      const inputLabel = this.s.ot.decryptWithKey(ct, bit, otKeys[i]);
      nonFixedLabels.push(inputLabel);
    }
    return nonFixedLabels;
  }


  async evaluateBatch(batch, cNo){
    const outputs = await this.s.workers[cNo].evaluateBatch(batch);
    const parsed = [];
    for (let i=0; i < batch.length; i++){
      parsed.push(new Uint8Array(outputs[i]));
    }
    return parsed;
  }
  
}