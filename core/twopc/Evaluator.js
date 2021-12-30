export class Evaluator{
  constructor(parent){
    // s is the current session
    this.s = parent;
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