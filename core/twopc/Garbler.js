import {concatTA, assert} from './../utils.js';

// class Garbler implements the role of the client as the garbler
export class Garbler{
  constructor(parent){
    // this.s is the TWOPC class
    this.s = parent;
    // this.garbledC will contain truth table, output labels and input labels for each
    // circuit after it is garbled
    this.garbledC = [];
  }

  async garbleAll(){
    // we don't parallelize garbling of non-c5 circuits, we garble them
    // one by one
    const allPromises = [];
    for (let cNo = 1; cNo < this.s.cs.length; cNo++){
      if (cNo === 5){
        allPromises.push(Promise.resolve('empty'));
        continue;
      }
      const worker = this.s.workers[cNo];
      allPromises.push(worker.garble());
    }

    const allTt = [];
    const allOl = [];
    const allIl = [];
    // while non-c5 circuits are being garbled, we saturate the CPU with
    // parallel garbling of c5
    const outputs = await this.s.workers[5].garbleBatch(this.s.C5Count, {});
    for (let i=0; i < this.s.C5Count; i++){
      const out = outputs[i];
      allTt.push(new Uint8Array(out.tt));
      allOl.push(new Uint8Array(out.ol));
      allIl.push(new Uint8Array(out.il));
    }
    this.garbledC[5] = {
      tt: concatTA(...allTt),
      ol: concatTA(...allOl),
      il: concatTA(...allIl)};

    // all non-c5 circuits have been garbled by now
    const allRv = await Promise.all(allPromises);

    for (let cNo=1; cNo < this.s.cs.length; cNo++){
      const rv = allRv[cNo-1];
      if (cNo === 5){
        continue; // c5 already dealt with
      }
      this.garbledC[cNo] = {
        tt: new Uint8Array(rv.tt),
        ol: new Uint8Array(rv.ol),
        il: new Uint8Array(rv.il)};
    }
  }

  // Notary's inputs are always the first inputs in the circuit
  getNotaryLabels(cNo){
    // exeCount is how many executions of this circuit we need
    const exeCount = [0, 1, 1, 1, 1, this.s.C5Count, this.s.C6Count][cNo];
    const il = this.garbledC[cNo].il;
    const c = this.s.cs[cNo];
    const ilArray = [];
    // chunkSize is the bytesize of input labels for one circuit
    const chunkSize = (c.notaryInputSize+c.clientInputSize)*32;
    assert(chunkSize*exeCount == il.length);
    for (let i=0; i < exeCount; i++){
      ilArray.push(il.slice(i*chunkSize, i*chunkSize+c.notaryInputSize*32));
    }
    return concatTA(...ilArray);
  }

  // Client's inputs always come after the Notary's inputs in the circuit
  getClientLabels(clientInputs, cNo){
    const repeatCount = [0, 1, 1, 1, 1, this.s.C5Count, this.s.C6Count][cNo];
    const il = this.garbledC[cNo].il;
    const c = this.s.cs[cNo];
    const ilArray = [];
    // chunkSize is the bytesize of input labels for one circuit
    const chunkSize = (c.notaryInputSize+c.clientInputSize)*32;
    assert(chunkSize*repeatCount == il.length);
    for (let i=0; i < repeatCount; i++){
      ilArray.push(il.slice(i*chunkSize+c.notaryInputSize*32, (i+1)*chunkSize));
    }
    const clientLabelBlob = concatTA(...ilArray);
    assert(clientInputs.length*32 == clientLabelBlob.length);
    const out = [];
    for (let i=0; i < clientInputs.length; i++){
      const bit = clientInputs[i];
      const label = clientLabelBlob.subarray(i*32+bit*16, i*32+bit*16+16);
      out.push(label);
    }
    return concatTA(...out);
  }
}


