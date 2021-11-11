import {concatTA, assert, ba2int, expandRange} from './../utils.js';

export class Garbler{
  // class Garbler implements the role of the client as the garbler
  s;
  garbledC;

  constructor(parent){
    // this.s is the TWOPC class
    this.s = parent; 
    // this.garbledC will contain truth table, output labels and input labels for each
    // circuit after it is garbled
    this.garbledC = []; 
  }

  async getAllB(allB){
    let fixedCount = 0;
    let nonFixedCount = 0;

    for (let i = 1; i < this.s.cs.length; i++) {
      if (i !== 6){
        fixedCount += this.s.cs[i].notaryFixedInputSize;
      }
      else {
        fixedCount += 160 + this.s.C6Count * 128;
      }
      console.log('fixed count for ', i, ' is ', fixedCount);
      nonFixedCount += this.s.cs[i].notaryNonFixedInputSize;
    }
  
    console.log('in getAllB fixedCount, nonFixedCount', fixedCount, nonFixedCount);
    const OT0PoolSize = Math.ceil(nonFixedCount/2 * 1.2);
    const OT1PoolSize = Math.ceil(nonFixedCount/2 * 1.2);
  
    // 4000 OT for OT-ghash
    const expectedLen = (OT0PoolSize + OT1PoolSize + fixedCount  + 6000)*32;
    assert(allB.length === expectedLen);
  
    const fixedBlob = allB.slice(0, fixedCount*32);
    const nonFixedPoolBlob = allB.slice(fixedCount*32);
      
    const encLabels = [];
    let fixedBlobIdx = 0;
    for (let j = 1; j < this.s.cs.length; j++) {
      const c = this.s.cs[j];
      let inputCount = c.notaryFixedInputSize;
      if (j === 6){
        inputCount = 160 + this.s.C6Count * 128;
      }
      assert(inputCount*32 === this.garbledC[j].il.notaryFixed.length);
      for (let i = 0; i < inputCount; i++) {
        const m0 = this.garbledC[j].il.notaryFixed.slice(i*32, i*32+16);
        const m1 = this.garbledC[j].il.notaryFixed.slice(i*32+16, i*32+32);
        const B = fixedBlob.slice(fixedBlobIdx*32, fixedBlobIdx*32+32);
        encLabels.push(this.s.ot.encrypt(m0, m1, B));
        fixedBlobIdx++;
      }
    }
    assert(fixedBlobIdx*32 === fixedBlob.length);
  
    const arrOfB = [];
    for ( let i = 0; i < nonFixedPoolBlob.length/32; i++) {
      arrOfB[i] = nonFixedPoolBlob.slice(i*32, i*32+32);
    }
    await this.s.ot.prepareEncryptionKeys(arrOfB);
    return concatTA(...encLabels);
  }
 
  async garbleAll(){
    // first garble circuit 5 once, so that future invocations can reuse labels
    const rv5 = await this.s.workers[5].garble();

    // garble the rest of the circuits asyncronously
    const allPromises = [];
    for (let cNo =1; cNo < this.s.cs.length; cNo++){
      if (cNo === 5){
        allPromises.push(Promise.resolve('empty'));
        continue;  
      }
      const worker = this.s.workers[cNo];
      allPromises.push(worker.garble());
    }

    // reuse labels of c5 and garble in batches
    const allTt = [new Uint8Array(rv5.tt)];
    const allOl = [new Uint8Array(rv5.ol)];
    const allIl = this.separateLabels(new Uint8Array(rv5.il), 5);
    
    const outputs = await this.s.workers[5].garbleBatch(this.s.C5Count-1, {
      reuseLabels: concatTA(allIl.notaryFixed, allIl.clientNonFixed),
      reuseIndexes: expandRange(0, 320),
      reuseR: new Uint8Array(rv5.R)
    });

    for (let i=0; i < this.s.C5Count-1; i++){
      const out = outputs[i];
      allTt.push(new Uint8Array(out.tt));
      allOl.push(new Uint8Array(out.ol));
      const labels = this.separateLabels(new Uint8Array(out.il), 5);
      allIl.clientFixed = concatTA(allIl.clientFixed, labels.clientFixed);
    }
    this.garbledC[5] = {
      tt: concatTA(...allTt),
      ol: concatTA(...allOl),
      il: allIl};
    
    // all the other circuits have been garbled by now
    const allRv = await Promise.all(allPromises);

    for (let cNo=1; cNo < this.s.cs.length; cNo++){
      const rv = allRv[cNo-1];
      if (cNo === 5){
        // c5 already dealt with
        continue;
      }
      this.garbledC[cNo] = {
        tt: new Uint8Array(rv.tt),
        ol: new Uint8Array(rv.ol),
        il: this.separateLabels(new Uint8Array(rv.il), cNo)};
    }
  }

  getNonFixedEncLabels(idxBlob, cNo){
    const nfis = this.s.cs[cNo].notaryNonFixedInputSize;
    assert(nfis*2 === idxBlob.length);

    const encLabels = [];
    console.time('encryptWithKeyAtIndex');
    for (let i=0; i < nfis; i++){
      const idx = ba2int(idxBlob.subarray(i*2, i*2+2));
      const m0 = this.garbledC[cNo].il.notaryNonFixed.subarray(i*32, i*32+16);
      const m1 = this.garbledC[cNo].il.notaryNonFixed.subarray(i*32+16, i*32+32);
      const encr = this.s.ot.encryptWithKeyAtIndex(m0, m1, idx);
      encLabels.push(encr);
    }
    console.timeEnd('encryptWithKeyAtIndex');
    console.log('encryptWithKeyAtIndex for count:', nfis);

    return concatTA(...encLabels);
  }

  getClientLabels(nonFixedBits, cNo){
    const fixedBits = this.s.cs[cNo].fixedInputs;
    const clientInputs = [].concat(nonFixedBits, fixedBits);
    const inputLabels = [];
    const clientLabelBlob = concatTA(
      this.garbledC[cNo].il.clientNonFixed,
      this.garbledC[cNo].il.clientFixed);
    assert(clientInputs.length*32 == clientLabelBlob.length);

    for (let i=0; i < clientInputs.length; i++){
      const bit = clientInputs[i];
      const label = clientLabelBlob.subarray(i*32+bit*16, i*32+bit*16+16);
      inputLabels.push(label);
    }
    return concatTA(...inputLabels);
  }

  // separate one continuous blob of input labels into 4 blobs as in Labels struct
  separateLabels(blob, cNo) {
    const c = this.s.cs[cNo];
    if (blob.length != (c.notaryInputSize+c.clientInputSize)*32) {
      throw('in separateLabels');
    }
    const labels = {}; 
    let offset = 0;
    labels['notaryNonFixed'] = blob.slice(offset, offset+c.notaryNonFixedInputSize*32);
    offset += c.notaryNonFixedInputSize * 32;

    labels['notaryFixed'] = blob.slice(offset, offset+c.notaryFixedInputSize*32);
    offset += c.notaryFixedInputSize * 32;

    labels['clientNonFixed'] = blob.slice(offset, offset+c.clientNonFixedInputSize*32);
    offset += c.clientNonFixedInputSize * 32;

    labels['clientFixed'] = blob.slice(offset, offset+c.clientFixedInputSize*32);
    offset += c.clientFixedInputSize * 32;
    assert(offset === blob.length);
    return labels;
  }
}


