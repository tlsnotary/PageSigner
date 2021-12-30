/* global sodium */

import {assert, getRandom, bytesToBits, concatTA, xor, eq, AESCTRdecrypt,
  sha256, ba2int} from '../utils.js';
import OTCommon from './OTCommon.js';


// class OTSender implements the sender of the Oblivious Transfer acc.to.
// the KOS15 protocol
export class OTSender extends OTCommon{
  constructor(otCount){
    super(); //noop but JS requires it to be called
    this.otCount = otCount;
    this.extraOT = 256; // extended OT which will be sacrificed as part of KOS15 protocol
    this.totalOT = Math.ceil(otCount/8)*8 + this.extraOT;
    this.S = null;
    this.sBits = [];
    this.decrKeys = [];
    this.RQ0 = [];
    this.RQ1 = [];
    // sentSoFar is how many OTs the sender has already sent
    this.sentSoFar = 0;
    // hisCommit is Receiver's commit to the PRG seed
    this.hisCommit = null;
    // seedShare is my xor share of a PRG seed
    this.seedShare = null;
  }

  // part of KOS15
  setupStep1(A, hisCommit){
    this.hisCommit = hisCommit;
    this.seedShare = getRandom(16);
    // Alice computes her Bs and decryption keys based on each bit in S
    this.S = getRandom(16);
    this.sBits = bytesToBits(this.S).reverse();
    const allBs = [];
    this.decrKeys = [];
    for (const bit of this.sBits){
      const b = sodium.crypto_core_ristretto255_scalar_random();
      let B = sodium.crypto_scalarmult_ristretto255_base(b);
      if (bit == 1){
        B = sodium.crypto_core_ristretto255_add(A, B);
      }
      const k = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b, A));
      this.decrKeys.push(k);
      allBs.push(B);
    }
    return [concatTA(...allBs), this.seedShare];
  }


  // part of KOS15
  async setupStep2(encryptedColumnsBlob, receiverSeedShare, x, t){
    assert(receiverSeedShare.length == 16);
    assert(encryptedColumnsBlob.length % 256 == 0);
    const encryptedColumns = [];
    const columnSize = encryptedColumnsBlob.length/256;
    for (let i=0; i < 256; i++){
      encryptedColumns.push(encryptedColumnsBlob.slice(i*columnSize, (i+1)*columnSize));
    }
    // Decrypt only those columns which correspond to S's bit
    const columns = [];
    for (let i=0; i < 128; i++){
      const col0 = encryptedColumns[i*2];
      const col1 = encryptedColumns[i*2+1];
      if (this.sBits[i] == 0){
        columns.push(await AESCTRdecrypt(this.decrKeys[i], col0));
      } else {
        columns.push(await AESCTRdecrypt(this.decrKeys[i], col1));
      }
    }
    const Q0 = this.transposeMatrix(columns);

    // KOS15: Alice multiplies every 128-bit row of matrix Q1 with the corresponding random
    // value in expandedSeed and XORs the products
    assert(eq(await sha256(receiverSeedShare), this.hisCommit), 'Bad seed commit');
    const seed = xor(receiverSeedShare, this.seedShare);
    const expandedSeed = await this.expandSeed(seed, this.totalOT);
    let q = new Uint8Array(32).fill(0);
    for (let i=0; i < Q0.length; i++){
      const rand = expandedSeed.subarray(i*16, (i+1)*16);
      q = xor(q, this.clmul128(Q0[i], rand));
    }
    // Alice checks that t = q xor x * S
    assert(eq(t, xor(q, this.clmul128(x, this.S))));

    // Alice xors each row of Q0 with S to get Q1
    const Q1 = [];
    for (let i=0; i < Q0.length; i++){
      Q1.push(xor(Q0[i], this.S));
    }

    // we need to break correlations between Q0 and Q1
    // The last extraOTs were sacrificed as part of the KOS15 protocol
    // and so we don't need them anymore
    console.log('start breakCorrelation');
    this.RQ0 = await this.breakCorrelation(Q0.slice(0, -this.extraOT));
    this.RQ1 = await this.breakCorrelation(Q1.slice(0, -this.extraOT));
    console.log('end breakCorrelation');
    // now we have instances of Random OT where depending on r's bit,
    // each row in RT0 equals to a row either in RQ0 or RQ1
    console.log('done 2');
    // in Steps 5,6,7 we will use Beaver Derandomization to convert
    // randomOT into standardOT
  }


  // processRequest performs Beaver Derandomization:
  // for every bit in bitsToFlip, the Sender has two 16-byte messages for 1-of-2 OT and
  // two random masks (from the KOS15 protocol) r0 and r1
  // if the bit is 0, the Sender sends (m0 xor r0) and (m1 xor r1),
  // if the bit is 1, the Sender sends (m0 xor r1) and (m1 xor r0)
  processRequest(bitsBlob, messages){
    const dropCount = ba2int(bitsBlob.slice(0, 1));
    const bitsToFlipWithRem = bytesToBits(bitsBlob.slice(1));
    const bitsToFlip = bitsToFlipWithRem.slice(0, bitsToFlipWithRem.length-dropCount);
    assert(this.sentSoFar + bitsToFlip.length <= this.otCount);
    assert(bitsToFlip.length*32 == messages.length);
    const encodedToSend = [];
    for (let i=0; i < bitsToFlip.length; i++){
      const m0 = messages.slice(i*32, i*32+16);
      const m1 = messages.slice(i*32+16, i*32+32);
      const r0 = this.RQ0.slice((this.sentSoFar+i)*16, (this.sentSoFar+i)*16+16);
      const r1 = this.RQ1.slice((this.sentSoFar+i)*16, (this.sentSoFar+i)*16+16);
      if (bitsToFlip[i] == 0){
        encodedToSend.push(xor(m0, r0));
        encodedToSend.push(xor(m1, r1));
      } else {
        encodedToSend.push(xor(m0, r1));
        encodedToSend.push(xor(m1, r0));
      }
    }
    this.sentSoFar += bitsToFlip.length;
    return concatTA(...encodedToSend);
  }
}