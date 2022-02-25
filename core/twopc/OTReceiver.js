/* global sodium */

import {assert, getRandom, bytesToBits, concatTA, sha256, xor, int2ba,
  bitsToBytes, AESCTRencrypt} from '../utils.js';
import OTCommon from './OTCommon.js';

// class OTReceiver implements the receiver of the 1-of-2 Oblivious Transfer.
// run the full KOS15 protocol
export class OTReceiver extends OTCommon{
  constructor(otCount){
    super(); //noop but JS requires it to be called
    this.otCount = otCount;
    this.extraOT = 256; // extended OT which will be sacrificed as part of KOS15 protocol
    this.totalOT = Math.ceil(otCount/8)*8 + this.extraOT;
    // seedShare is my xor share of a PRG seed
    this.seedShare = null;
    this.rbits = [];
    this.T0 = [];
    this.T1 = [];
    this.a = null;
    this.A = null;
    this.RT0 = [];
    // receivedSoFar counts how many bits of OT have been used up by the receiver
    this.receivedSoFar = 0;
    // expectingResponseSize is how many OTs the receiver expects to receive from the sender
    // at this point
    this.expectingResponseSize = 0;
  }

  // run KOS15 to prepare Random OT. Step 1
  async setupStep1(){
    this.seedShare = getRandom(16);
    const seedCommit = await sha256(this.seedShare);
    const r = getRandom(this.totalOT/8);
    const R = this.extend_r(r);
    this.rbits = bytesToBits(r).reverse();
    [this.T0, this.T1] = this.secretShareMatrix(R);
    // for baseOT Bob is the sender, he chooses a and sends A
    this.a = sodium.crypto_core_ristretto255_scalar_random();
    this.A = sodium.crypto_scalarmult_ristretto255_base(this.a);
    return [this.A, seedCommit];
  }

  // run KOS15 to prepare Random OT. Step 2
  async setupStep2(allBsBlob, senderSeedShare){
    // compute key_0 and key_1 for each B of the base OT
    assert(allBsBlob.length == 128*32);
    assert(senderSeedShare.length == 16);
    const encrKeys = [];
    for (let i=0; i < 128; i++){
      const B = allBsBlob.slice(i*32, (i+1)*32);
      const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(this.a, B));
      const sub = sodium.crypto_core_ristretto255_sub(B, this.A);
      const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(this.a, sub));
      encrKeys.push([k0, k1]);
    }
    // Use the i-th k0 to encrypt the i-th column in T0, likewise
    // use the i-th k1 to encrypt the i-th column in T1
    const T0columns = this.transposeMatrix(this.T0);
    const T1columns = this.transposeMatrix(this.T1);
    const encryptedColumns = [];
    for (let i=0; i < 128; i++){
      encryptedColumns.push(await AESCTRencrypt(encrKeys[i][0], T0columns[i]));
      encryptedColumns.push(await AESCTRencrypt(encrKeys[i][1], T1columns[i]));
    }

    // KOS15 kicks in at this point to check if Receiver sent the correct columnsArray
    // combine seed shares and expand the seed
    const seed = xor(this.seedShare, senderSeedShare);
    const expandedSeed = await this.expandSeed(seed, this.totalOT);
    // Bob multiplies every 128-bit row of matrix T1 with the corresponding random
    // value in expandedSeed and XORs the products.
    // Bob multiplies every bit of r with the corresponding random
    // value in expandedSeed and XORs the products.
    // Bob sends seed,x,t to Alice
    let x = new Uint8Array(16).fill(0);
    let t = new Uint8Array(32).fill(0);
    for (let i=0; i < this.T0.length; i++){
      const rand = expandedSeed.subarray(i*16, (i+1)*16);
      if (this.rbits[i] == 1){
        x = xor(x, rand);
      }
      t = xor(t, this.clmul128(this.T0[i], rand));
    }

    // we need to break correlations between Q0 and Q1
    // The last extraOTs were sacrificed as part of the KOS15 protocol
    // and so we don't need them anymore
    console.log('start breakCorrelation');
    this.RT0 = await this.breakCorrelation(this.T0.slice(0, -this.extraOT));
    console.log('end breakCorrelation');
    // also drop the unneeded bytes and bits of r
    this.rbits = this.rbits.slice(0, -this.extraOT);


    // now we have instances of Random OT where depending on r's bit,
    // each row in RT0 equals to a row either in RQ0 or RQ1
    console.log('done 2');
    // use Beaver Derandomization [Beaver91] to convert randomOT into standardOT
    return [concatTA(...encryptedColumns), this.seedShare, x, t];
  }

  // Steps 5, 6 and 7 are repeated for every batch of OT


  // createRequest takes OT receiver's choice bits and instructs the
  // OT sender which random masks need to be flipped (Beaver Derandomization)
  createRequest(choiceBits){
    assert(this.receivedSoFar + choiceBits.length <= this.otCount, 'No more OTs left.');
    assert(this.expectingResponseSize == 0, 'The previous request must be processed before requesting more OTs.');
    // for Beaver Derandomization, tell the Sender which masks to flip: 0 means
    // no flip needed, 1 means a flip is needed
    const bitsToFlip = [];
    for (let i=0; i < choiceBits.length; i++){
      bitsToFlip.push(choiceBits[i] ^ this.rbits[this.receivedSoFar+i]);
    }
    // pad the bitcount to a multiple of 8
    let padCount = 0;
    if (choiceBits.length % 8 > 0){
      padCount = 8 - choiceBits.length % 8;
    }
    for (let i=0; i < padCount; i++){
      bitsToFlip.push(0);
    }

    this.expectingResponseSize = choiceBits.length;
    // prefix with the amount of bits that Sender needs to drop
    // in cases when bitsArr.length is not a multiple of 8
    return concatTA(int2ba(padCount, 1), bitsToBytes(bitsToFlip));
  }

  // parseResponse unmasks the OT sender's masked values based on the choice
  // bit and the random mask of the OT receiver
  parseResponse(choiceBits, maskedOT){
    assert(this.expectingResponseSize == choiceBits.length);
    assert(this.expectingResponseSize*32 == maskedOT.length);
    const decodedArr = [];
    for (let i=0; i < choiceBits.length; i++){
      const mask = this.RT0.slice((this.receivedSoFar+i)*16, (this.receivedSoFar+i)*16+16);
      const m0 = maskedOT.slice(i*32, i*32+16);
      const m1 = maskedOT.slice(i*32+16, i*32+32);
      if (choiceBits[i] == 0){
        decodedArr.push(xor(m0, mask));
      } else {
        decodedArr.push(xor(m1, mask));
      }
    }
    this.receivedSoFar += choiceBits.length;
    this.expectingResponseSize = 0;
    return concatTA(...decodedArr);
  }
}