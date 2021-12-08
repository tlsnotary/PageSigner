import {OTWorker} from './OTWorker.js';
import {concatTA, int2ba, assert, encrypt_generic, decrypt_generic} from './../utils.js';

export class OT{
  // class OT implements oblivious transfer protocol based on
  // Chou-Orlandi "Simplest OT"
  // as much pre-computation as possiblle is done in the offline phase
  
  constructor(){
    this.decryptionKeys = [];
    this.notaryA = null; // A value of notary the sender
    this.worker = new OTWorker(4);

    // pools are used to pre-compute in the offline phase the decryption key
    // for a receiver's bit in the oblivious transfer
    this.poolOf0 = []; // item format {k_R:<value>, B:<value>, idx:<>}
    this.poolOf1 = []; //
      
    // OT for the sender
    this.a = sodium.crypto_core_ristretto255_scalar_random();
    this.A = sodium.crypto_scalarmult_ristretto255_base(this.a);
    this.encryptionKeys = [];
  }
  
  setA(A){
    this.notaryA = A;
  }

  getSenderA(){
    return this.A;
  }
  
  // for each bit in bits pre-compute B and k_R (per [1])
  saveDecryptionKeysOld(bits){
    const receiverBs = [];
    // we will reuse the same B to save time 
    // during release REUSE IS NOT ALLOWED - IT BREAKS SECURITY
    const b0 = sodium.crypto_core_ristretto255_scalar_random();
    const B0 = sodium.crypto_scalarmult_ristretto255_base(b0);
    const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b0, this.notaryA));
      
    const b1 = sodium.crypto_core_ristretto255_scalar_random();
    const gb1 = sodium.crypto_scalarmult_ristretto255_base(b1);
    const B1 = sodium.crypto_core_ristretto255_add(this.notaryA, gb1);
    const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b1, this.notaryA));
  
    for (let i=0; i < bits.length; i++){
      const bit = bits[i];
      this.decryptionKeys.push(bit === 0 ? k0 : k1);
      receiverBs.push(bit === 0 ? B0 : B1);
    }
    console.log('saveDecryptionKeys for count:', bits.length);
    return receiverBs;
  }

  async saveDecryptionKeys(bits){
    const receiverBs = [];
    const entries = await this.worker.saveDecryptionKeys(bits, this.notaryA);
    for (const e of entries){
      this.decryptionKeys.push(e[0]);
      receiverBs.push(e[1]);
    }
    return receiverBs;
  }

  
  // decrypts 1-of-2 ciphertexts for a bit "bit" with a key "key" at index "idx"
  // returns the plaintext 
  decryptWithKeyFromIndex(ciphertext, bit, idx){ 
    assert(ciphertext.length == 32);
    assert(bit === 0 || bit === 1);
    assert(this.decryptionKeys[idx] != undefined);
    const encMessage = ciphertext.slice(16*bit, 16*bit+16);
    return decrypt_generic(encMessage, this.decryptionKeys[idx], 0);
  }
  
  // decrypts 1-of-2 ciphertexts for a bit "bit" with a key from obj.k_R
  decryptWithKey(ciphertext, bit, key){ 
    assert(ciphertext.length === 32 && key.length === 16);
    assert(bit === 0 || bit === 1);
    const encMessage = ciphertext.slice(16*bit, 16*bit+16);
    return decrypt_generic(encMessage, key, 0);
  }
  
  // we prepare B and k_R for 120% of the bits. The extra 20% is needed because we don't
  // know in advance exactly how many 1s and 0s we'll need during the online phase
  precomputePoolOld(numBits){
    // we will reuse the same B to save time 
    // during release REUSE IS NOT ALLOWED - IT BREAKS SECURITY
    const b0 = sodium.crypto_core_ristretto255_scalar_random();
    const B0 = sodium.crypto_scalarmult_ristretto255_base(b0);
    const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b0, this.notaryA));
      
    const b1 = sodium.crypto_core_ristretto255_scalar_random();
    const gb1 = sodium.crypto_scalarmult_ristretto255_base(b1);
    const B1 = sodium.crypto_core_ristretto255_add(this.notaryA, gb1);
    const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(b1, this.notaryA));
  
    console.time('precomputePool');
    for (let i = 0; i < Math.ceil(numBits/2 * 1.2) ; i++){
      this.poolOf0.push({k_R:k0, B:B0});
    }
    for (let i = 0; i < Math.ceil(numBits/2 * 1.2); i++){
      this.poolOf1.push({k_R:k1, B:B1});
    }
    console.timeEnd('precomputePool');
    console.log('total bits', numBits);
  }

  // we prepare B and k_R for 120% of the bits. The extra 20% is needed because we don't
  // know in advance exactly how many 1s and 0s we'll need during the online phase
  async precomputePool(numBits){
    const count = Math.ceil(numBits/2 * 1.2); // we need "count" zeroes and "count" ones
    const entries = await this.worker.precomputePool(count, this.notaryA);
    assert(entries.length === count*2);
    for (const e of entries.slice(0, count)){
      this.poolOf0.push({k_R:e[0], B:e[1]});
    }
    for (const e of entries.slice(count, count*2)){
      this.poolOf1.push({k_R:e[0], B:e[1]});
    }
  }
  
  // given an array of bits, return the index for each bit in the pool
  // and decryption keys for OT
  getIndexesFromPool(bits){
    const idxArray = [];
    const otKeys = [];
    for (let i=0; i < bits.length; i++){
      const otbit = this.getFromPool(bits[i]);
      idxArray.push(int2ba(otbit.idx, 2));
      otKeys.push(otbit.k_R);
    }
    return [concatTA(...idxArray), otKeys];
  }


  // return an array of B values from poolOf0 and poolOf1 in random sequence
  // and remember each B's index in that sequence.
  getRandomizedPool(){
    function getRandomInt(min, max) {
      min = Math.ceil(min);
      max = Math.floor(max);
      return Math.floor(Math.random() * (max - min + 1)) + min;
    }
  
    const randomizedB = [];
    const fullPool = [].concat(this.poolOf0, this.poolOf1);
    const origLen = fullPool.length;
    for (let i=0; i < origLen; i++){
      const randIdx = getRandomInt(0, fullPool.length-1);
      const ot = fullPool.splice(randIdx, 1)[0];
      // modifying ot will be reflected in this.poolOf0/this.poolOf1 because of pass-by-reference
      ot.idx = i;
      randomizedB.push(ot.B);
    }
    return randomizedB;
  }
  
   
  // gets either 0 or 1 from pool
  getFromPool(bit){
    assert(bit === 0 || bit === 1);
    const pool = (bit === 0) ? this.poolOf0 : this.poolOf1;
    const item = pool.pop();
    assert(this.poolOf0.length > 0 && this.poolOf0.length > 0);
    return item;
  }
  
  // given the receiver's B, encrypt m0 and m1
  // we don't parallelize this function because the amount of encryptions is small
  encrypt(m0, m1, B){
    const k0 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(this.a, B)); 
    const sub = sodium.crypto_core_ristretto255_sub(B, this.A);
    const k1 = sodium.crypto_generichash(16, sodium.crypto_scalarmult_ristretto255(this.a, sub)); 
    const e0 = encrypt_generic(m0, k0, 0);
    const e1 = encrypt_generic(m1, k1, 0);
    return concatTA(e0, e1);
  }

  encryptWithKeyAtIndex(m0, m1, idx){
    const k0 = this.encryptionKeys[idx][0];
    const k1 = this.encryptionKeys[idx][1];
    const e0 = encrypt_generic(m0, k0, 0);
    const e1 = encrypt_generic(m1, k1, 0); 
    return concatTA(e0, e1);
  }

  // (client as the sender) for each B in arrOfB save an encryption keypair [k0,k1]
  async prepareEncryptionKeys(arrOfB){
    console.time('prepareEncryptionKeys');
    const entries = await this.worker.prepareEncryptionKeys(arrOfB, this.a, this.A);
    assert(entries.length === arrOfB.length);
    for (const e of entries){
      this.encryptionKeys.push([e[0], e[1]]);
    }
    console.timeEnd('prepareEncryptionKeys');
    console.log('prepareEncryptionKeys for count:', arrOfB.length);
  }
}
  