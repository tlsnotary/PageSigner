import {assert, getRandom, bytesToBits, concatTA, int2ba, xor, ba2int,
  bitsToBytes, splitIntoChunks, AESCTRencrypt, Salsa20} from '../utils.js';

// methods used by both OTSender and OTReceiver classes
export default class OTCommon{
  // extend r (Uint8Array) into a matrix of 128 columns where depending on r's bit, each row
  // is either all 0s or all 1s
  extend_r(r){
    // 128 bits all set to 1
    const all_1 = new Uint8Array(16).fill(255);
    // 128 bits all set to 0
    const all_0 = new Uint8Array(16).fill(0);
    const matrix = [];
    const bits = bytesToBits(r).reverse();
    for (const bit of bits){
      matrix.push(bit == 0 ? all_0 : all_1);
    }
    return matrix;
  }


  // given a matrix, output 2 xor shares of it
  secretShareMatrix(matrix){
    const T0 = [];
    const T1 = [];
    for (let i=0; i < matrix.length; i++){
      const rand = getRandom(16);
      T0.push(rand);
      T1.push(xor(matrix[i], rand));
    }
    return [T0, T1];
  }


  // transpose a matrix of bits. matrix is an array of rows (each row is a Uin8Array)
  transposeMatrix(matrix){
    const colCount = matrix[0].length*8;
    const rowCount = matrix.length;
    assert(colCount == 128 || rowCount == 128);
    const newRows = [];
    for (let j=0; j < colCount; j++){
      // in which byte of the column is j located
      const byteNo = j >> 3; //Math.floor(j / 8);
      // what is the index of j inside the byte
      const bitIdx =  j % 8;
      const newRowBits = [];
      for (let i=0; i < rowCount; i++){
        newRowBits.push((matrix[i][byteNo] >> (7-bitIdx)) & 1);
      }
      newRows.push(bitsToBytes(newRowBits.reverse()));
    }
    return newRows;
  }


  // pseudorandomly expands a 16-byte seed into a bytestring of bytesize "count"*16
  // to benefit from AES-NI, we use browser WebCrypto's AES-CTR: with seed as the key
  // we encrypt an all-zero bytestring.
  async expandSeed(seed, count){
    assert(seed.length == 16);
    return await AESCTRencrypt(seed, new Uint8Array(count*16).fill(0));
  }


  // encrypt each 16-byte chunk of msg with a fixed-key Salsa20
  async fixedKeyCipher(msg){
    assert(msg.length % 16 == 0);
    const fixedKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
    const encryptedArr = [];
    const chunks = splitIntoChunks(msg, 16);
    for (const chunk of chunks){
      encryptedArr.push(Salsa20(fixedKey, chunk));
    }
    return concatTA(...encryptedArr);
  }


  // to break the correlation, KOS15 needs a hash function which has tweakable correlation
  // robustness (tcr). GKWY20 shows (Section 7.4) how to achieve tcr using a fixed-key cipher C
  // instead of a hash, i.e. instead of Hash(x, i) we can do C(C(x) xor i) xor C(x)
  async breakCorrelation(rows){
    assert(rows[0].length == 16);
    const AESx = await this.fixedKeyCipher(concatTA(...rows));
    const indexesArray = [];
    for (let i=0; i < rows.length; i++){
      indexesArray.push(int2ba(i, 16));
    }
    const indexes = concatTA(...indexesArray);
    return xor(await this.fixedKeyCipher(xor(AESx, indexes)), AESx);
  }


  // carry-less multiplication (i.e. multiplication in galois field) without reduction.
  // Let a's right-most bit have index 0. Then for every bit set in a, b is left-shifted
  // by the set bit's index value. All the left-shifted values are then XORed.
  // a and b are both UintArray's of 16 bytes. Returns UintArray's of 32 bytes

  // this version is 25% faster than the naive implementation clmul128_unoptimized
  clmul128(a, b){
    const aBits = bytesToBits(a); // faster if turned to bits rather than shift each time
    const b_bi = ba2int(b);
    const shiftedB = [];
    // shift only 7 times and then use these 7 shifts to construct all other shifts
    for (let i=0n; i < 8n; i++){
      const tmp = new Uint8Array(32).fill(0);
      tmp.set(int2ba(b_bi << i, 17), 0);
      shiftedB.push(tmp);
    }
    const res = new Uint8Array(32).fill(0);
    for (let i = 0; i < 128; i++){
      if (aBits[i]){ // a's bit is set
        const byteNo = i >> 3; // this is faster than Math.floor(i / 8);
        const bitIdx = i % 8;
        const bLen = 17+byteNo;
        for (let i=0; i < bLen; i++){
          res[31-i] = res[31-i] ^ shiftedB[bitIdx][bLen-1-i];
        }
      }
    }
    return res;
  }


  // not in use, just for reference. This is the unoptimized version of clmul128
  clmul128_unoptimized(a, b){
    let res = 0n;
    const aBits = bytesToBits(a); // faster if turned to bits rather than shift each time
    const b_bi = ba2int(b);
    for (let i = 0n; i < 128n; i++){
      if (aBits[i]){ // a's bit is set
        res ^= (b_bi << i);
      }
    }
    return int2ba(res, 32);
  }
}


// To test the protocol end-to-end, copy-paste this function into the extension's console
async function testFullProtocol(){
  let otR = new PageSigner.OTReceiver(8);
  let otS = new PageSigner.OTSender(8);
  const [A, seedCommit] = await otR.setupStep1();
  const [allBs, senderSeedShare] = otS.setupStep1(A, seedCommit);
  const [encryptedColumns, receiverSeedShare, x, t] = await otR.setupStep2(allBs, senderSeedShare);
  await otS.setupStep2(encryptedColumns, receiverSeedShare, x, t);
  const requestBits = [0, 1, 1, 0];
  const otReq1 = otR.createRequest(requestBits);
  const senderMsg = new Uint8Array([].concat(
    Array(16).fill(0),
    Array(16).fill(1),
    Array(16).fill(2),
    Array(16).fill(3),
    Array(16).fill(4),
    Array(16).fill(5),
    Array(16).fill(6),
    Array(16).fill(7)));
  const otResp = otS.processRequest(otReq1, senderMsg);
  const decoded = otR.parseResponse(requestBits, otResp);
  console.log('the result is: ', decoded);
  const expected =  new Uint8Array([].concat(
    Array(16).fill(0),
    Array(16).fill(3),
    Array(16).fill(5),
    Array(16).fill(6),
  ));
  console.log('expected result is: ', expected);
}