import {sortKeys, assert, bytesToBits, concatTA, int2ba, xor, ba2int,
  splitIntoChunks} from '../utils.js';


// class GHASH implements a method of computing the AES-GCM's GHASH function
// in a secure two-party computation (2PC) setting using 1-of-2 Oblivious
// Transfer (OT). The parties start with their secret shares of H (GHASH key) end at
// the end each gets their share of the GHASH output.
// The method is decribed here:
// (https://tlsnotary.org/how_it_works#section4).


export class GHASH {
  constructor(noOfAESBlocks){
    // otR is an instance of OTReceiver
    this.otR = null;
    // shares is a sparse array of shares of the powers of H. H is also
    // known as GHASH key - it is an all-zero bytestring AES-ECB-encrypted
    // with TLS session's client_write_key. Array's key is the power n,
    // Array's value is the value of the client's xor-share of H^n.
    this.shares = [];
    // maxPowerNeeded is the maximum power of H that we'll need in order to
    // compute the GHASH function. It is the number of AES blocks +
    // aad (1 block) + suffix (1 block)
    this.maxPowerNeeded = noOfAESBlocks + 2;
    // lastChoiceBits is the choice bits in client's most recent OT request.
    this.lastChoiceBits = null;
    // lastStrategy contains one of the two strategies which was used when
    // preparing the most recent OT request. The same strategy will be used
    // when processing an OT response.
    this.lastStrategy = null;
    // res contains an intermediate result during Block Aggregation. We
    // save it here before making an OT request and pick it up after
    // receiving a response.
    this.res = new Uint8Array(16).fill(0);

    // strategy1&2 shows what existing shares we will be multiplying (values
    // 0 and 1) to obtain other odd shares (key).
    // Max sequential odd share that we can obtain on first round of
    // communication is 19 (we already have 1) shares of H^1, H^2, H^3 from
    // the Client Finished message and 2) squares of those 3 shares).
    // Note that "sequential" is a keyword here. We can't obtain 21 but we
    // indeed can obtain 25==24+1, 33==32+1 etc. However with 21 missing,
    // even if we have 25,33,etc, there will be a gap and we will not be able
    // to obtain all the needed shares by Block Aggregation.

    // We request OT for each share in each pair of the strategy, i.e. for
    // shares: 4,1,4,3,8,1, etc. Even though it would be possible to introduce
    // optimizations in order to avoid requesting OT for the same share more
    // than once, that would only save us ~2000 OT instances at the cost of
    // complicating the code.

    this.strategy1 = {
      5:  [4, 1],
      7:  [4, 3],
      9:  [8, 1],
      11: [8, 3],
      13: [12, 1],
      15: [12, 3],
      17: [16, 1],
      19: [16, 3]};
    this.strategy2 = {
      21: [17, 4],
      23: [17, 6],
      25: [17, 8],
      27: [19, 8],
      29: [17, 12],
      31: [19, 12],
      33: [17, 16],
      35: [19, 16]};

    // maxOddPowerNeeded is the maximum odd share that we need (it is a key
    // from one of the strategies)
    this.maxOddPowerNeeded = this.findMaxOddPower(this.maxPowerNeeded);
    // otCount is how many instances of OT the client (who is the OT receiver)
    // will have to execute. The OT count for Client_Finished is 256 and for
    // Server_Finished it is also 256.
    this.otCount = 256 + 256 + this.calculateOTCount();
  }

  // sets the OTReceiver instance
  setOTReceiver(otR){
    this.otR = otR;
  }

  // return true if we need another communication roundtrip with the notary
  isStep2Needed(){
    return this.maxOddPowerNeeded > 19;
  }

  // return true if we expect the notary to respond with data on Step1
  isStep1ResponseExpected(){
    return this.maxOddPowerNeeded > 3;
  }

  // findMaxOddPower finds the max odd share that we
  findMaxOddPower(maxPowerNeeded){
    assert(maxPowerNeeded <= 1026);

    // maxHTable's <value> shows how many GHASH blocks can be processed
    // with Block Aggregation if we have all the sequential shares
    // starting with 1 up to and including <key>.
    // e.g. {5:29} means that if we have shares of H^1,H^2,H^3,H^4,H^5,
    // then we can process 29 GHASH blocks.
    // max TLS record size of 16KB requires 1026 GHASH blocks
    const maxHTable = {0: 0, 3: 19, 5: 29, 7: 71, 9: 89, 11: 107, 13: 125, 15: 271, 17: 305, 19: 339, 21: 373,
      23: 407, 25: 441, 27: 475, 29: 509, 31: 1023, 33: 1025, 35: 1027};

    let maxOddPowerNeeded = null;
    for (const key of sortKeys(maxHTable)){
      const maxH = maxHTable[key];
      if (maxH >= maxPowerNeeded){
        maxOddPowerNeeded = key;
        break;
      }
    }
    return maxOddPowerNeeded;
  }

  // calculateOTCount calculates the amount of OTs the OT receiver
  // will have to execute when sending the request (Client/Server Finished
  // are not included)
  calculateOTCount(){
    // z is a dummy value which we set to indicate that we have the share
    const z = new Uint8Array(16).fill(0);
    // all shares of powers which the client has
    // add powers 1,2,3 which the client will already have
    const allShares = [undefined, z, z, z];
    // powerCount contains powers from strategies. Each power requires
    // 128 OTs.
    let powerCount = 0;
    const strategy = {...this.strategy1, ...this.strategy2};
    for (const k of sortKeys(strategy)){
      if (k > this.maxOddPowerNeeded){
        break;
      }
      allShares[k] = z;
      powerCount += 2;
    }
    this.freeSquare(allShares, this.maxPowerNeeded);

    // how many auxillary shares needed for Block Aggregation. Each aux
    // share requires 128 OTs for the share itself and 128 OTs for
    // its aggregated value.
    const auxShares = [];
    for (let i=1; i <= this.maxPowerNeeded; i++){
      if (allShares[i] != undefined){
        continue; // the client already has this share
      }
      // a is the smaller power
      const [a, b] = this.findSum(allShares, i);
      if (! auxShares.includes(a)){
        auxShares.push(a);
      }
    }
    return powerCount * 128 + auxShares.length * 256;
  }

  // prepareOTRequest prepares a request for Notary's masked XTables
  // corresponding to our shares in the strategies.
  async prepareOTRequest(strategyNo){
    assert(this.lastChoiceBits == null);
    this.freeSquare(this.shares, this.maxPowerNeeded);
    const strategy = strategyNo == 1 ? this.strategy1 : this.strategy2;
    const inputBits1Arr = [];
    const keys = Object.keys(strategy);
    for (const k of keys){
      if (k > this.maxOddPowerNeeded){
        break;
      }
      const v = strategy[k];
      inputBits1Arr.push(bytesToBits(this.shares[v[0]]).reverse());
      inputBits1Arr.push(bytesToBits(this.shares[v[1]]).reverse());
    }
    this.lastChoiceBits = [].concat(...inputBits1Arr);
    this.lastStrategy = strategy;
    return this.otR.createRequest(this.lastChoiceBits);
  }

  processOTResponse(otResp){
    assert(this.lastChoiceBits != null);
    const hisXTables = this.otR.parseResponse(this.lastChoiceBits, otResp);
    this.getPowerShares(hisXTables, this.shares);
    this.freeSquare(this.shares, this.maxPowerNeeded);
    this.lastChoiceBits = null;
    this.lastStrategy = null;
  }

  // buildStep1 starts the process of computing our share of the tag for the
  // client request. We already have shares of H^1, H^2, H^3 from the tag for
  // the Client_Finished earlier
  async buildStep1(){
    console.log('maxPowerNeeded is', this.maxPowerNeeded);
    assert(this.maxPowerNeeded <= 1026);
    if (this.maxOddPowerNeeded === 3){
      this.freeSquare(this.shares, this.maxPowerNeeded);
      return int2ba(this.maxPowerNeeded, 2);
    }
    return concatTA(int2ba(this.maxPowerNeeded, 2), await this.prepareOTRequest(1));
  }

  // Step2 is needed when the amount of odd powers needed is > 19
  async buildStep2(){
    return await this.prepareOTRequest(2);
  }

  // Step3 performs Block Aggregation for GHASH inputs
  async buildStep3(ghashInputs){
    this.res = this.multiplyShares(ghashInputs);
    return await this.blockAggregationBuildRequest(ghashInputs);
  }

  // Add notary's masked XTables to our tag share
  processStep3Response(resp){
    assert(this.lastChoiceBits != null);
    let o = 0;
    const otResp = resp.slice(o, o += this.lastChoiceBits.length * 32);
    const hisTagShare = resp.slice(o, o += 16);
    assert(resp.length === o);
    const res = this.blockAggregationProcessResponse(otResp);
    return xor(res, hisTagShare);
  }

  // buildFinRequest builds an OT request to compute the tag of either
  // Client Finished (CF) or Server Finished (SF) message
  // Note that you must use separate instances of the GHASH class: one for
  // CF and one for SF
  buildFinRequest(H1){
    assert(this.lastChoiceBits == null);
    const H2 = blockMult(H1, H1);
    const h1Bits = bytesToBits(H1).reverse();
    const h2Bits = bytesToBits(H2).reverse();
    this.shares[1] = H1;
    this.shares[2] = H2;
    this.lastChoiceBits = [].concat(h1Bits, h2Bits);
    return this.otR.createRequest(this.lastChoiceBits);
  }

  // processFinResponse processes notary's OT response and multiplies
  // each share of H with the corresponding GHASH block
  processFinResponse(otResp, ghashInputs){
    assert(this.lastChoiceBits != null);
    const twoXTables = this.otR.parseResponse(this.lastChoiceBits, otResp);
    let H3 = new Uint8Array(16).fill(0);
    // we multiply our H1 share with his H2's masked XTable and
    // we multiply our H2 share with his H1's masked XTable
    const items = splitIntoChunks(twoXTables, 16);
    for (let i = 0; i < 256; i++) {
      H3 = xor(H3, items[i]);
    }
    H3 = xor(H3, blockMult(this.shares[1], this.shares[2]));
    this.shares[3] = H3;
    const s1 = blockMult(ghashInputs[0], this.shares[3]);
    const s2 = blockMult(ghashInputs[1], this.shares[2]);
    const s3 = blockMult(ghashInputs[2], this.shares[1]);
    this.lastChoiceBits = null;
    return xor(xor(s1, s2), s3);
  }

  // findSum finds summands from "powers" which add up to "sumNeeded"
  // those powers which we don't have are undefined
  findSum(powers, sumNeeded){
    for (let i=1; i < powers.length; i++){
      if (powers[i] == undefined){
        continue;
      }
      for (let j=1; j < powers.length; j++){
        if (powers[j] == undefined){
          continue;
        }
        if (i+j === sumNeeded){
          return [i, j];
        }
      }
    }
    // this should never happen because we always call
    // findSum() knowing that the sum can be found
    throw('sum not found');
  }

  // Perform squaring of each odd share up to maxPower. It is "free" because
  // it is done locally without OT.
  // "powers" is a sparse array where idx is the power (or undefined if not set) and
  // item at that idx is client's share of H^power. Modifies "powers" in-place,
  // e.g if "powers" contains 1,2,3 and maxPower==19, then upon return "powers"
  // will contain 1,2,3,4,6,8,12,16
  freeSquare(powers, maxPower){
    for (let i=0; i < powers.length; i++){
      if (powers[i] == undefined || i % 2 == 0){
        continue;
      }
      if (i > maxPower){
        return;
      }
      let power = i;
      while (power <= maxPower){
        power = power * 2;
        if (powers.includes(power)){
          continue;
        }
        powers[power] = blockMult(powers[power/2], powers[power/2]);
      }
    }
  }

  // multiply H shares with corresponding ciphertext blocks
  // for all H shares which we do not have we wll use the Block Aggregation method
  multiplyShares(ghashInputs){
    let res = new Uint8Array(16).fill(0);
    // this.powersOfH is a sparse array, its .length is the max index
    for (let i=1; i < this.shares.length; i++){
      if (i > ghashInputs.length){
        // we will have more powers than the input blocks
        break;
      }
      if (this.shares[i] == undefined){
        continue;
      }
      const x = ghashInputs[ghashInputs.length-i];
      res = xor(res, blockMult(this.shares[i], x));
    }
    return res;
  }

  // for those shares of powers which are not in powersOfH, we do not compute the shares of
  // powers, but instead we compute the share of (X_n*H), where X_n is a ciphertext block

  // e.g. if we need H^21*X_1 and we have shares of H^19 and H^2, we compute it as follows:
  // (H19_a + H19_b)*(H2_a + H2_b)*X_1 == H19_a*H2_a*X_1 + H19_a*X_1*H2_b + H19_b*X_1*H2_a +
  // H19_b*H2_b*X_1
  // only the 2 middle cross-terms need to be computed using OT
  // A will receive OT for H19_a*X_1 from B
  // B will receive OT for H19_b*X_1 from A
  // All other powers where one of the factors is H^2 can be "collapsed" into (i.e xored with)
  // the above two cross-terms, eg if parties have shares of H^23 and need to compute
  // H^25 == H^23*H^2, then H23_a*X_2 can be collapsed into H19_a*X_1 and
  // H23_b*X_2 can be collapsed into H19_b*X_1
  // Thus we would not need any extra OT to compute shares of H^25

  async blockAggregationBuildRequest(ghashInputs){
    assert(this.lastChoiceBits == null);
    // aggregated object's keys are shares and values are the aggregated
    // value of shares * GHASH block
    let aggregated = {};
    // this.powersOfH is a sparse array. It contains: the powers 1,2,3 + odd powers that we
    // computed earlier + squares of all those powers
    for (let i=4; i < this.shares.length; i++){
      if (i > ghashInputs.length){
        // we stop iterating shares of powers of H
        break;
      }
      if (this.shares[i] != undefined){
        // we already multiplied the block with this share in multiplyShares()
        continue;
      }
      // found a share which does not exist in our sparse array,
      // we need X*H for this missing power
      // a is the smaller power, b is the bigger power
      const [a, b] = this.findSum(this.shares, i);
      const x = ghashInputs[ghashInputs.length-i];
      this.res = xor(this.res, blockMult(blockMult(this.shares[a], this.shares[b]), x));
      if (aggregated[a] == undefined){
        aggregated[a] = new Uint8Array(16).fill(0);
      }
      aggregated[a] = xor(aggregated[a], blockMult(this.shares[b], x));
    }

    // request Notary's masked X-table for each Notary's small power a.
    // We send bits of our aggregated values
    // and also
    // request Notary's X-table for each Notary's aggregated value. We send bits
    // of our small power
    const sortedKeys = sortKeys(aggregated);
    let allBits = [];
    for (const key of sortedKeys){
      // OT starts with the highest bit because ours is the y value of block multiplication
      allBits = [].concat(allBits, bytesToBits(aggregated[key]).reverse());
      allBits = [].concat(allBits, bytesToBits(this.shares[key]).reverse());
    }
    this.lastChoiceBits = allBits;
    if (allBits.length == 0){
      // no block agregation is needed
      return new Uint8Array(0);
    } else {
      return this.otR.createRequest(allBits);
    }
  }

  // add NOtary's XTable to our share of the tag
  blockAggregationProcessResponse(otResp){
    assert(this.lastChoiceBits != null);
    const XTableEntries = this.otR.parseResponse(this.lastChoiceBits, otResp);
    const items = splitIntoChunks(XTableEntries, 16);
    for (let i = 0; i < items.length; i += 1) {
      this.res = xor(this.res, items[i]);
    }
    this.lastChoiceBits = null;
    return this.res;
  }

  // Compute shares of powers listed in strategies
  // modifies PowersOfH in-place
  getPowerShares(hisXTables, powersOfH){
    const stratKeys = sortKeys(this.lastStrategy);
    // for each strategy we have 128 values for 1st factor and 128 values for 2nd factor
    const xTablePair = splitIntoChunks(hisXTables, 256*16);
    for (let j=0; j < stratKeys.length; j++){
      const oddPower = stratKeys[j];
      if (oddPower > this.maxOddPowerNeeded){
        assert(xTablePair.length === j);
        break;
      }
      let xorSum = new Uint8Array(16).fill(0); // start with 0 sum
      const xTableRow = splitIntoChunks(xTablePair[j], 16);
      for (let i=0; i < 256; i++){
        xorSum = xor(xorSum, xTableRow[i]);
      }
      const Cx = powersOfH[this.lastStrategy[oddPower][0]];
      const Cy = powersOfH[this.lastStrategy[oddPower][1]];
      const CxCy = blockMult(Cx, Cy);
      powersOfH[oddPower] = xor(xorSum, CxCy);
    }
  }

}

// perform GCM Galois Field block multiplication
// x_,y_ are Uint8Arrays
export function blockMult(x_, y_){
  // casting to BigInt just in case if ba2int returns a Number
  let x = BigInt(ba2int(x_));
  const y = BigInt(ba2int(y_));
  let res = 0n;
  for (let i=127n; i >= 0n; i--){
    res ^= x * ((y >> i) & 1n);
    x = (x >> 1n) ^ ((x & 1n) * BigInt(0xE1000000000000000000000000000000));
  }
  return int2ba(res, 16);
}

// return a table of 128 x values needed for block multiplication
// x is Uint8Array
// Not in use because the Client is the OT receiver, he supplies
// the bits of y. The Notary supplies the XTable.
export function getXTable(x_){
  let x = ba2int(x_);
  const table = [];
  for (let i=0; i < 128; i++){
    table[i] = int2ba(x, 16);
    x = (x >> 1n) ^ ((x & 1n) * BigInt(0xE1000000000000000000000000000000));
  }
  return table;
}
