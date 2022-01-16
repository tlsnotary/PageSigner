/* global bcuNode, ECSimple */
import {ba2str, concatTA, int2ba, str2ba, ba2int, assert} from './../utils.js';

var bcu;
if (typeof(window) !== 'undefined'){
  import('./../third-party/math.js').then((module) => {
    bcu = module;
  });
} else {
  // we are in node. bcuNode must have been made global
  bcu = bcuNode;
}

function pad(str) {
  if (str.length % 2 === 1) {
    return `0${str}`;
  }
  return str;
}


// class PaillierPubkey implements encryption and homomorphic operations
class PaillierPubkey {
  constructor(n, g) {
    this.n = n;
    this.n2 = n ** 2n;
    this.g = g;
  }

  multiply(ciphertext, cleartext) {
    return bcu.modPow(ciphertext, cleartext, this.n2);
  }

  encrypt(m) {
    let r;
    do {
      r = bcu.randBetween(this.n);
    } while (bcu.gcd(r, this.n) !== 1n);
    return (bcu.modPow(this.g, m, this.n2) * bcu.modPow(r, this.n, this.n2)) % this.n2;
  }

  addCleartext(ciphertext, cleartext) {
    return (ciphertext * bcu.modPow(this.g, cleartext, this.n2)) % this.n2;
  }

  addCiphertext(ct1, ct2) {
    return (ct1 * ct2) % this.n2;
  }
}

// Protocol to compute EC point addition in Paillier as described here:
// https://tlsnotary.org/how_it_works#section1
// The code uses the same notation as in the link above.

// class Paillier2PC implements the client's side of computing an EC point
// addition in 2PC
export class Paillier2PC {
  // x and y are 32-byte Uint8Arrays: coordinates of server pubkey
  constructor(x, y) {
    // define secp256r1 curve
    this.secp256r1 = new ECSimple.Curve(
      0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFCn,
      0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn,
      0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n,
      (2n ** 224n) * (2n ** 32n - 1n) + 2n ** 192n + 2n ** 96n - 1n,
      new ECSimple.ModPoint(
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n,
      ),
    );

    this.Q_b = new ECSimple.ModPoint(ba2int(x), ba2int(y));
    // C picks a random private key share d_c
    this.d_c = bcu.randBetween(this.secp256r1.n - 1n, 1n);
    // and computes a public key share Q_c
    this.Q_c = this.secp256r1.multiply(this.secp256r1.g, this.d_c);
    // C computes an EC point d_c * Q_b
    const ECpoint_c = this.secp256r1.multiply(this.Q_b, this.d_c);
    this.x_p = ECpoint_c.x;
    this.y_p = ECpoint_c.y;
    this.p = this.secp256r1.p;
    // all the fields below are intermediate values which we save after each
    // communication round with the Notary
    // Enx_q is enrypted negative x_q
    this.Enx_q = null;
    this.Q_nx = null;
    this.Q_ny = null;
    this.Ey_q2 = null;
    // enrypted negative 2*y_q
    this.En2y_q = null;
    // we call E(A*M_A+N_A) "E114"
    this.E114 = null;
    this.N_Amodp = null;
    this.M_b = null;
    this.M_A = null;
    this.M_B = null;
    this.s_q = null;
  }

  // run 2PC computation with the notary
  step1() {
    // S sends its public key Q_b to C and C passes it to N
    const payload1 = str2ba(JSON.stringify({
      Q_bx: pad(this.Q_b.x.toString(16)),
      Q_by: pad(this.Q_b.y.toString(16))
    }));
    return payload1;
  }

  step2(step1Resp){
    const step1 = JSON.parse(ba2str(step1Resp));
    // -------- PHASE 1: computing term B

    const n = BigInt(`0x${step1.n}`, 16);
    const g = BigInt(`0x${step1.g}`, 16);
    const Ex_q = BigInt(`0x${step1.Ex_q}`, 16);
    this.Enx_q = BigInt(`0x${step1.Enx_q}`, 16);
    this.Q_nx =  BigInt(`0x${step1.Q_nx}`, 16);
    this.Q_ny =  BigInt(`0x${step1.Q_ny}`, 16);
    this.Ey_q2 = BigInt(`0x${step1.Ey_q2}`, 16);
    this.En2y_q = BigInt(`0x${step1.Pn2yq}`, 16);

    // we expect n to be 1536 bits = 192 bytes
    assert(int2ba(n).length == 192);
    this.pubkey = new PaillierPubkey(n, g);

    // 1.2.4
    // if x_p > x_q then b will be negative and the size of N_b would have to be
    // n = 2048bits in order to mask a negative b. But if we keep b positive then
    // the size of N_b will be 256+256=512 bits. In order to keep b positive, we
    // increase x_q by prime p and only then add -x_p, which is the same as doing:
    // x_q + (p - x_p)
    const Eb = this.pubkey.addCleartext(Ex_q, this.p - this.x_p);
    // 1.2.5
    // picks random mask M_b
    this.M_b = bcu.randBetween(2n ** 256n);
    // picks random mask N_b
    const N_b = bcu.randBetween(2n ** 512n);
    // we call E(b*M_b+N_b) E125
    const E125 = this.pubkey.addCleartext(this.pubkey.multiply(Eb, this.M_b), N_b);
    const N_bmodp = N_b % this.p;
    // 1.2.6
    const payload2 = str2ba(JSON.stringify({
      E125: pad(E125.toString(16)),
      N_bmodp: pad(N_bmodp.toString(16)),
    }));
    return payload2;
  }

  async step2async(){
    // while fetching we can compute PHASE 2: computing term A
    // N provides: E(y_q**2), E(-2y_q) (both were received in step1 response above)
    // 1.1.3
    const EA = this.pubkey.addCleartext(
      this.pubkey.addCiphertext(this.Ey_q2, this.pubkey.multiply(this.En2y_q, this.y_p)),
      bcu.modPow(this.y_p, 2n, this.p),
    );
    // 1.1.4
    this.M_A = bcu.randBetween(2n ** 512n);
    const N_A = bcu.randBetween(2n ** 1024n);
    this.E114 = this.pubkey.addCleartext(this.pubkey.multiply(EA, this.M_A), N_A);
    this.N_Amodp = N_A % this.p;
    // we don't send step 1.1.5 now, because a response from N is pending
  }

  step3(step2Resp){
    const step2 = JSON.parse(ba2str(step2Resp));
    // get what N sent in 1.2.10
    const E1210 = BigInt(`0x${step2.E1210}`, 16);
    // 1.2.11
    const Binv = bcu.modInv(bcu.modPow(this.M_b, this.p - 3n, this.p), this.p);
    // 1.2.12
    const EB = this.pubkey.multiply(E1210, Binv);
    // 1.2.13
    this.M_B = bcu.randBetween(2n ** 512n);
    const N_B = bcu.randBetween(2n ** 1024n);
    const E1213 = this.pubkey.addCleartext(this.pubkey.multiply(EB, this.M_B), N_B);
    const N_Bmodp = N_B % this.p;
    // 1.2.14 + 1.1.5
    const payload3 = str2ba(JSON.stringify({
      E1213: pad(E1213.toString(16)),
      N_Bmodp: pad(N_Bmodp.toString(16)),
      E114: pad(this.E114.toString(16)),
      N_Amodp: pad(this.N_Amodp.toString(16)),
    }));
    return payload3;
  }

  step4(step3Resp){
    const step3 = JSON.parse(ba2str(step3Resp));
    // -------- PHASE 3: computing termA*termB and term C
    // get what N sent in 1.3.1 (note that E(-x_q) was already sent to us earlier
    // in step1)
    const E131 = BigInt(`0x${step3.E131}`, 16);
    // 1.3.2
    const EAB = this.pubkey.multiply(E131, bcu.modInv((this.M_B * this.M_A) % this.p, this.p));
    // 1.3.3.
    // nx_p is negative x_p
    const nx_p = this.p - this.x_p;
    // Note that the reason why 1.3.3 says "computes E(-x_p)" is to simplify the
    // explanation. In reality, Paillier crypto allows to add a cleartext to a
    // ciphertext without needing to first encrypt the cleartext. For this reason
    // we don't encrypt -x_p but we add it homomorphically.
    // 1.3.4
    const EABC = this.pubkey.addCleartext(this.pubkey.addCiphertext(EAB, this.Enx_q),
      nx_p);
    // 1.3.5
    // EABC may be up to 1027 bits long, the mask must be same length
    const S_q = bcu.randBetween(2n ** 1027n);
    const E135 = this.pubkey.addCleartext(EABC, S_q);
    // 1.3.6
    // Since N has (PMS + S_q) and we have S_q, in order to compute PMS, we will
    // later compute the following in 2PC circuit: PMS = (PMS + S_q) - S_q,
    // thus C's s_q must be negative
    this.s_q = this.p - (S_q % this.p);
    const payload4 = str2ba(JSON.stringify({
      E135: pad(E135.toString(16)),
    }));
    return payload4;
  }

  final(){
    // N sends Q_n to C who computes Q_a = Q_c + Q_n and sends Q_a to S
    const Q_n = new ECSimple.ModPoint(this.Q_nx, this.Q_ny);
    const Q_a = this.secp256r1.add(Q_n, this.Q_c);
    // cpubBytes is TLS session's client's ephemeral pubkey for ECDHE
    const cpubBytes = concatTA(int2ba(Q_a.x, 32), int2ba(Q_a.y, 32));
    return [int2ba(this.s_q, 32), cpubBytes];
  }
}
