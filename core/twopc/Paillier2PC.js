/* eslint-disable no-console */
/* eslint-disable max-classes-per-file */

import * as bcu from './../third-party/math.js';
import {ba2str, concatTA, int2ba, str2ba, ba2hex, ba2int} from './../utils.js';

function pad(str) {
  if (str.length % 2 === 1) {
    return `0${str}`;
  }
  return str;
}

// eslint-disable-next-line no-unused-vars
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

// Protocol to compute EC point addition in Paillier
//
// we need to find xr = lambda**2 - xp - xq, where
// lambda = (yq - yp)(xq - xp)**-1
// (when p is prime then) a**-1 mod p == a**p-2 mod p
// Simplifying:
// xr == (yq**2 - 2yqyp + yp**2) (xq - xp)**2p-4 - xp - xq
// we have 3 terms
// A = (yq**2 - 2yqyp + yp**2)
// B = (xq - xp)**2p-4
// C = - xp - xq
//
// class Paillier2PC is the client's side part of 2PC
// you should launch the notary side of 2PC with:
// go build -o notary2pc && ./notary2pc

// TODO rename Paillier2PC into ECDH2PC  

// eslint-disable-next-line no-unused-vars
export class Paillier2PC {
  // x and y are 32-byte long byte arrays: coordinates of server pubkey
  constructor(parent, x_, y_, ) {
    this.send = parent.send;
    this.notary = parent.notary;
    this.clientKey = parent.clientKey;
    this.notaryKey = parent.notaryKey;
    this.encryptToNotary = parent.encryptToNotary;
    this.decryptFromNotary = parent.decryptFromNotary;

    this.uid = parent.uid;
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

    const x = ba2int(x_);
    const y = ba2int(y_);
    
    this.serverPubkey = new ECSimple.ModPoint(x, y);

    this.pPriv = bcu.randBetween(this.secp256r1.n - 1n, 1n);
    // debug only delete priv by 2 so that the final client priv doesnt
    // overflow 32 bytes - to make openssl happy
    // remove in production
    this.pPriv = this.pPriv / 2n;
    this.pPrivG = this.secp256r1.multiply(this.secp256r1.g, this.pPriv);

    this.share1 = this.secp256r1.multiply(this.serverPubkey, this.pPriv);


    // var ecPubKey = secp256r1.add(qPrivG, pPrivG)
    // var pms = secp256r1.add(share1, share2)
    // console.log('pms is', pms)
  }

  // run 2PC computation with the notary
  async run() {
    const payload1 = str2ba(JSON.stringify({
      serverX: pad(this.serverPubkey.x.toString(16)),
      serverY: pad(this.serverPubkey.y.toString(16)),
      share1X: pad(this.share1.x.toString(16)),
      share1Y: pad(this.share1.y.toString(16)),
    }));
    const step1 = JSON.parse(ba2str(await this.send('step1', payload1)));
    const p = this.secp256r1.p;

    // (party1 is the notary, party2 is the client)
    // -------- PHASE 1: computing term B

    // party1 provides P(xq)
    // var Pxq = publicKey.encrypt(qPrivG.x)
    // // negative xq
    // // 5 - 3 mod 6 == 5 + (6 -3) mod 6
    // var Pnxq = publicKey.encrypt(secp256r1.p - qPrivG.x)

    // party2:
    // 1) compute P(A) == P(xq - xp)
    // 2) blind with B: P(AB) == P(A)^B
    // 3) (to prevent factorizing AB) blind with C: P(AB+C) == P(AB)*C
    // 4) send 1) P(AB+C) and 2) C mod p

    // if xp > xq then PA below is negative and we'd have to apply the mask C the size of
    // n = 2048bits we don't want that. If we keep PA positive then the mask C size will be
    // 256+256=512 bits for this reason we increase xp by prime (mod prime)

    const n = BigInt(`0x${step1.n}`, 16);
    const g = BigInt(`0x${step1.g}`, 16);
    const Pxq = BigInt(`0x${step1.Pxq}`, 16);
    const Pnxq = BigInt(`0x${step1.Pnxq}`, 16);

    this.pubkey = new PaillierPubkey(n, g);

    const PA = this.pubkey.addCleartext(Pxq, p - this.share1.x);
    const maskB = bcu.randBetween(2n ** 256n);
    const PAB = this.pubkey.multiply(PA, maskB);
    const maskC = bcu.randBetween(2n ** 512n);
    const PABC = this.pubkey.addCleartext(PAB, maskC);
    const Cmodp = maskC % p;

    const payload2 = str2ba(JSON.stringify({
      PABC: pad(PABC.toString(16)),
      Cmodp: pad(Cmodp.toString(16)),
    }));
    const fetch2 = this.send('step2', payload2, true);

    // while fetching we can compute

    // -------- PHASE 2: computing term A

    // party1 provides: P(yq**2), P(-2yq) (was done in step1)

    // var Pyq2 = publicKey.encrypt(bcu.modPow(qPrivG.y, 2n, secp256r1.p))
    // var Pn2yq = publicKey.encrypt(2n * (secp256r1.p - qPrivG.y) % secp256r1.p)

    // party2
    // 1) computes P(term A) = P(yq**2) + P(-2yq)**yp + P(yp**2)
    // 2) blind with c1 and c2 : d == P(termA * c1 mod c2)
    // 3) send d and c2 mod p

    const Pyq2 = BigInt(`0x${step1.Pyq2}`, 16);
    const Pn2yq = BigInt(`0x${step1.Pn2yq}`, 16);

    const PtermA = this.pubkey.addCleartext(
      this.pubkey.addCiphertext(Pyq2, this.pubkey.multiply(Pn2yq, this.share1.y)),
      bcu.modPow(this.share1.y, 2n, p),
    );

    const c1 = bcu.randBetween(2n ** 512n);
    const c2 = bcu.randBetween(2n ** 1024n);
    const d = this.pubkey.addCleartext(this.pubkey.multiply(PtermA, c1), c2);
    const c2modp = c2 % p;

    const step2 = JSON.parse(ba2str(await fetch2));

    // party1
    // computing term B continued
    // 1) decrypt to get AB+C
    // 2) reduce AB+C mod p
    // 3) subtract C to get AB mod p
    // 4) compute ABraised = (AB)**2p-4 mod p
    // 5) send P(ABraised)

    // var DABC = privateKey.decrypt(PABC)
    // var ABC = DABC % secp256r1.p
    // var AB = (ABC + secp256r1.p - Cmodp) % secp256r1.p
    // var ABraised = bcu.modPow(AB, 2n*secp256r1.p - 4n, secp256r1.p)
    // var PABraised = publicKey.encrypt(ABraised)

    // party2
    // (remember that ABraised == (A**2p-4)(B**2p-4)
    // in order to get (A**2p-4), we need to divide by (B**2p-4) or multiply by (B**2p-4)**-1)
    // 1) compute P(term B) = P(ABraised) ** (B**2p-4)**-1 mod p
    // 2) blind with a1 and a2 : b == P(termB * a1 + a2)
    // 3) send b and a2 mod p

    const PABraised = BigInt(`0x${step2.PABraised}`, 16);
    const Braised = bcu.modPow(maskB, p - 3n, p);
    const Binv = bcu.modInv(Braised, p);
    const PtermB = this.pubkey.multiply(PABraised, Binv);
    const a1 = bcu.randBetween(2n ** 512n);
    const a2 = bcu.randBetween(2n ** 1024n);
    const b = this.pubkey.addCleartext(this.pubkey.multiply(PtermB, a1), a2);
    const a2modp = a2 % p;

    const payload3 = str2ba(JSON.stringify({
      b: pad(b.toString(16)),
      a2modp: pad(a2modp.toString(16)),
      d: pad(d.toString(16)),
      c2modp: pad(c2modp.toString(16)),
    }));
    const step3 = JSON.parse(ba2str(await this.send('step3', payload3)));

    // -------- PHASE 3: computing termA*termB and term C

    // party1
    // 1) compute termB*a1*termA*c2
    // 2) send P()

    // var termBa1 = (privateKey.decrypt(b) - a2modp) % secp256r1.p
    // var termAc2 = (privateKey.decrypt(d) - c2modp) % secp256r1.p
    // var PtermABmasked = publicKey.encrypt(termBa1 * termAc2 % secp256r1.p)

    // party2
    // 1) compute P(termAB) = P(termABmasked) * (a1*c2)**-1
    // 2) compute P(X) = P(termAB) + P(-xp) + P (-xq)
    // 3) blind P(X) with x1: P(x2) = P(X+x1)
    // 4) send P(x2) (unreduced)

    const PtermABmasked = BigInt(`0x${step3.PtermABmasked}`, 16);
    const a1c1inv = bcu.modInv((a1 * c1) % p, p);
    const PtermAB = this.pubkey.multiply(PtermABmasked, a1c1inv);

    // negative xp
    const nxp = p - this.share1.x;
    const PX = this.pubkey.addCleartext(
      this.pubkey.addCiphertext(PtermAB, Pnxq),
      nxp,
    );
    // PX may be up to 1027 bits long
    const x1unreduced = bcu.randBetween(2n ** 1027n);
    const Px2unreduced = this.pubkey.addCleartext(PX, x1unreduced);
    // negative x1
    const nx1 = p - (x1unreduced % p);

    const payload4 = str2ba(JSON.stringify({
      Px2unreduced: pad(Px2unreduced.toString(16)),
    }));
    const step4 = JSON.parse(ba2str(await this.send('step4', payload4)));

    // party1

    // var x2 = privateKey.decrypt(Px2unreduced) % secp256r1.p
    // // now both parties have additive shares of X: x1 and nx2
    // // x2 + nx1 == x2 - x1   == X

    const x2 = BigInt(`0x${step4.x2}`, 16);
    const qPriv = BigInt(`0x${step4.qPriv}`, 16);
    const qPrivG = this.secp256r1.multiply(this.secp256r1.g, qPriv);
    const share2 = this.secp256r1.multiply(this.serverPubkey, qPriv);

    // TODO this must not be done here because qPriv (from which qPrivG is computed)
    // is here only for debugging. notary should pass qPrivG after step1
    const clientPubkey = this.secp256r1.add(qPrivG, this.pPrivG);
    const cpubBytes = concatTA(
      int2ba(clientPubkey.x, 32),
      int2ba(clientPubkey.y, 32));

    const clientPrivkey = this.pPriv + qPriv;
    console.log('priv sum len is ', int2ba(clientPrivkey).length);
    // if privkey > 32 bytes, the result will still be correct
    // the problem may arise when (during debugging) we feed >32 bytes
    // into openssl. It expects 32 bytes

    // assert(bigint2ba(clientPrivkey).length <= 32)


    const x = ((( 
      bcu.modPow(share2.y + p - this.share1.y, 2n, p) * 
      bcu.modPow(share2.x + p - this.share1.x, p - 3n, p)) % p) + 
      (p - this.share1.x) + (p - share2.x)) % p;

    const pms = (x2 + nx1) % p;
    console.log('is sum larger than prime', (x2 + nx1) > p);

    const nx1Hex = int2ba(nx1, 32); // negative share x1
    return [nx1Hex, cpubBytes];
  }
}
