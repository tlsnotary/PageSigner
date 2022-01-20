/* global bcuNode, ECSimple */

import {TLS, decrypt_tls_responseV6} from './TLS.js';


var bcu;
if (typeof(window) !== 'undefined'){
  import('./third-party/math.js').then((module) => {
    bcu = module;
  });
} else {
  // we are in node. bcuNode must have been made global
  bcu = bcuNode;
}
import {assert, concatTA, int2ba, str2ba, ba2int, getRandom, eq, sha256, ba2str}
  from './utils.js';

// class TLSprobe is used when we want to give a preview of notarization.
// It creates a TLS connection and fetches a resource.
export class TLSprobe extends TLS{
  constructor(server, port, request, sessionOptions){
    super(server, port, request, sessionOptions);
  }

  async start(){
    await super.buildAndSendClientHello();
    const serverEcPubkey = await super.receiveAndParseServerHello();
    const [pms, cpubBytes] = this.generatePMS(serverEcPubkey);
    await super.buildClientKeyExchange(cpubBytes);
    const [cr, sr] = await super.getRandoms();
    const [cwk, swk, civ, siv, MS_CryptoKey] = await this.getExpandedKeys(pms, cr, sr);
    const verifyData = await this.computeVerifyDataCF(MS_CryptoKey, super.getAllHandshakes());
    const cf = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verifyData);
    super.updateAllHandshakes(cf);
    const [encCF, tagCF] = await this.encryptClientFinished(cf, cwk, civ);
    await super.sendClientFinished(encCF, tagCF);
    const encSF = await super.receiveServerFinished();
    await this.checkServerFinished(encSF, super.getAllHandshakes(), MS_CryptoKey, swk, siv);
    const encReq = await this.encryptRequest(str2ba(this.headers), cwk, civ);
    this.sendRequest([encReq]);
    const serverRecords = await super.receiveServerResponse();
    const plaintextRecs = await decrypt_tls_responseV6(serverRecords, swk, siv);
    let plaintextFlat = '';
    for (const rec of plaintextRecs){
      plaintextFlat += ba2str(rec);
    }
    return plaintextFlat;
  }


  // serverEcPubkey is webserver's ephemeral pubkey from the Server Key Exchange
  generatePMS(serverEcPubkey) {
    const x = serverEcPubkey.slice(1, 33);
    const y = serverEcPubkey.slice(33, 65);
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

    const Q_server = new ECSimple.ModPoint(ba2int(x), ba2int(y));
    const d = bcu.randBetween(this.secp256r1.n - 1n, 1n);
    const Q = this.secp256r1.multiply(this.secp256r1.g, d);
    const ECpoint = this.secp256r1.multiply(Q_server, d);
    const pms = ECpoint.x;

    const pubBytes = concatTA(int2ba(Q.x, 32), int2ba(Q.y, 32));
    return [int2ba(pms, 32), pubBytes];
  }

  async getExpandedKeys(preMasterSecret, cr, sr){
    const Secret_CryptoKey = await crypto.subtle.importKey(
      'raw',
      preMasterSecret.buffer,
      {name: 'HMAC', hash:'SHA-256'},
      true,
      ['sign']);

    // calculate Master Secret and expanded keys
    const seed = concatTA(str2ba('master secret'), cr, sr);
    const a0 = seed;
    const a1 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, a0.buffer));
    const a2 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, a1.buffer));
    const p1 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, concatTA(a1, seed).buffer));
    const p2 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, concatTA(a2, seed).buffer));
    const ms = concatTA(p1, p2).slice(0, 48);
    const MS_CryptoKey = await crypto.subtle.importKey('raw', ms.buffer, {name: 'HMAC', hash:'SHA-256'}, true, ['sign']);

    // Expand keys
    const eseed = concatTA(str2ba('key expansion'), sr, cr);
    const ea0 = eseed;
    const ea1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, ea0.buffer));
    const ea2 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, ea1.buffer));
    const ep1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(ea1, eseed).buffer));
    const ep2 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(ea2, eseed).buffer));

    const ek = concatTA(ep1, ep2).slice(0, 40);
    // GCM doesnt need MAC keys
    const client_write_key = ek.slice(0, 16);
    const server_write_key = ek.slice(16, 32);
    const client_write_IV = ek.slice(32, 36);
    const server_write_IV = ek.slice(36, 40);
    return [client_write_key, server_write_key, client_write_IV, server_write_IV, MS_CryptoKey];
  }

  // returns verify_data for Client Finished
  async computeVerifyDataCF(MS_CryptoKey, allHandshakes){
    const hshash = await sha256(allHandshakes);
    const seed = concatTA(str2ba('client finished'), hshash);
    const a0 = seed;
    const a1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, a0.buffer));
    const p1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(a1, seed).buffer));
    const verifyData = p1.slice(0, 12);
    return verifyData;
  }

  // encrypt Client Finished and return the encrypted CF (without the 8-byte nonce)
  // and the auth tag
  async encryptClientFinished(cf, cwk, civ){
    const explicit_nonce = int2ba(1, 8); //explicit nonce is hard-coded to 1 for now
    //const explicit_nonce = getRandom(8);
    const nonce = concatTA(civ, explicit_nonce);
    const seq_num = 0;
    const tmp = [];
    tmp.push(...Array.from(int2ba(seq_num, 8)));
    tmp.push(0x16); // type 0x16 = Handshake
    tmp.push(0x03, 0x03); // TLS Version 1.2
    tmp.push(0x00, 0x10); // 16 bytes of unencrypted data
    //additional authenticated data
    const aad = new Uint8Array(tmp);
    const key = await crypto.subtle.importKey('raw', cwk.buffer, 'AES-GCM',
      true, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM',
      iv: nonce.buffer, additionalData: aad.buffer}, key, cf.buffer));
    console.log('len in encryptClientFinished  is ', ciphertext.length);
    return [ciphertext.slice(0, -16), ciphertext.slice(-16)];
  }

  // encrypt Server Finished using the explicit_nonce
  // return ciphertext (without the nonce) and the tag
  async encryptServerFinished(sf, explicit_nonce, swk, siv){
    const nonce = concatTA(siv, explicit_nonce);
    const seq_num = 0;
    const tmp = [];
    tmp.push(...Array.from(int2ba(seq_num, 8)));
    tmp.push(0x16, 0x03, 0x03); // Handshake, TLS Version 1.2
    tmp.push(0x00, 0x10); // 16 bytes of unencrypted data
    //additional authenticated data
    const aad = new Uint8Array(tmp);
    const key = await crypto.subtle.importKey('raw', swk.buffer, 'AES-GCM',
      true, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM',
      iv: nonce.buffer, additionalData: aad.buffer}, key, sf.buffer));
    return [ciphertext.slice(0, -16), ciphertext.slice(-16)];
  }

  async checkServerFinished(encSF, allHandshakes, MS_CryptoKey, swk, siv){
    const hshash = await sha256(allHandshakes);
    const seed = concatTA(str2ba('server finished'), hshash);
    const a0 = seed;
    const a1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, a0.buffer));
    const p1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(a1, seed).buffer));
    const verifyData = p1.slice(0, 12);
    const sf = concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), verifyData);
    const nonceFromWire = encSF.slice(0, 8);
    const [ct, tag] = await this.encryptServerFinished(sf, nonceFromWire, swk, siv);
    assert(eq(concatTA(nonceFromWire, ct, tag), encSF));
  }

  async encryptRequest(req, cwk, civ){
    const explicit_nonce = getRandom(8);
    const nonce = concatTA(civ, explicit_nonce);
    let seq_num = 1;
    const tmp = [];
    tmp.push(...Array.from(int2ba(seq_num, 8)));
    tmp.push(0x17, 0x03, 0x03); // Application data, TLS Version 1.2
    tmp.push(...Array.from(int2ba(req.length, 2))); // bytelength of unencrypted data
    //additional authenticated data
    const aad = new Uint8Array(tmp);
    const key = await crypto.subtle.importKey('raw', cwk.buffer, 'AES-GCM',
      true, ['encrypt']);
    return concatTA(explicit_nonce, new Uint8Array(
      await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce.buffer,
        additionalData: aad.buffer}, key, req.buffer)));
  }

  sendRequest(records){
    let appdata = new Uint8Array();
    for (let i=0; i< records.length; i++){
      appdata = concatTA(
        appdata,
        new Uint8Array([0x17, 0x03, 0x03]), // Type: Application data, TLS Version 1.2
        int2ba(records[i].length, 2), // 2-byte length of encrypted data
        records[i]);
    }
    console.log('sending http request');
    this.sckt.send(appdata);
  }
}
