import {TWOPC} from './twopc/TWOPC.js';
import {TLS} from './TLS.js';
import {concatTA, sha256, assert, xor, str2ba} from './utils.js';


// class TLSNotarySession impements one notarization session
// (one client request followed by one server response) using the TLSNotary protocol.
export class TLSNotarySession{
  constructor(server, port, request, notary, sessionOptions, circuits, progressMonitor){
    // twopc is an instance of class TWOPC. Used to speak to the notary.
    this.twopc = new TWOPC(notary, request.length, circuits, progressMonitor);
    // tls is an instance of class TLS. Used to speak to the webserver.
    this.tls = new TLS(server, port, request, sessionOptions);
    // probeTLS is used to probe the webserver to see if it supports TLSNotary,
    // before we start any time-intensive 2PC
    this.probeTLS = new TLS(server, port, request, sessionOptions);
    this.request = str2ba(request);
    this.notary = notary;
    this.pm = progressMonitor;
    this.options = null;
  }

  async start(){
    await this.probeTLS.buildAndSendClientHello();
    await this.probeTLS.receiveAndParseServerHello();
    await this.probeTLS.sckt.close();
    await this.twopc.init();
    await this.tls.buildAndSendClientHello();
    const serverEcPubkey = await this.tls.receiveAndParseServerHello();
    if ( this.pm) this.pm.update('last_stage', {'current': 3, 'total': 10});
    const [pmsShare, cpubBytes] = await this.twopc.getECDHShare(serverEcPubkey);
    if ( this.pm) this.pm.update('last_stage', {'current': 4, 'total': 10});

    await this.tls.buildClientKeyExchange(cpubBytes);
    const [cr, sr] = await this.tls.getRandoms();
    const [encCF, tagCF, vdCF] = await this.twopc.run(cr, sr, this.tls.getAllHandshakes(), pmsShare);
    // Finished (0x14) with length 12 (0x0c)
    this.tls.updateAllHandshakes(concatTA(new Uint8Array([0x14, 0x00, 0x00, 0x0c]), vdCF));
    await this.tls.sendClientFinished(encCF, tagCF);
    const encSF = await this.tls.receiveServerFinished();
    await this.twopc.checkServerFinished(encSF, this.tls.getAllHandshakes());
    if ( this.pm) this.pm.update('last_stage', {'current': 5, 'total': 10});

    const encCountersForRequest = await this.twopc.getEncryptedCounters();
    if ( this.pm) this.pm.update('last_stage', {'current': 8, 'total': 10});
    const encRequestBlocks = this.encryptRequest(this.request, encCountersForRequest);
    const gctrBlocks = await this.twopc.getGctrBlocks();
    if ( this.pm) this.pm.update('last_stage', {'current': 9, 'total': 10});
    const [ghashOutputs, ghashInputsBlob] = await this.twopc.getTagFromPowersOfH(encRequestBlocks);
    await this.tls.buildAndSendRequest(gctrBlocks, ghashOutputs, encRequestBlocks);
    const serverRecords = await this.tls.receiveServerResponse();
    await this.tls.sckt.close();

    const commitHash = await TLSNotarySession.computeCommitHash(serverRecords);
    const [cwkShare, civShare, swkShare, sivShare] = this.twopc.getKeyShares();
    const keyShareHash = await sha256(concatTA(cwkShare, civShare, swkShare, sivShare));
    const pmsShareHash = await sha256(pmsShare);
    const data5 = await this.twopc.send('commitHash', concatTA(
      commitHash,
      keyShareHash,
      pmsShareHash));
    this.twopc.destroy();

    let o = 0; // offset
    const signature = data5.slice(o, o+=64);
    const notaryPMSShare = data5.slice(o, o+=32);
    const notaryCwkShare = data5.slice(o, o+=16);
    const notaryCivShare = data5.slice(o, o+=4);
    const notarySwkShare = data5.slice(o, o+=16);
    const notarySivShare = data5.slice(o, o+=4);
    const timeBytes = data5.slice(o, o+=8);
    assert(data5.length == o);

    const [eKey, eValidFrom, eValidUntil, eSigByMasterKey] = this.twopc.getEphemeralKey();

    // convert certPath to DER.
    const certPath = this.tls.getCertPath();
    var certs = [];
    for (let cert of certPath){
      certs.push(new Uint8Array(cert.toSchema(true).toBER(false)));
    }
    if ( this.pm) this.pm.update('last_stage', {'current': 10, 'total': 10});
    return {
      'certificates': certs,
      'notarization time': timeBytes,
      'server RSA sig': this.tls.getRSAsignature(),
      'server pubkey for ECDHE': serverEcPubkey,
      'notary PMS share': notaryPMSShare,
      'client PMS share': pmsShare,
      'client random': cr,
      'server random': sr,
      'notary client_write_key share': notaryCwkShare,
      'notary client_write_iv share': notaryCivShare,
      'notary server_write_key share': notarySwkShare,
      'notary server_write_iv share': notarySivShare,
      'client client_write_key share': cwkShare,
      'client client_write_iv share': civShare,
      'client server_write_key share': swkShare,
      'client server_write_iv share': sivShare,
      'client request ciphertext': ghashInputsBlob,
      'server response records': serverRecords,
      'session signature': signature,
      'ephemeral pubkey': eKey,
      'ephemeral valid from': eValidFrom,
      'ephemeral valid until': eValidUntil,
      'ephemeral signed by master key': eSigByMasterKey,
    };

  }


  // encryptRequest encrypts (i.e. XORs) the plaintext request with encrypted counter blocks.
  // (This is how AES-GCM encryption works - first counter blocks are AES-ECB-encrypted,
  // then encrypted counter blocks are XORes with the plaintext to get the ciphertext.)
  encryptRequest(request, encCounterBlocks){
    assert(Math.ceil(request.length/16) === encCounterBlocks.length);
    const encRequestBlocks = [];
    for (let i=0; i < encCounterBlocks.length; i++){
      if (i == encCounterBlocks.length-1){
        // last block, make sure arrays are of the same length before xoring
        let lastBlockLen = this.request.length - i*16;
        encRequestBlocks.push(xor(encCounterBlocks[i].slice(0, lastBlockLen), this.request.slice(i*16)));
      }
      else {
        encRequestBlocks.push(xor(encCounterBlocks[i], this.request.slice(i*16, i*16+16)));
      }
    }
    return encRequestBlocks;
  }


  // computeCommitHash computes a hash over all TLS records with MACs
  static async computeCommitHash(encRecords){
    return await sha256(concatTA(...encRecords));
  }
}

