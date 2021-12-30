import {pem2ba, eq} from './utils.js';
import * as asn1js from './third-party/pkijs/asn1.js';
import Certificate from './third-party/pkijs/Certificate.js';
import CertificateChainValidationEngine from
  './third-party/pkijs/CertificateChainValidationEngine.js';

var trustedCertificates = [];

// extract PEMs from Mozilla's CA store and convert into asn1js's Certificate object
export async function parse_certs(text){
  // wait for pkijs module to load
  while (typeof(asn1js) == 'undefined'){
    console.log('waiting for pkijs');
    await new Promise(function(resolve) {
      setTimeout(function(){
        resolve();
      }, 100);
    });
  }

  const lines = text.split('"\n"').slice(1); // discard the first line - headers
  for (const line of lines){
    const fields = line.split('","');
    const pem = fields[32].slice(1, -1);
    const asn1cert = asn1js.fromBER(pem2ba(pem).buffer);
    trustedCertificates.push(new Certificate({ schema: asn1cert.result }));
  }
}


// Verify that the common name in the Certificate is the name of the server we are sending to
// Otherwise an attacker can send us his CA-issued certificate for evildomain.com
export function checkCertSubjName(cert, serverName){
  let commonName = getCommonName(cert);
  let alternativeNames = getAltNames(cert);
  let allNames = alternativeNames;
  allNames.push(commonName);

  // test a string against a string with a wildcard
  function wildTest(wildcardStr, str) {
    var index = wildcardStr.indexOf('*');
    if (index > -1){
      // if wildcard has an asterisk then we match from the end up to the asterisk
      var substringAfterAsterisk = wildcardStr.slice(index+1);
      return str.endsWith(substringAfterAsterisk);
    }
    else{
      // if it doesnt contain an asterisk then wildcard must be equal to str
      return (wildcardStr == str);
    }
  }

  for (let nameInCert of allNames){
    if (wildTest(nameInCert, serverName) == true)
      return true;
  }
  throw 'Server name is not the same as the certificate\'s subject name(s)';
}


export function getCommonName(cert) {
  for (let type of cert.subject.typesAndValues){
    if (type.type == '2.5.4.3') {
      return type.value.valueBlock.value;
    }
  }
}


export function getAltNames(cert) {
  let altNames = [];
  if (cert.extensions){
    for (let ext of cert.extensions){
      if (ext.extnID != '2.5.29.17') continue;
      for (let name of ext.parsedValue.altNames){
        altNames.push(name.value);
      }
    }
  }
  return altNames;
}




// verifyChain verifies a certificate chain "chain_der" against the time "date". If "date" is not
// given, verifies againt the current time.
// Returns true on success or throws if verification failed.
// Sometimes servers do not put intermediate certs into the chain. In such case we
// fetch the missing cert from a URL embedded in the leaf cert. We return the fetched cert.
export async function verifyChain(chain_der, date, trustedCerts) {
  if (trustedCerts == undefined){
    trustedCerts = trustedCertificates;
  }
  if (chain_der.length > 7){
    // prevent DOS from having to parse large chains
    throw ('Error: cannot parse an unusually large certificate chain.');
  }
  // convert each der certificate into a Certificate object
  const chain = [];
  for (const cert_der of chain_der){
    const cert_asn1 = asn1js.fromBER(cert_der.buffer);
    const cert = new Certificate({ schema: cert_asn1.result });
    chain.push(cert);
  }


  async function do_verify(chain, date, trustedCerts){
    // CertificateChainValidationEngine will fail the verification if the root cert is
    // included in the chain. To prevent this, we remove the root CA from the chain.
    // Check by pubkey if the last cert is a root CA known to us.

    var pubkeyToFind = new Uint8Array(chain.slice(-1)[0].subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
    for (let cert of trustedCerts){
      if (eq(new Uint8Array(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex), pubkeyToFind)){
        chain = chain.slice(0, -1);
        break;
      }
    }

    // pkijs requires that the leaf cert is last in the array
    // if not, the verification will still succeed, but the returned certificatePath
    // will be incomplete
    var leafCert = chain.splice(0, 1)[0];
    chain.push(leafCert);
    const ccve = new CertificateChainValidationEngine({
      trustedCerts: trustedCerts,
      certs: chain,
      checkDate: date ? date : new Date()
    });
    let rv = await ccve.verify();
    return rv;
  }

  let rv = await do_verify(chain, date, trustedCerts);
  if (chain.length == 1 && rv.result == false && chain[0].extensions != undefined){
    for (let ext of chain[0].extensions){
      if (ext.extnID != '1.3.6.1.5.5.7.1.1') continue;
      for (let ad of ext.parsedValue.accessDescriptions){
        if (ad.accessMethod != '1.3.6.1.5.5.7.48.2') continue;
        let cert_url = ad.accessLocation.value;
        let resp = await fetch(cert_url, {
          method: 'POST',
          mode: 'cors',
          cache: 'no-store',
        });
        let blob = await resp.blob();
        let certDER = await blob.arrayBuffer();
        let cert_asn1 = asn1js.fromBER(certDER);
        let cert = new Certificate({ schema: cert_asn1.result });
        chain.push(cert);
        rv = await do_verify(chain);
      }
    }
  }
  if (rv.result == false){
    throw ('Could not notarize because the website presented an untrusted certificate');
  }
  return rv;
}