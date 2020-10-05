var trustedCertificates = [];


//extract PEMs from Mozilla's CA store and convert into asn1js's Certificate object
async function parse_certs(){
  //wait for pkijs module to load
  while (typeof(asn1js) == 'undefined'){
    console.log('waiting for pkijs')
    await new Promise(function(resolve, reject) {
      setTimeout(function(){
        resolve();
      }, 100);
    })
  }

  var text = await import_resource('verifychain/certs.txt')
  var lines = text.split('"\n"').slice(1) //discard the first line - headers
  for (let line of lines){
    let fields = line.split('","')
    let pem = fields[32].slice(1,-1);
    let certificateBuffer = pem2ab(pem);
    let asn1cert = asn1js.fromBER(certificateBuffer);
    let c = new Certificate({ schema: asn1cert.result });
    trustedCertificates.push(c)
  } 
}


function getPubkey(c){
    return ab2ba(c.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex)
}


function getModulus(cert_ba) {
  let cert_asn1 = asn1js.fromBER(ba2ab(cert_ba));
  let cert = new Certificate({ schema: cert_asn1.result });
  let modulus_ba = ab2ba(cert.subjectPublicKeyInfo.parsedKey.modulus.valueBlock.valueHex)
  return modulus_ba;
}


//Verify that the common name in the Certificate is the name of the server we are sending to
//Otherwise an attacker can send us his CA-issued certificate for evildomain.com
//and steal HTTP credentials
function checkCertSubjName(cert, server){
  let commonName = getCommonName(cert);
  let alternativeNames = getAlternativeNames(cert);
  let allNames = alternativeNames;
  allNames.push(commonName)

  for (let name of allNames){
    if (wildTest(name, server) == true) 
      return true;
  }
  return false;
}


function getCommonName(cert_ba) {
  let cert_asn = asn1js.fromBER(ba2ab(cert_ba));
  let cert = new Certificate({ schema: cert_asn.result });
  for (let type of cert.subject.typesAndValues){
    if (type.type == '2.5.4.3') {
       return type.value.valueBlock.value;
    }
  }
}


function getAlternativeNames(cert_ba) {
  let cert_asn = asn1js.fromBER(ba2ab(cert_ba));
  let cert = new Certificate({ schema: cert_asn.result });
  let altNames = [];
  for (let ext of cert.extensions){
    if (ext.extnID != '2.5.29.17') continue;
    for (let name of ext.parsedValue.altNames){
      altNames.push(name.value)
    }
  }
  return altNames;
}




//return true/false and an intermediate certificate which was missing in the chain, if any
//verification is against a date in the past when the notarization took place
async function verifyChain(chain_ba, date) {
  let chain = []
  for (let cert_ba of chain_ba){
    let cert_asn1 = asn1js.fromBER(ba2ab(cert_ba));
    let cert = new Certificate({ schema: cert_asn1.result });
    chain.push(cert)
  }

  async function do_verify(chain, date){

    const ccve = new CertificateChainValidationEngine({
          trustedCerts: trustedCertificates,
          certs: chain,
          checkDate: date ? date : new Date()
        });
    
    let pr = await ccve.verify()
    return pr.result
  }

  let rv = await do_verify(chain, date)
  if (chain.length == 1 && rv != true){
    //maybe we must fetch the intermedate cert
    for (let ext of chain[0].extensions){
      if (ext.extnID != '1.3.6.1.5.5.7.1.1') continue;
      for (let ad of ext.parsedValue.accessDescriptions){
        if (ad.accessMethod != '1.3.6.1.5.5.7.48.2') continue;
        let cert_url = ad.accessLocation.value
        let resp = await fetch(cert_url)
        let blob = await resp.blob()
        let certDER = await blob.arrayBuffer()
        let cert_asn1 = asn1js.fromBER(certDER);
        let cert = new Certificate({ schema: cert_asn1.result });
        chain.push(cert)
        let rv = await do_verify(chain)
        //we want to save this intermediate cert
        return [rv, ab2ba(certDER)];
      }
    }
  }

  return [rv]
}


if (typeof module !== 'undefined'){ //we are in node.js environment
  module.exports={
    checkCertSubjName,
    getCommonName,
    getModulus,
    parse_certs,
    verifyChain
  }
}