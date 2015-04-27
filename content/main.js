var script_exception;
try {	
var random_uid; //we get a new uid for each notarized page
var reliable_sites = []; //read from content/pubkeys.txt
var previous_session_start_time; // used to make sure user doesnt exceed rate limiting
var verbose = false; //trigger littering of the browser console
var chosen_notary;


function init(){
	if (getPref('verbose', 'bool') === true){
		verbose = true;
	}
	//check if user wants to use a fallback
	if (getPref('fallback', 'bool') === true){
		oracles_intact = true;
		//TODO this should be configurable, e.g. choice from list
		//or set in prefs
		chosen_notary = pagesigner_servers[1];
	}
	else {
		chosen_notary = oracles[Math.random()*(oracles.length) << 0];
		var oracle_hash = ba2hex(sha256(JSON.stringify(chosen_notary)));
		var was_oracle_verified = false;
		if (getPref('verifiedOracles.'+oracle_hash, 'bool') === true){
			was_oracle_verified = true;	
		}
		if (! was_oracle_verified){
			//async check oracles and if the check fails, sets a global var
			//which prevents notarization session from running
			log('oracle not verified');
			var main_pubkey = {pubkey:''};
			check_oracle(chosen_notary.main, 'main', main_pubkey).
			then(function(){
				check_oracle(chosen_notary.sig, 'sig',  main_pubkey);
			}).
			then(function success(){
				setPref('verifiedOracles.'+oracle_hash, 'bool', true);
				oracles_intact = true;
			}).
			catch(function(err){
				log('caught error', err);
				//query for a new oracle
				//TODO fetch backup oracles list
			});
		}
		else {
			oracles_intact = true;
		}
	}
	import_reliable_sites();
	startListening();
}


function parse_reliable_sites(text){
	var lines = text.split('\n');
	var name = "";
	var expires = "";
	var modulus = [];
	var i = -1;
	var x;
	var mod_str;
	var line;
	while (true){
		i += 1;
		if (i >= lines.length){
			break;
		}
		x = lines[i];
		if (x.startsWith('#')){
			continue;
		}
		else if (x.startsWith('Name=')){
			name = x.slice('Name='.length);
		}
		else if (x.startsWith('Expires=')){
			expires = x.slice('Expires='.length);
		}
		else if (x.startsWith('Modulus=')){
			mod_str = '';
			while (true){
				i += 1;
				if (i >= lines.length){
					break;
				}
				line = lines[i];
				if (line === ''){
					break;
				}
				mod_str += line;
			}
			modulus = [];
			var bytes = mod_str.split(' ');
			for (var j=0; j < bytes.length; j++){
				if (bytes[j] === ''){
					continue;
				}
				modulus.push( hex2ba(bytes[j])[0] );
			}
			//Don't use pubkeys which expire less than 3 months from now
			var ex = expires.split('/');
			var extime = new Date(parseInt(ex[2]), parseInt(ex[0])-1, parseInt(ex[1]) ).getTime();
			var now = new Date().getTime();
			if ( (extime - now) < 1000*60*60*24*90){
				continue;
			}
			reliable_sites.push( {'name':name, 'expires':expires, 'modulus':modulus} );		
			}
		}	
}




//callback is used in testing to signal when this page's n10n finished
function startNotarizing(callback){
	if (! oracles_intact){
		alert('Cannot notarize because something is wrong \
			with PageSigner server. Please try again later');
		return;
	}
	var retval = getHeaders();
	if (retval === false){
		return; //there was an error
	}
	var headers = retval;
	var server = headers.split('\r\n')[1].split(':')[1].replace(/ /g,'');
	
	loadBusyIcon();
	  
	var modulus;
	var certsha256;
	get_certificate(server).then(function(cert){
		log('got certificate');
		if (! verifyCert(cert)){
			alert("This website cannot be audited by PageSigner because it presented an untrusted certificate");
			return;
		}
		modulus = getModulus(cert);
		certsha256 = sha256(cert);
		random_uid = Math.random().toString(36).slice(-10);
		previous_session_start_time = new Date().getTime();
		//loop prepare_pms 10 times until succeeds
		return new Promise(function(resolve, reject) {
			var tries = 0;
			var loop = function(resolve, reject){
				tries += 1;
				prepare_pms(modulus).then(function(args){
					resolve(args);
				}).catch(function(error){
					log('caught error', error);
					if (error.startsWith('Timed out')){
						reject(error);
						return;
					}
					if (error != 'PMS trial failed'){
						reject('in prepare_pms: caught error ' + error);
						return;
					}
					if (tries == 10){
						reject('Could not prepare PMS after 10 tries');
						return;
					}
					//else PMS trial failed
					loop(resolve, reject);
				});
			};
			loop(resolve, reject);
		});
	})
	.then(function(args){
		return start_audit(modulus, certsha256, server, headers, args[0], args[1], args[2]);
	})
	.then(function(args2){
		return save_session_and_open_html(args2, server);
	})
	.then(function(){
		//testing only
		if (testing){
			callback();
		}
		loadNormalIcon();
	})
	.catch(function(err){
	 //TODO need to get a decent stack trace
	 	loadNormalIcon();
		log('There was an error: ' + err);
		if (err.startsWith('Timed out waiting for notary server to respond') &&
			((new Date().getTime() - previous_session_start_time) < 60*1000) ){
			alert ('You are signing pages way too fast. Please retry in 60 seconds.');
		}
		else {
			alert('There was an error: ' + err);
		}
	});
}



function save_session_and_open_html(args, server){
	assert (args.length === 17, "wrong args length");
	var cipher_suite = args[0];
	var client_random = args[1];
	var server_random = args[2];
	var pms1 = args[3];
	var pms2 = args[4];
	var server_certchain = args[5];
	var tlsver = args[6];
	var initial_tlsver = args[7];
	var fullresp_length = args[8];
	var fullresp = args[9];
	var IV_after_finished_length = args[10];
	var IV_after_finished = args[11];
	var notary_modulus_length = args[12];
	var signature = args[13];
	var commit_hash = args[14];
	var notary_modulus = args[15];
	var html_with_headers = args[16];
	
	var server_chain_serialized = []; //3-byte length prefix followed by cert
	for (var i=0; i < server_certchain.length; i++){
		var cert = server_certchain[i];
		server_chain_serialized = [].concat(
			server_chain_serialized,
			bi2ba(cert.length, {'fixed':3}),
			cert);
	}
	
	var pgsg = ba2ua([].concat(
			str2ba('tlsnotary notarization file\n\n'),
			[0x00, 0x01],
			bi2ba(cipher_suite, {'fixed':2}),
			client_random,
			server_random,
			pms1,
			pms2,
			bi2ba(server_chain_serialized.length, {'fixed':3}),
			server_chain_serialized,
			tlsver,
			initial_tlsver,
			bi2ba(fullresp_length, {'fixed':8}),
			fullresp,
			bi2ba(IV_after_finished_length, {'fixed':2}),
			IV_after_finished,
			bi2ba(notary_modulus_length, {'fixed':2}),
			signature,
			commit_hash,
			notary_modulus));
			
	var commonName = getCommonName(server_certchain[0]);
	var sdir = makeSessionDir(server);
	create_final_html(html_with_headers, sdir)
	.then(writePgsg(pgsg, sdir, commonName))
	.then(openTabs(sdir, commonName));
}


function verify_tlsn(imported_data, from_past){
var data = ua2ba(imported_data);
	var offset = 0;
	if (ba2str(data.slice(offset, offset+=29)) !== "tlsnotary notarization file\n\n"){
		throw('wrong header');
	}
	if(data.slice(offset, offset+=2).toString() !== [0x00, 0x01].toString()){
		throw('wrong version');
	}
	var cs = ba2int(data.slice(offset, offset+=2));
	var cr = data.slice(offset, offset+=32);
	var sr = data.slice(offset, offset+=32);
	var pms1 = data.slice(offset, offset+=24);
	var pms2 = data.slice(offset, offset+=24);
	var chain_serialized_len = ba2int(data.slice(offset, offset+=3));
	var chain_serialized = data.slice(offset, offset+=chain_serialized_len);
	var tlsver = data.slice(offset, offset+=2);
	var tlsver_initial = data.slice(offset, offset+=2);
	var response_len = ba2int(data.slice(offset, offset+=8));
	var response = data.slice(offset, offset+=response_len);
	var IV_len = ba2int(data.slice(offset, offset+=2));
	var IV = data.slice(offset, offset+=IV_len);
	var sig_len = ba2int(data.slice(offset, offset+=2));
	var sig = data.slice(offset, offset+=sig_len);
	var commit_hash = data.slice(offset, offset+=32);
	var notary_pubkey = data.slice(offset, offset+=sig_len);
	assert (data.length === offset, 'invalid .pgsg length');
	
	offset = 0;
	var chain = []; //For now we only use the 1st cert in the chain
	while(offset < chain_serialized.length){
		var len = ba2int(chain_serialized.slice(offset, offset+=3));
		var cert = chain_serialized.slice(offset, offset+=len);
		chain.push(cert);
	}
	
	var commonName = getCommonName(chain[0]);
	//verify cert
	if (!verifyCert(chain[0])){
		throw ('certificate verification failed');
	}
	var modulus = getModulus(chain[0]);
	//verify commit hash
	if (sha256(response).toString() !== commit_hash.toString()){
		throw ('commit hash mismatch');
	}
	//verify sig
	var signed_data = sha256([].concat(commit_hash, pms2, modulus));
	var signing_key;
	if (from_past){signing_key = notary_pubkey;}
	else {signing_key = chosen_notary.sig.modulus;}
	if (!verify_commithash_signature(signed_data, sig, signing_key)){
		throw ('notary signature verification failed');
	}
	
	//decrypt html and check MAC
	var s = new TLSNClientSession();
	s.__init__();
	s.unexpected_server_app_data_count = response.slice(0,1);
	s.chosen_cipher_suite = cs;
	s.client_random = cr;
	s.server_random = sr;
	s.auditee_secret = pms1.slice(2, 2+s.n_auditee_entropy);
	s.initial_tlsver = tlsver_initial;
	s.tlsver = tlsver;
	s.server_modulus = modulus;
	s.set_auditee_secret();
	s.auditor_secret = pms2.slice(0, s.n_auditor_entropy);
	s.set_auditor_secret();
	s.set_master_secret_half(); //#without arguments sets the whole MS
	s.do_key_expansion(); //#also resets encryption connection state
	s.store_server_app_data_records(response.slice(1));
	s.IV_after_finished = IV;
	s.server_connection_state.seq_no += 1;
	s.server_connection_state.IV = s.IV_after_finished;
	html_with_headers = decrypt_html(s);
	return [html_with_headers,commonName,imported_data, notary_pubkey];
}


function verify_tlsn_and_show_html(path, create){
	readFile(path)
	.then( function(imported_data){
		return verify_tlsn(imported_data, create);
	})
	.then(function (a){
	if (create){
		var html_with_headers = a[0];
		var commonName = a[1];
		var imported_data = a[2];
		var session_dir = makeSessionDir(commonName, true);
		create_final_html(html_with_headers, session_dir)
		.then(writePgsg(imported_data, session_dir, commonName))
		.then(openTabs(session_dir, commonName));
	}
	}).catch( function(error){
		log("got error in vtsh: "+error);
	});
}



//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
browser_specific_init();


} catch (e){
	script_exception = e;
}
