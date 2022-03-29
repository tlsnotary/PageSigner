export const globals = {
  // defaultNotaryIP/Port is the default IP address/port of the notary server.
  // If this IP address becomes unavailable, Pagesigner will query backupUrl for
  // a new notary's IP address and will save the new IP address in the preferences.
  // defaultNotaryIP: '127.0.0.1',
  defaultNotaryIP: '44.201.26.208',
  defaultNotaryPort: 10011,
  // backupUrl is the URL to query to get the IP address of another notary
  // server in case if defaultNotaryIP is unreachable
  backupUrl: 'https://tlsnotary.org/backup_oracle',
  // use python for raw socket communication
  usePythonBackend: false,
  sessionOptions: {
    // Future use: use max_fragment_length TLS extension
    'useMaxFragmentLength': false,
    // can be set to false during debugging to be able to work with self-signed certs
    'mustVerifyCert': true
  },
  // if useHTTP11 is set to true then we use HTTP/1.1 in the request, otherwise
  // we use HTTP/1.0. Using HTTP/1.0 is the only way to prevent a webserver from using
  // chunked transfer encoding. This may be useful e.g. when webserver response is used
  // inside zk proofs and we want simpler parsing without de-chunking.
  useHTTP11: true,
  // appId is Chrome-only: the id of Chrome app used to send raw TCP packets.
  appId: 'oclohfdjoojomkfddjclanpogcnjhemd',
  // if useNotaryNoSandbox is set to true, then we fetch notary's pubkey by
  // querying /getPubKey and trust it. This is only useful when notary runs
  // in a non-sandbox environment.
  useNotaryNoSandbox: false
  // useNotaryNoSandbox: true
};