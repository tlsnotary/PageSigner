export function decode_str(str){
  try {
    return decodeURIComponent(escape(str));
  }
  catch (err){
    // not a utf-encoded string
    return str;
  }
}

export function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || 'Assertion failed';
  }
}

// converts string to byte array
export function str2ba(str) {
  if (typeof(str) !== 'string') {
    throw ('Only type string is allowed in str2ba');
  }
  const ba = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    ba[i] = str.charCodeAt(i);
  }
  return ba;
}