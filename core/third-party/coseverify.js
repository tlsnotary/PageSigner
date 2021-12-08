// this file is not used by the extension, it serves as an input to to create cose.js with:
// browserify coseverify.js --standalone COSE > cose.js

//const cose = require('cose-js');
import * as cose from 'cose-js'

// x,y,doc is an ArrayBuffer
export const verify = function (x, y, doc){
    const verifier = {
        'key': {
            'x': Buffer.from(x),
            'y': Buffer.from(y)
        }
    };
      
    cose.sign.verify(
        Buffer.from(doc),
        verifier,
        {defaultType: 18})
            .then((buf) => {
            console.log("Verification successful")
            //console.log('Verified message: ' + buf.toString('utf8'));
            }).catch((error) => {
             console.log(error);
            });  
}

if (typeof module !== 'undefined'){ //we are in node.js environment
    module.exports={
        verify
    }
}