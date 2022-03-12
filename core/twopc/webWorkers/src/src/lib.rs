#! [allow(non_snake_case)]
#! [allow(non_upper_case_globals)]

use core::slice::{from_raw_parts_mut, from_raw_parts};

// when debugging, uncomment the imports below,
// add #[wasm_bindgen] to the function and insert on 1st line of function:
// panic::set_hook(Box::new(console_error_panic_hook::hook));

//use wasm_bindgen::prelude::*;
//use web_sys::console;
//extern crate console_error_panic_hook;
//use std::panic;

// We are trying to make as many vars global as possible. It sacrifices code readability
// but the performance gains are worth it (~20% gains).

static mut gatesCount: u32 = 0;
static mut wiresCount: u32 = 0;
static mut andGateCount: u32 = 0;
static mut notaryInputSize: u32 = 0;
static mut clientInputSize: u32 = 0;
static mut outputSize: u32 = 0;

// gates is parsed gates
static mut gates: Vec<Gate> = Vec::new();
// ga is garbling assignment: all wires with their labels
static mut ga: Vec<[[u8; 16]; 2]> = Vec::new();
// ea is evaluating assignment: one label per wire
static mut ea: Vec<[u8; 16]> = Vec::new();
// R is circuit's delta (garbler only)
static mut R: [u8; 16] = [0; 16];

// resumeFrom saves the gate number from which we will resume
static mut resumeFrom: usize = 0;
// andIdx is index of the AND gate that was processed so far
static mut andIdx: usize = 0;

// m is malloc()ed pointer to shared memory between wasm and JS
static mut m: u32 = 0;
// ipc1 points to a 20-byte buffer for IPC. wasm puts 16-byte data to be salsaed and a
// 4-byte tweak and reads the salsaed result (the first 16 bytes).
static mut ipc1: &mut [u8] = &mut [0; 0];
// ipc2 points to a 48-byte buffer for IPC. wasm puts data to be salsaed,
// JS puts the result of salsaing.
static mut ipc2: &mut [u8] = &mut [0; 0];
// output points to output (for garbler it is decoding table, for evaluator it 
// is encoded output)
static mut output: &mut [u8] = &mut [0; 0];
// tt points to truth tables
static mut tt: &mut [u8] = &mut [0; 0];
// il points to input labels
static mut il: &mut [u8] = &mut [0; 0];
// gatesBuf points to serialized gates description
static mut gatesBuf: &[u8] = &[0; 0];
// randBuf points to crypto random data supplied by JS
static mut randBuf: &[u8] = &[0; 0];
// g points to a gate currently being processed
static mut g: &Gate = &Gate{op:0, in1:0, in2:0, out:0};


// xor* are values that need to be xored to randomOracle's output
// to get an encrypted row
static mut xor0: [u8; 16] = [0; 16];
static mut xor1: [u8; 16] = [0; 16];
static mut xor2: [u8; 16] = [0; 16];
// rows contains info about rows of 1 specific AND gate
static mut rows: Vec<Row> = Vec::new();
static mut idxToReduce: u8 = 0;
// a2 and b4 used in encrypt();
static mut a2: [u8; 16] = [0; 16];
static mut b4: [u8; 16] = [0; 16];
// a and b a re return values of encrypt()
static mut a: [u8; 16] = [0; 16];
static mut b: [u8; 16] = [0; 16];

#[derive(Default, Clone)]
struct Gate {
    // gate operation {'XOR': 0, 'AND': 1, 'INV': 2};
    op: u8,
    // first input wire number
    in1: u32,
    // second input wire number
    in2: u32,
    // output wire number
    out: u32,
}

struct Row <'a>{
    in1: &'a[u8; 16],
    in2: &'a[u8; 16],
    outNo: u8,
}

#[no_mangle]
pub fn startEvaluator() {
    unsafe {
        resumeFrom = 0;
        andIdx = 0;
        // set input labels
        for i in 0..(notaryInputSize + clientInputSize) as usize {
            ea[i].copy_from_slice(&il[i*16..i*16+16]);
        }        
    }
   return;
}

#[no_mangle]
pub fn startGarbler() {
    unsafe {
        resumeFrom = 0;
        andIdx = 0;
        idxToReduce = 99;

        R.copy_from_slice(&randBuf[0..16]);
        R[15] = R[15] | 0x01;
    
        // generate input labels
        for i in 0..(notaryInputSize + clientInputSize) as usize {
            let mut label0: [u8; 16] = [0; 16];
            label0.copy_from_slice(&randBuf[16 + i * 16..16 + (i + 1) * 16]);
            let label1 = xor(&label0, &R);
            ga[i] = [label0, label1];
        }
    }
   return;
}

#[no_mangle]
//#[wasm_bindgen]
// resume after AND gate was processed. Back to normal gate-by-gate
pub fn resumeGarbler_0() {
    unsafe {
        if resumeFrom > 0 || andIdx+1 == andGateCount as usize{
           finishLastANDGate();
        }

        let mut lastIdx = 0;
        for i in resumeFrom..gates.len() {
            lastIdx = i as u32;
            g = &gates[i];
            if g.op == 1 {
                // garbleAndStage1 will implicitly return values in globals a and b
                garbleAndStage1();
                ipc1[0..16].copy_from_slice(&a);
                ipc1[16..20].copy_from_slice(&i.to_be_bytes());
                xor0 = b;
                resumeFrom = i;
                return;
            } else if g.op == 0 {
                garbleXor();
            } else if g.op == 2 {
                garbleNot();
            } else {
                panic!("unknown gate op");
            }
        }
        assert!(gatesCount == lastIdx+1);
        return;
    }
}


#[no_mangle]
//#[wasm_bindgen]
// resume after AND gate was processed. Back to normal gate-by-gate
pub fn resumeEvaluator_0() {
    unsafe {
        // this is the last step of the previous AND gate
        if resumeFrom > 0 {
            let out = gates[resumeFrom].out;
            ea[out as usize] = xor(&ipc1[0..16], &xor0);
            andIdx += 1;
            resumeFrom += 1;
        }

        // proceed gate by gate
        let mut lastIdx = 0;
        for i in resumeFrom..gates.len() {
            lastIdx = i as u32;
            g = &gates[i];
            if g.op == 1 {
                // evaluateAndStage1 will implicitly return values in globals a and b
                evaluateAndStage1();
                ipc1[0..16].copy_from_slice(&a);
                ipc1[16..20].copy_from_slice(&i.to_be_bytes());
                xor0 = b;
                resumeFrom = i;
                return;
            } else if g.op == 0 {
                evaluateXor();
            } else if g.op == 2 {
                evaluateNot();
            } else {
                panic!("unknown gate op");
            }
        }
        assert!(gatesCount == lastIdx+1);
        return;
    }
}



#[no_mangle]
//#[wasm_bindgen]
// resume after 1 Salsa invocation
pub fn resumeGarbler_1() {
    unsafe {
        let outWire = xor(&ipc1[0..16], &xor0);
        let mut outLabels: [[u8; 16]; 2] = [[0;16];2];
        if idxToReduce == 3 {
            outLabels[0] = xor(&outWire, &R);
            outLabels[1] = outWire;
        } else {
            outLabels[0] = outWire;
            outLabels[1] = xor(&outWire, &R);            
        }

        let out = gates[resumeFrom].out;
        ga[out as usize][0] = outLabels[0];
        ga[out as usize][1] = outLabels[1];

        for i in 0..rows.len(){
            if i == idxToReduce as usize {
                continue;
            }
            encrypt(&rows[i].in1, &rows[i].in2, &outLabels[rows[i].outNo as usize]);
            let point = (2 * getPoint(&rows[i].in1) + getPoint(&rows[i].in2)) as usize;
            ipc2[point*16..(point+1)*16].copy_from_slice(&a);
            if point == 0 {
                xor0 = b;
            }
            else if point == 1 {
                xor1 = b;
            }
            else if point == 2 {
                xor2 = b;
            }
            else {
                panic!("wrong point");
            }
        }
    }
}

#[no_mangle]
// final touches after all salsa invocations:
// xor the data from JS with saved data to finish row encryption
pub fn finishLastANDGate() {
    unsafe {
        tt[andIdx*   48..andIdx*48+16].copy_from_slice(&xor( &xor0, &ipc2[0..16]));
        tt[andIdx*48+16..andIdx*48+32].copy_from_slice(&xor( &xor1, &ipc2[16..32]));
        tt[andIdx*48+32..andIdx*48+48].copy_from_slice(&xor( &xor2, &ipc2[32..48]));
        andIdx += 1;
        resumeFrom += 1;
    }
}

#[no_mangle]
//#[wasm_bindgen]
// finishGarbler is called after garbling of all AND gates has been done
// to output the output labels and input labels. (the truth tables are already
// sitting in the output buffer).
pub fn finishGarbler() {
    unsafe {
        // finish with the remaining non-AND gates
        resumeGarbler_0();

        let roundedUp = ((outputSize+7)/8) as usize;
        let mut bits: Vec<u8> = vec![0; roundedUp*8];
        for i in 0..outputSize as usize {
            // get decoding table: LSB of label0 for each output wire
            bits[i] = ga[ga.len() - outputSize as usize + i][0][15] & 1
        }
        output.copy_from_slice(&bitsToBytes(&bits));

        // input label size: how many input label pairs there are
        let ils = (notaryInputSize + clientInputSize) as usize;
        for i in 0..ils {
            il[i*   32..i*32+16].copy_from_slice(&ga[i][0]);
            il[i*32+16..i*32+32].copy_from_slice(&ga[i][1]);
        }
    }
}

// convert a string of bits with LSB at index 0 into big-endian bytes
fn bitsToBytes(bits: &Vec<u8>) -> Vec<u8> {
    let mut outBytes: Vec<u8> = vec![0; bits.len()/8];
    let byteLen = outBytes.len();
    for i in 0..byteLen {
        let eightBits = &bits[i*8..i*8+8];
        let mut byte: u8 = 0;
        for j in 0..8 {
            byte <<= 1;
            byte ^= eightBits[7-j]
        }
        outBytes[byteLen-1 - i] = byte
    }
    return outBytes
}

#[no_mangle]
//#[wasm_bindgen]
// finishEvaluator is called after garbling of all AND gates has been done
// to output the encoded output
pub fn finishEvaluator() {
    //panic::set_hook(Box::new(console_error_panic_hook::hook));
    
    unsafe {
        // finish with the remaining non-AND gates
        resumeEvaluator_0();

        let roundedUp = ((outputSize+7)/8) as usize;
        let mut bits: Vec<u8> = vec![0; roundedUp*8];
        for i in 0..outputSize as usize {
            // get encoded bits: LSB of label0 for each output wire
            bits[i] = ea[ea.len() - outputSize as usize + i][15] & 1
        }
        let encodedBytes = bitsToBytes(&bits);
        output.copy_from_slice(&encodedBytes);  
    }
}


fn garbleXor() {
    unsafe {
        ga[g.out as usize][0] = xor(&ga[g.in1 as usize][0], &ga[g.in2 as usize][0]);
        ga[g.out as usize][1] = xor(&ga[g.out as usize][0], &R);
    }
}

fn evaluateXor() {
    unsafe {
        let in1 = &ea[g.in1 as usize];
        let in2 = &ea[g.in2 as usize];
        ea[g.out as usize] = xor(in1, in2);
    }
}

fn garbleNot() {
    unsafe {
        ga[g.out as usize][0] = ga[g.in1 as usize][1];
        ga[g.out as usize][1] = ga[g.in1 as usize][0];
    }
}

fn evaluateNot() {
    unsafe {
        ea[g.out as usize] = ea[g.in1 as usize];
    }
}

fn garbleAndStage1() {
    unsafe {
        let in1_0 = &ga[g.in1 as usize][0];
        let in1_1 = &ga[g.in1 as usize][1];
        let in2_0 = &ga[g.in2 as usize][0];
        let in2_1 = &ga[g.in2 as usize][1];
        rows = vec![
            Row {in1: in1_0, in2: in2_0, outNo: 0,},
            Row {in1: in1_0, in2: in2_1, outNo: 0,},
            Row {in1: in1_1, in2: in2_0, outNo: 0,},
            Row {in1: in1_1, in2: in2_1, outNo: 1,}];

        for i in 0..rows.len() {
            if getPoint(&rows[i].in1) == 1 && getPoint(&rows[i].in2) == 1 {
                idxToReduce = i as u8;
                // encrypt implicitly returns in a and b
                encrypt(&rows[i].in1, &rows[i].in2, &[0; 16]);
                break;
            }
        }
        assert!(idxToReduce != 99);
    }
}

fn evaluateAndStage1() {
    unsafe {
        let label1 = &ea[g.in1 as usize];
        let label2 = &ea[g.in2 as usize];
        let mut cipher: [u8; 16] = [0; 16]; // if point == 3, we will keep it zeroed
        let point = (2 * getPoint(label1) + getPoint(label2)) as usize;
        if point != 3 {
            cipher.copy_from_slice(&tt[andIdx*48+16*point..andIdx*48+16*point+16]);
        }
        // decrypt implicitly returns in globals a and b 
        decrypt(label1, label2, &cipher);
    }
}

fn getPoint(label: &[u8; 16]) -> u8 {
    return label[15] & 0x01;
}

fn decrypt(a_: &[u8; 16], b_: &[u8; 16], m_: &[u8; 16]){
    encrypt(a_, b_, m_); 
}

fn encrypt(a_: &[u8; 16], b_: &[u8; 16], m_: &[u8; 16]) {
    unsafe {
        a2.copy_from_slice(a_);
        let leastbyte = a2[0];
        a2.copy_within(1..15, 0);
        a2[14] = leastbyte;

        b4.copy_from_slice(b_);
        let leastbyte0 = b4[0];
        let leastbyte1 = b4[1];
        b4.copy_within(2..15, 0);
        b4[13] = leastbyte0;
        b4[14] = leastbyte1;

        // return mid-state of encryption:
        // a must be hashed with Salsa and the result xored with b
        a = xor(&a2, &b4);
        b = xor(&a, m_);
    }
}


fn threeBytesToInt(b_: &[u8]) -> u32 {
    return b_[2] as u32 + b_[1] as u32 * 256 + b_[0] as u32 * 65536;
}

// xors 16-byte slices
fn xor(a_: &[u8], b_: &[u8]) -> [u8; 16] {
    let mut c: [u8; 16] = [0; 16];
    for i in 0..16 {
        c[i] = a_[i] ^ b_[i];
    }
    return c;
}

#[no_mangle]
//#[wasm_bindgen]
pub fn parseGatesBlob() {
    unsafe {
        gates = vec![Gate::default(); gatesCount as usize];
        for i in 0..gatesCount as usize {
            let blob: Vec<u8> = gatesBuf[i * 10..(i + 1) * 10].to_vec();
            let gate: Gate = Gate {
                op: (blob[0]),
                in1: (threeBytesToInt(&blob[1..4])),
                in2: (threeBytesToInt(&blob[4..7])),
                out: (threeBytesToInt(&blob[7..10])),
            };
            gates[i] = gate;
        }
    }
}

#[no_mangle]
//#[wasm_bindgen]
pub fn initAll(
    gatesCount_: u32,
    wiresCount_: u32,
    notaryInputSize_: u32,
    clientInputSize_: u32,
    outputSize_: u32,
    andGateCount_: u32,
) -> u32 {
    unsafe {
        gatesCount = gatesCount_;
        wiresCount = wiresCount_;
        notaryInputSize = notaryInputSize_;
        clientInputSize = clientInputSize_;
        outputSize = outputSize_;
        andGateCount = andGateCount_;
        
        // memory needs to be allocated for:
        let mut total = 0;
        // IPC buffer 1 of 20 bytes
        total += 20;
        // IPC buffer 2 of 48 bytes (garbler only)
        total += 48;
        // gates blob
        total += gatesCount * 10;
        // random blob (used by garbler only)
        total += (notaryInputSize + clientInputSize + 1) * 16;
        // output
        total += (outputSize+7)/8;
        // truth tables
        total += andGateCount * 48;
        // input lables
        total += (notaryInputSize + clientInputSize) * 32;
        m = malloc(total as usize) as u32;

        // o is memory offset
        let mut o = m;
        ipc1 = from_raw_parts_mut(o as *mut u8, 20);
        o += 20;
        ipc2 = from_raw_parts_mut(o as *mut u8, 48);
        o += 48;
        gatesBuf = from_raw_parts(o as *mut u8, (gatesCount * 10)as usize);
        o += gatesCount * 10;
        let randSize = (notaryInputSize + clientInputSize + 1) * 16;
        randBuf = from_raw_parts(o as *mut u8, randSize as usize);
        o += randSize;
        output = from_raw_parts_mut(o as *mut u8, ((outputSize+7)/8) as usize);
        o += (outputSize+7)/8;
        tt = from_raw_parts_mut(o as *mut u8, (andGateCount * 48) as usize);
        o += andGateCount * 48;
        il = from_raw_parts_mut(o as *mut u8, ((notaryInputSize + clientInputSize)*32) as usize);
        ga = vec![[[0; 16]; 2]; wiresCount as usize];
        ea = vec![[0; 16]; wiresCount as usize];
        return m;
    }
}

// allocates memory
fn malloc(size: usize) -> *mut u8 {
    let mut buf: Vec<u8> = vec![0; size];
    let ptr = buf.as_mut_ptr();
    // take ownership of the memory block and
    // ensure that its destructor is not
    // called when the object goes out of scope
    // at the end of the function
    std::mem::forget(buf);
    return ptr;
}
