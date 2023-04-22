use entropy::shannon_entropy;
use std::io::{BufReader,Read};
use std::fs::{File};
use clap::Parser;
use std::time::Instant;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};

// Command line argument parser
/// Proof of concept for a ChaCha20 implementation with reduced IO page entropy 
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the target file
    #[arg(long)]
    path: String,
    /// Value of bytes to encrypt after 
    #[arg(long)]
    stripe: usize,
    /// Value of bytes to skip after 
    #[arg(long)]
    skip: usize,
    /// Display in data mode
    #[arg(long, short, action)]
    data: bool,
}

// Struct to collect results match results per file
#[derive(Serialize, Deserialize)]
struct TestResult {
    filename: String,
    stripeValue: usize,
    skipValue: usize,
    initialEntropy: f32,
    readTime: f32,
    fullEncryptionEntropy: f32,
    fullEncryptionTime: f32,
    fullEncryptionEntropyDelta: f32,
    stripedEncryptionEntropy: f32,
    stripedEncryptionTime: f32,
    stripedEncrptionEntropyDelta: f32,
}

// Function to return the Shannon entropy of a sequence of bytes
fn get_shannon_entropy(bytes: &[u8]) -> f32 {
    let sh_entropy = shannon_entropy(bytes);
    sh_entropy
}

// Function to open a file and read the contents into a byte sequence
fn read_file(file: String) -> Vec<u8> {
    let f = BufReader::new(File::open(file).unwrap());

    let mut bytes: Vec<u8> = Vec::new();

    for byte in f.bytes() {
        let result = byte.unwrap();
        //println!("{}", result);
        bytes.push(result);
    }

    return bytes;

}

// Function to ChaCha20 encrypt a byte sequence and return the encrypted sequence
fn chacha20_encrypt(bytes: &[u8]) -> Vec<u8>{

    let plaintext = bytes;

    // Declare a dummy key consisting of at least 32 bytes
    let key = [0x42; 32];

    // Declare a dummy nonce consisting of at least 12 bytes
    let nonce = [0x24; 12];

    // Create keystream and plaintext buffer to operate on
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut buffer = plaintext.clone().to_owned();

    // Apply the keystream to the plaintext
    cipher.apply_keystream(&mut buffer);

    return buffer;

}

fn striped_encryption_coordinator(bytes: Vec<u8>, stripe:usize, skip: usize) -> Vec<u8> {

    let mut ciphertext = bytes;
    let mut pointer = 0;

    let len = ciphertext.len();

    // Iterate the entire file, encrypting 64 bytes and then skipping 192 bytes
    while pointer < len {

        // Borrow 64 bytes from the plaintext starting at the pointer
        let encryption_target = &ciphertext[pointer..pointer + stripe];

        // Encrypt the borrowed bytes
        let encrypted_slice = chacha20_encrypt(&encryption_target);

        // Insert the borrowed bytes into the ciphertext by iterating from the pointer
        for byte in encrypted_slice{
            ciphertext[pointer] = byte;
            pointer = pointer + 1;
        }

        // Iterate the pointer to skip a segment of the the file
        pointer = pointer + skip;

    }

    return ciphertext;

}

// Entrypoint
fn main() {

    let args = Args::parse();
    let file = args.path;
    let stripe = args.stripe;
    let skip = args.skip;
    let data_mode = args.data;

    // Show the starting entropy of the file
    let read_start = Instant::now(); 
    let file_bytes = read_file(file.clone());
    let read_finish = read_start.elapsed().as_secs_f32();
    let file_len = file_bytes.len();
    let starting_entropy = get_shannon_entropy(&file_bytes);

    // Perform a full ChaCha20 encryption on a file & caclulate the entropy
    let full_encryption_start = Instant::now(); 
    let full_encryption = chacha20_encrypt(&file_bytes);
    let full_encryption_finish = full_encryption_start.elapsed().as_secs_f32();
    let full_encryption_entropy = get_shannon_entropy(&full_encryption);
    let full_encryption_entropy_delta = full_encryption_entropy - starting_entropy;


    // Perform a striped ChaCha20 encryption on a file & caclulate the entropy
    let striped_encryption_start = Instant::now(); 
    let striped_ecnryption = striped_encryption_coordinator(file_bytes.clone(), stripe, skip);
    let striped_encryption_finish = striped_encryption_start.elapsed().as_secs_f32();
    let striped_encryption_entropy = get_shannon_entropy(&striped_ecnryption);
    let striped_encryption_entropy_delta = striped_encryption_entropy - starting_entropy;

    if data_mode == false {

        println!("File name: {}", &file);
        println!("Encryption stripe value: {}", stripe);
        println!("Skip stripe value: {}", skip);
        println!("File byte length: {}", file_len);
        println!("Initial file entropy: {}", starting_entropy);
        println!("File read elapsed time: {:.2?}", read_finish);
    
        println!("Full encryption file entropy: {}", full_encryption_entropy);
        println!("Full encryption elapsed time: {:.2?}", full_encryption_finish);
        println!("Full encryption entropy delta: {}", full_encryption_entropy_delta);
    
        println!("Striped encryption file entropy: {}", striped_encryption_entropy);
        println!("Striped encryption elapsed time: {:.2?}", striped_encryption_finish);
        println!("Striped encryption entropy delta: {}", striped_encryption_entropy_delta);
    
    } else {

        let test_result = TestResult {
            filename: file,
            stripeValue: stripe,
            skipValue: skip,
            initialEntropy: starting_entropy,
            readTime: read_finish,
            fullEncryptionEntropy: full_encryption_entropy,
            fullEncryptionTime: full_encryption_finish,
            fullEncryptionEntropyDelta: full_encryption_entropy_delta,
            stripedEncryptionEntropy: striped_encryption_entropy,
            stripedEncryptionTime: striped_encryption_finish,
            stripedEncrptionEntropyDelta: striped_encryption_entropy_delta,
        };

        let serialised_test_result = serde_json::to_string(&test_result).unwrap();
        println!("{}", serialised_test_result)

    }


}
