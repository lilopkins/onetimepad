use std::process;

use clap::{arg, command, Parser, Subcommand};
use onetimepad::OneTimePad;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// The alphabet used by this converted. By default, ASCII is used.
    #[arg(short, long)]
    alphabet: Option<String>,

    /// Which action should be performed?
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    Encode {
        /// The plain text to be encoded.
        #[arg(index = 1)]
        plaintext: String,

        /// The pad to use, or if not specified it will be randomly generated.
        #[arg(short, long)]
        pad: Option<String>,
    },
    Decode {
        /// The ciphertext to be decoded. The ciphertext and pad are interchangable.
        #[arg(index = 1)]
        ciphertext: String,

        /// The pad to use during decoding. The ciphertext and pad are interchangable.
        #[arg(index = 2)]
        pad: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let mut one_time_pad = if let Some(alphabet) = cli.alphabet {
        OneTimePad::new_with_alphabet(alphabet)
    } else {
        OneTimePad::new()
    };

    match cli.command {
        Commands::Encode { plaintext, pad } => {
            if let Some(pad) = pad {
                if let Err(e) = one_time_pad.push_to_pad(pad) {
                    eprintln!("Failed to encode: {e}");
                    process::exit(1);
                }
            } else {
                one_time_pad.generate_pad(plaintext.len());
            }
            match one_time_pad.encode(plaintext) {
                Ok(encoding_result) => {
                    eprintln!("       Pad: {}", encoding_result.pad);
                    eprint!("Ciphertext: ");
                    println!("{}", encoding_result.cipher_text);
                }
                Err(e) => {
                    eprintln!("Failed to encode: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Decode { ciphertext, pad } => {
            if let Err(e) = one_time_pad.push_to_pad(pad) {
                eprintln!("Failed to decode: {e}");
                process::exit(1);
            }
            match one_time_pad.decode(ciphertext) {
                Ok(plain_text) => println!("{plain_text}"),
                Err(e) => {
                    eprintln!("Failed to decode: {e}");
                    process::exit(1);
                }
            }
        }
    }
}
