use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
};
use csv::ReaderBuilder;

fn main() {
    let path = env::current_dir().unwrap();
    print!("{}", path.display());
    let dest_path = path.join("token_map.rs");
    let stoplist_path = path.join("stoplist.rs");
    let mut file = BufWriter::new(File::create(&dest_path).unwrap());
    let mut stoplist_file = BufWriter::new(File::create(&stoplist_path).unwrap());

    let mut map = phf_codegen::Map::new();
    let mut stoplist = phf_codegen::Set::new();

    // Load critical tokens
    let critical_path = path.join("data/critical_tokens.csv");
    let critical_tokens: Vec<String> = {
        let mut tokens = Vec::new();
        let mut reader = ReaderBuilder::new()
            .has_headers(false)
            .from_path(critical_path)
            .unwrap();
        for result in reader.records() {
            let record = result.unwrap();
            let token = record.get(0).unwrap().to_string();
            tokens.push(token);
        }
        tokens
    };

    for token in critical_tokens {
        map.entry(token.clone(), "TokenLabel::Critical");
    }

    // Load soft tokens
    let soft_path = path.join("data/soft_tokens.csv");
    let soft_tokens: Vec<String> = {
        let mut tokens = Vec::new();
        let mut reader = ReaderBuilder::new()
            .has_headers(false)
            .from_path(soft_path)
            .unwrap();
        for result in reader.records() {
            let record = result.unwrap();
            let token = record.get(0).unwrap().to_string();
            tokens.push(token);
        }
        tokens
    };
    for token in soft_tokens {
        map.entry(token.clone(), "TokenLabel::Soft");
    }

    // Load stoplist tokens
    let stoplist_path = path.join("data/stoplist.csv");
    let stoplist_tokens: Vec<String> = {
        let mut tokens = Vec::new();
        let mut reader = ReaderBuilder::new()
            .has_headers(false)
            .from_path(stoplist_path)
            .unwrap();
        for result in reader.records() {
            let record = result.unwrap();
            let token = record.get(0).unwrap().to_string();
            tokens.push(token);
        }
        tokens
    };
    for token in stoplist_tokens {
        stoplist.entry(token.clone());
    }

    // Emit the static PHF map
    write!(
        &mut file,
        "use crate::TokenLabel;\n\npub static TOKEN_MAP: phf::Map<&'static str, TokenLabel> = {};\n",
        map.build()
    )
    .unwrap();

    // Emit the static PHF set
    write!(
        &mut stoplist_file,
        "pub static STOPLIST: phf::Set<&'static str> = {};\n",
        stoplist.build()
    )
    .unwrap();

    // Re-run build if inputs change
    println!("cargo:rerun-if-changed=data/critical_tokens.csv");
    println!("cargo:rerun-if-changed=data/soft_tokens.csv");
    println!("cargo:rerun-if-changed=data/stoplist.csv");
}