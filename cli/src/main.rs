use std::{fs::File, path::PathBuf};

use clap::Parser;
use hypercube_recursion_machine::{verify_compressed, SP1Proof, SP1ProofWithPublicValues};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

fn main() {
    let args = Args::parse();

    let path = args.build_dir;

    let mut file = File::open(path).unwrap();

    let proof: SP1ProofWithPublicValues = bincode::deserialize_from(&mut file).unwrap();

    let proof = proof.proof;
    let proof = match proof {
        SP1Proof::Compressed(proof) => proof,
        _ => panic!("not a compressed proof"),
    };

    let result = verify_compressed(&proof);

    assert!(result.is_ok(), "Failed to verify compressed proof");

    println!(
        r" _______           _______  _______  _______  _______  _______  _ 
(  ____ \|\     /|(  ____ \(  ____ \(  ____ \(  ____ \(  ____ \( )
| (    \/| )   ( || (    \/| (    \/| (    \/| (    \/| (    \/| |
| (_____ | |   | || |      | |      | (__    | (_____ | (_____ | |
(_____  )| |   | || |      | |      |  __)   (_____  )(_____  )| |
      ) || |   | || |      | |      | (            ) |      ) |(_)
/\____) || (___) || (____/\| (____/\| (____/\/\____) |/\____) | _ 
\_______)(_______)(_______/(_______/(_______/\_______)\_______)(_)"
    );
}
