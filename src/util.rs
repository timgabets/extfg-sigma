extern crate rand;

use rand::Rng;

/// Generate Authorization Serno
pub fn gen_auth_serno() -> u64 {
    let mut rng = rand::thread_rng();
    let rrn: u64 = rng.gen();
    rrn
}
