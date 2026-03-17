use ssh_key::{Algorithm, Signature};

use crate::ctap::AssertionResponse;

pub fn encode(response: &AssertionResponse) -> Result<Signature, ssh_key::Error> {
    let mut data = response.signature.clone();
    data.push(response.flags);
    data.extend(response.counter.to_be_bytes());
    Signature::new(Algorithm::SkEd25519, data)
}
