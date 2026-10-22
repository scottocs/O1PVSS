//! Cached public-setup digests and domain-separated proof transcripts.
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub fn append<T: CanonicalSerialize>(transcript: &mut Transcript, label: &'static [u8], value: &T) {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialization to Vec");
    transcript.append_message(label, &bytes);
}

pub fn digest<T: CanonicalSerialize>(domain: &'static [u8], value: &T) -> [u8; 32] {
    let mut transcript = Transcript::new(domain);
    append(&mut transcript, b"public-setup", value);
    let mut digest = [0; 32];
    transcript.challenge_bytes(b"setup-digest", &mut digest);
    digest
}

pub fn challenge<F: PrimeField>(transcript: &mut Transcript) -> F {
    let mut bytes = [0; 64];
    transcript.challenge_bytes(b"challenge", &mut bytes);
    F::from_le_bytes_mod_order(&bytes)
}

pub fn transcript(domain: &'static [u8], sid: &[u8; 32], epoch: u64) -> Transcript {
    let mut transcript = Transcript::new(domain);
    transcript.append_message(b"setup-digest", sid);
    transcript.append_u64(b"epoch", epoch);
    transcript
}
