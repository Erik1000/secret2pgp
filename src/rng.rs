use hkdf::Hkdf;
use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng, Error, RngCore,
};
use sha2::Sha256;

// Generates values based on input key material to HKDF
///
/// This RNG has an interal state and must be reset in order to generate the same values again.
/// This RNG should only be used ONCE for key generation and dropped afterwards.
pub struct SecretSeededHkdfRng<'a> {
    info: &'a [u8],
    hkdf: Hkdf<Sha256>,
    total_length: usize,
}

impl<'a> SecretSeededHkdfRng<'a> {
    pub fn new(salt: Option<&'a [u8]>, seed: &'a [u8], info: &'a [u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(salt, seed);
        Self {
            info,
            hkdf,
            total_length: 0,
        }
    }

    pub fn reset(&mut self) {
        self.total_length = 0;
    }

    pub fn update_info_reset(&mut self, info: &'a [u8]) {
        self.info = info;
        self.reset();
    }
}

impl<'a> RngCore for SecretSeededHkdfRng<'a> {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.total_length += dest.len();

        // sadly, we have to advance hkdf manually
        let mut total_dest = vec![0; self.total_length];
        self.hkdf
            .expand(self.info, &mut total_dest)
            .map_err(|_| rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap()))?;

        // only put the new output from hkdf into `dest`
        dest.swap_with_slice(total_dest.split_at_mut(self.total_length - dest.len()).1);
        Ok(())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("length of `dest` not invalid")
    }

    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }
}
impl<'a> CryptoRng for SecretSeededHkdfRng<'a> {}

#[test]
fn smoke() {
    let seed =
        Base64UrlUnpadded::decode_vec("W_7yr1RIHW0YhaAKUaS56Vp7Vp6HqVTWbm-4xaqsEzI").unwrap();
    let info = b"sign";

    let mut rng = SecretSeededHkdfRng::new(None, &seed, info);

    let a = rng.next_u64();
    rng.reset();
    let b = rng.next_u64();
    assert_eq!(a, b);

    assert_ne!(rng.next_u64(), rng.next_u64());

    let mut other = SecretSeededHkdfRng::new(None, &seed, info);
    other.next_u64();
    other.next_u64();
    other.next_u64();
    assert_eq!(rng.next_u64(), other.next_u64());

    rng.reset();
    other.update_info_reset(b"enc");
    assert_ne!(rng.next_u64(), other.next_u64());
}
