use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyInit};
use sha3::{Digest, Keccak256};

pub struct MAC {
    hash: Keccak256,
    secret: Vec<u8>,
}

type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;

impl MAC {
    pub fn new(secret: Vec<u8>) -> Self {
        let hash = Keccak256::new();

        return MAC { hash, secret };
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    pub fn update_header(&mut self, data: &mut Vec<u8>) {
        let aes = Aes256EcbEnc::new(self.secret.as_slice().try_into().unwrap());
        let mut block = self.digest();
        let encrypted = aes.encrypt_padded::<NoPadding>(block.as_mut(), 16).unwrap();

        let xor_result: Vec<u8> = encrypted
            .iter()
            .zip(data.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        self.hash.update(xor_result);
    }

    pub fn update_body(&mut self, data: &mut Vec<u8>) {
        self.hash.update(data);
        let prev = self.digest();

        let aes = Aes256EcbEnc::new(self.secret.as_slice().try_into().unwrap());
        let mut block = prev.clone();
        let encrypted = aes.encrypt_padded::<NoPadding>(block.as_mut(), 16).unwrap();

        let xor_result: Vec<u8> = encrypted
            .iter()
            .zip(prev.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        self.hash.update(xor_result)
    }

    pub fn digest(&self) -> Vec<u8> {
        return self.hash.clone().finalize()[0..16].to_vec();
    }
}
