// Adapted from rust-crypto
// https://github.com/DaGenix/rust-crypto/blob/master/src/blowfish.rs

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{ptr, mem};

pub fn read_u32v_be(dst: &mut[u32], input: &[u8]) {
    assert_eq!(dst.len() * 4, input.len());
    unsafe {
        let mut x: *mut u32 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u32 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 4);
            *x = u32::from_be(tmp);
            x = x.offset(1);
            y = y.offset(4);
        }
    }
}

pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
    assert_eq!(dst.len(), 4);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

#[derive(Clone, Copy)]
pub struct Blowfish {
    s: [[u32; 256]; 4],
    p: [u32; 18]
}

impl Blowfish {
    pub fn new() -> Blowfish {
        unsafe { mem::uninitialized() }
    }

    pub fn init(&mut self, gamecode: &str, level: u32) {
        fn nds_expand_key(bf: &mut Blowfish, key: &mut [u32; 3]) {
            {
                let (l, r) = bf.encrypt(key[2], key[1]); key[2] = l; key[1] = r;
                let (l, r) = bf.encrypt(key[1], key[0]); key[1] = l; key[0] = r;
            }
            for (i, &k) in key.iter().take(2).cycle().take(bf.p.len()).enumerate() {
                // i'm not sure if i should use to_be or swap_bytes here
                // TODO: think about this
                bf.p[i] ^= k.to_be();
            }
            let mut l = 0u32;
            let mut r = 0u32;
            for i in (0..18).step_by(2) {
                let (new_l, new_r) = bf.encrypt(l, r);
                l = new_l;
                r = new_r;
                bf.p[i] = l;
                bf.p[i+1] = r;
            }
            for i in 0..4 {
                for j in (0..256).step_by(2) {
                    let (new_l, new_r) = bf.encrypt(l, r);
                    l = new_l;
                    r = new_r;
                    bf.s[i][j] = l;
                    bf.s[i][j+1] = r;
                }
            }
        }
        self.reset();
        let mut key: [u32; 3] = unsafe { mem::uninitialized() };
        if gamecode.len() < 4 {
            panic!("Invalid gamecode length");
        }
        unsafe { ptr::copy(gamecode.as_ptr() as *const u32, key.as_mut_ptr(), 1); }
        key[1] = key[0] >> 1;
        key[2] = key[0] << 1;
        if level >= 1 {
            nds_expand_key(self, &mut key);
        }
        if level >= 2 {
            nds_expand_key(self, &mut key);
        }
        if level >= 3 {
            key[2] = key[0];
            key[1] = key[0];
            nds_expand_key(self, &mut key);
        }
    }

    fn reset(&mut self) {
        // the 0x1048-byte blowfish array as in NDS firmware
        // sha1 = 84e467f2485078e401a17a5f231e3fe6e9686648
        let ndsbfstate = include_bytes!("ndsbfstate.bin");
        let pstate = ndsbfstate.as_ptr() as *const u32;
        unsafe {
            ptr::copy(pstate, self.p.as_mut_ptr(), 0x12);
            ptr::copy(pstate.offset(0x12), self.s[0].as_mut_ptr(), 0x100);
            ptr::copy(pstate.offset(0x112), self.s[1].as_mut_ptr(), 0x100);
            ptr::copy(pstate.offset(0x212), self.s[2].as_mut_ptr(), 0x100);
            ptr::copy(pstate.offset(0x312), self.s[3].as_mut_ptr(), 0x100);
        }
    }

    fn round_function(&self, x: u32) -> u32 {
        ((self.s[0][(x >> 24) as usize].wrapping_add(self.s[1][((x >> 16) & 0xff) as usize])) ^ self.s[2][((x >> 8) & 0xff) as usize]).wrapping_add(self.s[3][(x & 0xff) as usize])
    }

    fn encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (0..16).step_by(2) {
            l ^= self.p[i];
            r ^= self.round_function(l);
            r ^= self.p[i+1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];
        (r, l)
    }

    fn decrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        let mut i = 16;
        while i > 0 {
            l ^= self.p[i+1];
            r ^= self.round_function(l);
            r ^= self.p[i];
            l ^= self.round_function(r);
            i -= 2;
        }
        l ^= self.p[1];
        r ^= self.p[0];
        (r, l)
    }

    pub fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 8);
        assert_eq!(output.len(), 8);
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.encrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }

    pub fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), 8);
        assert_eq!(output.len(), 8);
        let mut block = [0u32, 0u32];
        read_u32v_be(&mut block, input);
        let (l, r) = self.decrypt(block[0], block[1]);
        write_u32_be(&mut output[0..4], l);
        write_u32_be(&mut output[4..8], r);
    }
}

#[cfg(test)]
mod test {
    use super::Blowfish;

    struct Test {
        key: &'static str,
        level: u32,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>
    }

    fn test_vectors() -> Vec<Test> {
        vec![
            Test { key: "ABXK", level: 2,
                    plaintext: vec![0x40, 0x00, 0x0C, 0x99, 0xAC, 0xE3, 0x9D, 0x46],
                    ciphertext: vec![0x07, 0xF7, 0x6F, 0x3B, 0x77, 0xAF, 0x94, 0x9F]
            },
            Test { key: "ABXK", level: 2,
                    plaintext: vec![0x10, 0x00, 0x01, 0x1A, 0x47, 0x33, 0x9D, 0x47],
                    ciphertext: vec![0xF6, 0x6C, 0xE1, 0x57, 0xF1, 0x2C, 0x1F, 0xFE]
            },
        ]
    }

    #[test]
    fn encrypt_test_vectors() {
        let tests = test_vectors();
        let mut state = Blowfish::new();
        let mut output = [0u8; 8];
        for test in &tests {
            state.init(test.key, test.level);
            state.encrypt_block(&test.plaintext[..], &mut output[..]);
            assert_eq!(test.ciphertext[..], output[..]);
        }
    }

    #[test]
    fn decrypt_test_vectors() {
        let tests = test_vectors();
        let mut state = Blowfish::new();
        let mut output = [0u8; 8];
        for test in &tests {
            state.init(test.key, test.level);
            state.decrypt_block(&test.ciphertext[..], &mut output[..]);
            assert_eq!(test.plaintext[..], output[..]);
        }
    }
}
