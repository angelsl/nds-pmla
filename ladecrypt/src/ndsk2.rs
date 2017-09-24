#[derive(Clone, Copy)]
pub struct Key2 {
    x: u64,
    y: u64
}

fn flip39(i: u64) -> u64 {
    (0..39).map(|b| if i & (1 << b) != 0 { 1u64 << (38-b) } else { 0u64 }).sum()
}

impl Key2 {
    pub fn new() -> Key2 {
        Key2 {
            x: 0,
            y: 0
        }
    }

    pub fn init(&mut self, seed: u32, hdrbyte: u8) {
        self.x = flip39(((seed as u64) << 15) + 0x6000u64 + 
            match hdrbyte {
                0 => 0xE8, 1 => 0x4D, 2 => 0x5A, 3 => 0xB1,
                4 => 0x17, 5 => 0x8F, 6 => 0x99, 7 => 0xD5,
                _ => panic!("invalid hdrbyte {}", hdrbyte)
            });
        self.y = 0x506CECF09Du64; // flip39(0x5C879B9B05u64)
    }

    pub fn dobyte(&mut self, byte: u8) -> u8 {
        let x = self.x;
        let y = self.y;
        self.x = (((x >> 5) ^ (x >> 17) ^ (x >> 18) ^ (x >> 31)) & 0xFF) + (x << 8);
        self.y = (((y >> 5) ^ (y >> 23) ^ (y >> 18) ^ (y >> 31)) & 0xFF) + (y << 8);
        byte ^ (((self.x ^ self.y) & 0xFF) as u8)
    }

    pub fn dobytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte = self.dobyte(*byte);
        }
    }
}

#[cfg(test)]
mod test {
    use super::{flip39, Key2};

    static DOBYTES_CIPHERTEXT: [u8; 16] = [0x78, 0x33, 0x95, 0xb4, 0x40, 0xcd, 0x19, 0x22, 0xda, 0x4f, 0xca, 0x72, 0x07, 0xf0, 0x41, 0x9b];

    #[test]
    fn flip39_test() {
        assert_eq!(flip39(0x5C879B9B05u64), 0x506CECF09Du64);
    }

    #[test]
    fn dobytes_test() {
        let mut k2 = Key2::new();
        k2.init(0xC99ACE, 0);
        let mut ct = DOBYTES_CIPHERTEXT.clone();
        k2.dobytes(&mut ct);
        assert_eq!(&ct, &[0u8; 16]);
    }
}