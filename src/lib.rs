extern crate hmacsha1;
extern crate byteorder;

use std::io::Cursor;
use hmacsha1::{hmac_sha1, SHA1_DIGEST_BYTES};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::time;

pub fn hotp(key: &[u8], counter: u64, digits: u32) -> u32 {
    let mut counter_bytes = vec![];
    counter_bytes.write_u64::<BigEndian>(counter).unwrap();

    let hmac = hmac_sha1(key, &counter_bytes);

    let dyn_offset = (hmac[SHA1_DIGEST_BYTES-1] & 0xf) as usize;
    let dyn_range = &hmac[dyn_offset..dyn_offset+4];

    let mut rdr = Cursor::new(dyn_range);
    let s_num = rdr.read_u32::<BigEndian>().unwrap() & 0x7fffffff;
    
    s_num % 10u32.pow(digits)
}

const DIGITS: u32 = 6;
const TIME_STEP: u64 = 30;
pub fn totp(key: &[u8]) -> u32 {
    let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).expect("Current time is before unix epoch");
    let slot = now.as_secs()/TIME_STEP;

    hotp(key, slot, DIGITS)
}

#[cfg(test)]
mod tests {
    use super::hotp;
    const KEY : &'static [u8] = b"12345678901234567890";
    const DIGITS: u32 = 6;
    #[test]
    fn test_hotp() {
        assert_eq!(hotp(KEY, 0, DIGITS), 755224);
        assert_eq!(hotp(KEY, 1, DIGITS), 287082);
        assert_eq!(hotp(KEY, 2, DIGITS), 359152);
        assert_eq!(hotp(KEY, 3, DIGITS), 969429);
        assert_eq!(hotp(KEY, 4, DIGITS), 338314);
        assert_eq!(hotp(KEY, 5, DIGITS), 254676);
        assert_eq!(hotp(KEY, 6, DIGITS), 287922);
    }
}

