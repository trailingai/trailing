use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(&'static str);

impl Error {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl Uuid {
    pub fn new_v4() -> Self {
        let mut bytes = [0u8; 16];
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let time_component = (nanos as u64) ^ (std::process::id() as u64).rotate_left(21);

        bytes[..8].copy_from_slice(&time_component.to_be_bytes());
        bytes[8..].copy_from_slice(&counter.to_be_bytes());
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        Self(bytes)
    }

    pub fn parse_str(input: &str) -> Result<Self, Error> {
        let compact = input.replace('-', "");
        if compact.len() != 32 {
            return Err(Error::new("invalid UUID length"));
        }

        let mut bytes = [0u8; 16];
        for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| Error::new("invalid UTF-8"))?;
            bytes[index] =
                u8::from_str_radix(text, 16).map_err(|_| Error::new("invalid UUID hex"))?;
        }

        Ok(Self(bytes))
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bytes = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u64::from_be_bytes([
                0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ])
        )
    }
}

impl FromStr for Uuid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}
