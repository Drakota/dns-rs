pub mod name;
pub mod query;
pub mod record;

use derive_try_from_primitive::*;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, TryFromPrimitive, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsRecordType {
    A = 0x01,
    NS = 0x02,
    MD = 0x03,
    MF = 0x04,
    CNAME = 0x05,
    SOA = 0x06,
    MB = 0x07,
    MG = 0x08,
    MR = 0x09,
    NULL = 0x0A,
    WKS = 0x0B,
    PTR = 0x0C,
    HINFO = 0x0D,
    MINFO = 0x0E,
    MX = 0x0F,
    TXT = 0x10,
    AAAA = 0x1C, // RFC 3596
}

#[derive(Debug, TryFromPrimitive, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsClass {
    IN = 0x01,
    CS = 0x02,
    CH = 0x03,
    HS = 0x04,
}
