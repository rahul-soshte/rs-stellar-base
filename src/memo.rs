use std::str::FromStr;

use crate::xdr;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

const MEMO_NONE: &str = "none";
const MEMO_ID: &str = "id";
const MEMO_TEXT: &str = "text";
const MEMO_HASH: &str = "hash";
const MEMO_RETURN: &str = "return";

pub enum MemoValue {
    NoneValue,
    IdValue(String),
    TextValue(Vec<u8>),
    HashValue(Vec<u8>),
    ReturnValue(Vec<u8>),
}

#[derive(Debug)]
pub struct Memo {
    memo_type: String,
    value: Option<String>,
}

// Define a trait for Memo behavior
pub trait MemoBehavior {
    fn new(memo_type: &str, value: Option<&str>) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
    fn id(input: &str) -> Self
    where
        Self: Sized;
    fn text(input: &str) -> Self
    where
        Self: Sized;
    fn text_buffer(input: Vec<u8>) -> Self
    where
        Self: Sized;
    fn hash_buffer(input: Vec<u8>) -> Self
    where
        Self: Sized;
    fn return_hash(input: Vec<u8>) -> Self
    where
        Self: Sized;
    fn none() -> Self
    where
        Self: Sized;
    fn value(&self) -> Result<MemoValue, &'static str>;
    fn from_xdr_object(object: xdr::Memo) -> Result<Self, &'static str>
    where
        Self: Sized;
    fn to_xdr_object(&self) -> Option<xdr::Memo>;
    fn _validate_id_value(value: &str) -> Result<(), String>;
    fn _validate_text_value(value: &str);
    fn _validate_hash_value(value: &[u8]);
}

impl MemoBehavior for Memo {
    fn new(memo_type: &str, value: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut value_buf = None;
        match memo_type {
            MEMO_NONE => {}
            MEMO_ID => {
                Self::_validate_id_value(value.expect("Expected a value for MEMO_ID"));
                if let Some(v) = value {
                    unsafe {
                        value_buf = Some(String::from_utf8_unchecked(v.into()));
                    }
                }
            }
            MEMO_TEXT => {
                Self::_validate_text_value(value.expect("Expected a value for MEMO_TEXT"));
                if let Some(v) = value {
                    unsafe {
                        value_buf = Some(String::from_utf8_unchecked(v.into()));
                    }
                }
            }
            MEMO_HASH | MEMO_RETURN => {
                Self::_validate_hash_value(unsafe {
                    String::from_utf8_unchecked(value.unwrap().as_bytes().to_vec()).as_bytes()
                });
                if let Some(v) = value {
                    value_buf = Some(v.into());
                }
            }
            _ => return Err("Invalid memo type".into()),
        }

        Ok(Memo {
            memo_type: memo_type.to_string(),
            value: value_buf,
        })
    }

    fn _validate_id_value(value: &str) -> Result<(), String> {
        let error = format!("Expects an int64 as a string. Got {}", value);

        let number = match BigInt::from_str(value) {
            Ok(num) => num,
            Err(_) => return Err(error.clone()),
        };

        if let Some(val) = number.to_i64() {
            let converted_back: BigInt = val.into();
            if converted_back != number {
                return Err(error.clone());
            }
        } else {
            return Err(error.clone());
        }

        Ok(())
    }

    fn _validate_text_value(value: &str) {
        assert!(value.len() <= 28, "String is longer than 28 bytes");
        let _ = xdr::Memo::Text(value.try_into().unwrap());
    }

    fn id(input: &str) -> Self {
        unsafe {
            Memo {
                memo_type: MEMO_ID.to_string(),
                value: Some(String::from_utf8_unchecked(input.into())),
            }
        }
    }

    fn text(input: &str) -> Self {
        assert!(input.len() <= 28, "String is longer than 28 bytes");

        unsafe {
            Memo {
                memo_type: MEMO_TEXT.to_string(),
                value: Some(String::from_utf8_unchecked(input.into())),
            }
        }
    }

    fn text_buffer(input: Vec<u8>) -> Self {
        unsafe {
            Memo {
                memo_type: MEMO_TEXT.to_string(),
                value: Some(String::from_utf8_unchecked(input)),
            }
        }
    }

    fn hash_buffer(input: Vec<u8>) -> Self {
        Self::_validate_hash_value(unsafe {
            String::from_utf8_unchecked(input.clone()).as_bytes()
        });

        unsafe {
            Memo {
                memo_type: MEMO_HASH.to_string(),
                value: Some(String::from_utf8_unchecked(input)),
            }
        }
    }

    fn return_hash(input: Vec<u8>) -> Self {
        Self::_validate_hash_value(unsafe {
            String::from_utf8_unchecked(input.clone()).as_bytes()
        });

        unsafe {
            Memo {
                memo_type: MEMO_RETURN.to_string(),
                value: Some(String::from_utf8_unchecked(input)),
            }
        }
    }

    fn _validate_hash_value(value: &[u8]) {
        if value.len() == 64 {
            // Check if it's hex encoded string
            let hex_str = match std::str::from_utf8(value) {
                Ok(s) => s,
                Err(_) => panic!("Expects a 32 byte hash value or hex encoded string"),
            };

            if hex::decode(hex_str).is_err() {
                panic!("Expects a 32 byte hash value or hex encoded string");
            }
            let decoded = match hex::decode(hex_str) {
                Ok(d) => d,
                Err(_) => panic!("Failed to decode hex string: {}", hex_str),
            };
            if decoded.len() != 32 {
                panic!("Expects a 32 byte hash value or hex encoded string");
            }
        } else if value.len() != 32 {
            let s = std::str::from_utf8(value).unwrap_or("<non-UTF8 data>");
            panic!("Expects a 32 byte hash value or hex encoded string");
        }
    }

    fn none() -> Self {
        Self {
            memo_type: MEMO_NONE.to_owned(),
            value: None,
        }
    }

    fn value(&self) -> Result<MemoValue, &'static str> {
        match self.memo_type.as_str() {
            MEMO_NONE => Ok(MemoValue::NoneValue),
            MEMO_ID => Ok(MemoValue::IdValue(self.value.clone().unwrap())),
            MEMO_TEXT => Ok(MemoValue::TextValue(
                self.value.clone().unwrap().as_bytes().to_vec(),
            )),
            MEMO_HASH | MEMO_RETURN => Ok(MemoValue::HashValue(
                self.value.clone().unwrap().as_bytes().to_vec(),
            )),
            _ => Err("Invalid memo type"),
        }
    }

    fn from_xdr_object(object: xdr::Memo) -> Result<Self, &'static str> {
        unsafe {
            match object {
                xdr::Memo::None => Ok(Memo {
                    memo_type: MEMO_NONE.to_owned(),
                    value: None,
                }),
                xdr::Memo::Text(x) => Ok(Memo {
                    memo_type: MEMO_TEXT.to_owned(),
                    value: Some(String::from_utf8_unchecked(x.to_vec())),
                }),
                xdr::Memo::Id(x) => Ok(Memo {
                    memo_type: MEMO_ID.to_owned(),
                    value: Some(x.to_string()),
                }),
                xdr::Memo::Hash(x) => Ok(Memo {
                    memo_type: MEMO_HASH.to_owned(),
                    value: Some(String::from_utf8_unchecked(x.0.to_vec())),
                }),
                xdr::Memo::Return(x) => Ok(Memo {
                    memo_type: MEMO_RETURN.to_owned(),
                    value: Some(String::from_utf8_unchecked(x.0.to_vec())),
                }),
            }
        }
    }

    fn to_xdr_object(&self) -> Option<xdr::Memo> {
        match self.memo_type.as_str() {
            MEMO_NONE => Some(xdr::Memo::None),
            MEMO_ID => Some(xdr::Memo::Id(
                u64::from_str(self.value.clone().unwrap().as_str()).unwrap(),
            )),
            MEMO_TEXT => Some(xdr::Memo::Text(
                self.value.clone().unwrap().as_str().try_into().unwrap(),
            )),
            MEMO_HASH => Some(xdr::Memo::Hash(
                xdr::Hash::from_str(&hex::encode(self.value.clone().unwrap().as_str())).unwrap(),
            )),
            // MemoType::MemoReturn => Some(XDRMemo::memo_return(&self._value)),
            MEMO_RETURN => Some(xdr::Memo::Return(
                xdr::Hash::from_str(&hex::encode(self.value.clone().unwrap().as_str())).unwrap(),
            )),
            _ => None,
        }
    }
}

fn assert_panic<F: FnOnce(), S: AsRef<str>>(f: F, expected_msg: S) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match result {
        Ok(_) => panic!("Function did not panic as expected"),
        Err(err) => {
            if let Some(s) = err.downcast_ref::<&str>() {
                assert!(
                    s.contains(expected_msg.as_ref()),
                    "Unexpected panic message. Got: {}",
                    s
                );
            } else {
                panic!("Unexpected panic type");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::memo::MemoBehavior;
    use crate::xdr;
    use crate::xdr::WriteXdr;
    use core::panic;

    use crate::memo::{MEMO_HASH, MEMO_NONE, MEMO_RETURN};

    use super::{assert_panic, Memo, MEMO_ID, MEMO_TEXT};

    #[test]
    fn constructor_throws_error_when_type_is_invalid() {
        let result = Memo::new("test", None);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(err_msg.contains("Invalid memo type"));
    }

    #[test]
    fn memo_none_converts_to_from_xdr() {
        let memo = Memo::none().to_xdr_object().unwrap();
        let base_memo = Memo::from_xdr_object(memo).unwrap();
        assert_eq!(base_memo.memo_type, MEMO_NONE);
        assert!(base_memo.value.is_none());
    }

    #[test]
    fn memo_text_returns_value_for_correct_argument() {
        let _ = Memo::new(MEMO_TEXT, Some("test"));

        let memo_utf8 = Memo::new(MEMO_TEXT, Some("三代之時")).unwrap();
        let val = match memo_utf8.to_xdr_object().unwrap() {
            xdr::Memo::Text(x) => x.to_utf8_string().unwrap(),

            _ => panic!("Invalid Type"),
        };
        let b = String::from("三代之時");
        print!("xx {}", val);

        assert_eq!(val, b, "Memo text value does not match expected value");
    }

    #[test]
    fn returns_value_for_correct_argument_utf8() {
        let vec2: Vec<u8> = vec![0xd1];
        let expected: Vec<u8> = vec![
            // memo_text
            0x00, 0x00, 0x00, 0x01, // memo_text
            0x00, 0x00, 0x00, 0x01, // length
            0xd1, 0x00, 0x00, 0x00,
        ];
        // let mut memo_text: Vec<u8> = vec![];
        let memo_text = Memo::text_buffer(vec2.clone())
            .to_xdr_object()
            .unwrap()
            .to_xdr(xdr::Limits::none())
            .unwrap();

        unsafe {
            let memo_text_2 =
                Memo::new(MEMO_TEXT, Some(&String::from_utf8_unchecked(vec2.clone())))
                    .unwrap()
                    .to_xdr_object()
                    .unwrap()
                    .to_xdr(xdr::Limits::none())
                    .unwrap();
            assert_eq!(memo_text_2, expected);
        }
        assert_eq!(memo_text, expected);
    }

    #[test]
    fn converts_to_from_xdr_object() {
        let memo = Memo::text("test").to_xdr_object().unwrap();

        let val = match memo.clone() {
            xdr::Memo::Text(x) => x.to_string(),
            _ => panic!("Invalid Type"),
        };

        assert_eq!(val, "test");

        let base_memo = Memo::from_xdr_object(memo.clone()).unwrap();
        assert_eq!(base_memo.memo_type, MEMO_TEXT);
        assert_eq!(base_memo.value.unwrap(), "test");
    }

    #[test]
    fn converts_to_from_xdr_object_buffer() {
        let buf = vec![0xd1];
        // unsafe {
        let memo = Memo::text_buffer(buf.clone()).to_xdr_object().unwrap();
        // }
        let val = match memo.clone() {
            xdr::Memo::Text(x) => x,
            _ => panic!("Invalid Type"),
        };

        unsafe {
            assert_eq!(val.to_vec(), buf);
        }

        let base_memo = Memo::from_xdr_object(memo).unwrap();
        assert_eq!(base_memo.memo_type, MEMO_TEXT);

        let val = match base_memo.value().unwrap() {
            crate::memo::MemoValue::TextValue(x) => x,
            _ => panic!("Bad"),
        };
        unsafe {
            assert_eq!(val.to_vec(), buf);
        }
    }

    #[test]
    fn errors_when_string_longer_than_28_bytes() {
        let long_string = "12345678901234567890123456789";
        let scenario_1 = || {
            Memo::text(long_string);
            ()
        };
        assert_panic(scenario_1, "String is longer than 28 bytes");

        let scenario_2 = || {
            let long_utf8_string = "三代之時三代之時三代之時";
            Memo::text(long_utf8_string);
            ()
        };
        assert_panic(scenario_2, "String is longer than 28 bytes");
    }

    fn memo_id_handles_correct_argument() {
        Memo::new(MEMO_ID, Some("1000"));
        Memo::new(MEMO_ID, Some("0"));
    }

    #[test]
    fn converts_to_from_xdr_object_if() {
        let memo = Memo::id("1000").to_xdr_object().unwrap();

        let val = match memo {
            xdr::Memo::Id(x) => x,
            _ => panic!("Invalid Type"),
        };

        assert_eq!(val.to_string(), "1000");

        let base_memo = Memo::from_xdr_object(memo).unwrap();

        match base_memo.memo_type.as_str() {
            MEMO_ID => (),
            _ => panic!("Invalid"),
        }

        assert_eq!(base_memo.value.unwrap(), "1000");
    }

    #[test]
    fn hash_converts_to_from_xdr_object() {
        // Assuming you have a Rust-equivalent to allocate a buffer of length 32 with all bytes being 10.
        let buffer = vec![10u8; 32];

        let memo = Memo::hash_buffer(buffer.clone()).to_xdr_object().unwrap();

        let val = match memo.clone() {
            xdr::Memo::Hash(x) => x,
            _ => panic!("Invalid"),
        };
        assert_eq!(val.0.len(), 32);
        unsafe {
            assert_eq!(
                val.to_string(),
                String::from_utf8_unchecked(hex::encode(buffer.clone()).into())
            );
        }
        let base_memo = Memo::from_xdr_object(memo).unwrap();

        match base_memo.memo_type.as_str() {
            MEMO_HASH => (),
            _ => panic!("Invalid"),
        }
        assert_eq!(base_memo.value.clone().unwrap().len(), 32);

        let base_memo_hex = hex::encode(base_memo.value.unwrap());
        let buffer_hex = hex::encode(buffer.clone());

        assert_eq!(base_memo_hex, buffer_hex);
    }

    #[test]
    fn return_converts_to_from_xdr_object() {
        let buffer = vec![10u8; 32];

        // Convert Vec<u8> to hex string
        let buffer_hex: String = hex::encode(&buffer);

        // Testing string hash
        let memo = Memo::return_hash(unsafe { buffer.clone() })
            .to_xdr_object()
            .unwrap();

        let val = match memo.clone() {
            xdr::Memo::Return(x) => x,
            _ => panic!("Invalid"),
        };

        assert_eq!(val.0.len(), 32);
        unsafe {
            assert_eq!(
                val.to_string(),
                String::from_utf8_unchecked(hex::encode(buffer.clone()).into())
            );
        }

        let base_memo = Memo::from_xdr_object(memo).unwrap();

        match base_memo.memo_type.as_str() {
            MEMO_RETURN => (),
            _ => panic!("Invalid"),
        };

        assert_eq!(base_memo.value.clone().unwrap().len(), 32);
        let base_memo_hex = hex::encode(base_memo.value.unwrap());
        let buffer_hex = hex::encode(buffer.clone());
        assert_eq!(base_memo_hex, buffer_hex);
    }

    #[test]
    fn returns_value_for_correct_argument() {
        let methods = [Memo::hash_buffer, Memo::return_hash];

        for method in &methods {
            let _ = method(vec![0u8; 32]);

            let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
            let _ = method(hex::decode(hex_str).expect("Failed to decode hex"));
        }

        let binding_1 =
            hex::decode("00000000000000000000000000000000000000000000000000000000000000").unwrap();
        let binding_2 =
            hex::decode("000000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let binding_3 = &vec![0u8; 33][..];

        let invalid_inputs = vec![
            &[] as &[u8], // empty
            &b"test"[..], // "test" as bytes
            &[0, 10, 20],
            binding_3,      // 33 zeros
            &binding_1[..], // 31 zeros in hex
            &binding_2[..], // 32 zeros in hex
                            // ... add any other byte slices as needed
        ];

        for method in &methods {
            for input in &invalid_inputs {
                let scenario_1 = || {
                    method(input.to_vec());
                    ()
                };
                assert_panic(
                    scenario_1,
                    "Expects a 32 byte hash value or hex encoded string",
                );
            }
        }
    }
}
