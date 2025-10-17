//! This file contains top level validator functions to raise error during first decode pass for lazy decoded structures.
use minicbor::data::Type;
use minicbor::decode::{Error as DecodeError, Probe};

/// Validate Try-Each DIRECTIVE: must be definite array with >= 2 elements,
/// each inner sequence must be .cbor bstr encoded (CBOR bytes).
///
///
/// Raise a top level error if the format is not appropriate before even lazy decoding.
pub(crate) fn validate_try_each<'b>(prob: &mut Probe<'_, 'b>) -> Result<(), DecodeError> {
    let len_opt = prob.array()?;

    match len_opt {
        Some(n) => {
            // require at least 2 sequences
            if n < 2 {
                return Err(DecodeError::message(
                    "invalid try-each: must contain at least 2 sequences",
                ));
            }

            // Check that each element is a bstr
            for _ in 0..n {
                let ty = prob.datatype()?;
                if ty != Type::Bytes {
                    return Err(DecodeError::type_mismatch(ty)
                        .with_message("try-each elements must be bstr"));
                }
                prob.skip()?;
            }
        }

        None => {
            // Reject indefinite arrays (safer)
            return Err(DecodeError::message(
                "indefinite-length try-each arrays are not supported",
            ));
        }
    }

    Ok(())
}

mod tests {

    #[test]
    fn test_try_each_validator() {
        use crate::suit_manifest::SuitDirectiveTryEachArgumentShared;
        use minicbor::{Decode, Decoder};

        let unvalid_try_each_bytes = cbor_macro::cbo!(r#"[<< [] >>]"#);
        let valid_try_each_bytes = cbor_macro::cbo!(r#"[<< [] >>, << [] >>]"#);
        let mut d1 = Decoder::new(&unvalid_try_each_bytes);
        assert!(
            SuitDirectiveTryEachArgumentShared::decode(&mut d1, &mut ())
                .is_err_and(|e| e.is_message())
        );

        let mut d2 = Decoder::new(&valid_try_each_bytes);
        assert!(SuitDirectiveTryEachArgumentShared::decode(&mut d2, &mut ()).is_ok())
    }
}
