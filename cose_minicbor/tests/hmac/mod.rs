#[cfg(all(feature = "a128kw", feature = "hmac256"))]
mod test_hmac_a128kw;

#[cfg(all(feature = "a256kw", feature = "hmac256"))]
mod test_hmac_a256kw;

#[cfg(all(feature = "ecdh_es", feature = "hmac256"))]
mod test_hmac_ecdh_es_a256;
