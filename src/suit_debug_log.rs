// use defmt macros when the feature is enabled
#[cfg(feature = "use-defmt")]
pub use defmt::{error, info};

// when std is available (host builds) and defmt not used -> map to println
#[cfg(all(feature = "std", not(feature = "use-defmt")))]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => (println!($($arg)*));
}
#[cfg(all(feature = "std", not(feature = "use-defmt")))]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => (eprintln!($($arg)*));
}

// default for embedded builds without defmt: no-op
#[cfg(all(not(feature = "std"), not(feature = "use-defmt")))]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{}};
}
#[cfg(all(not(feature = "std"), not(feature = "use-defmt")))]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{}};
}
