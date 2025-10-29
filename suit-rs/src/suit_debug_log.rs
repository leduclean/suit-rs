// use defmt
#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        defmt::info!($($arg)*)
    };
}

#[cfg(feature = "defmt")]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        defmt::error!($($arg)*)
    };
}

// fallback when std and not defmt
#[cfg(all(feature = "std", not(feature = "defmt")))]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        println!($($arg)*)
    };
}
#[cfg(all(feature = "std", not(feature = "defmt")))]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*)
    };
}
