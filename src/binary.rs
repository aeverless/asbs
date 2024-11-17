//! Binary implementations of [`Conceal`][crate::Conceal] and [`Reveal`][crate::Reveal] traits.
//!
//! The [`Carrier`] and [`Package`] structures can be used to conceal and reveal hidden binary
//! messages within some other binary data via the use of bit patterns.
//!
//! ## Bit Patterns
//!
//! A bit pattern paired with a message length here act as a steganographic key.
//!
//! *Bit patterns* are defined as a function that takes a byte index and returns a bit mask
//! for the byte at that index. They can be used to significantly increase the entropy level
//! and thus hide the messages more effectively, as there's no one predetermined pattern that
//! is used for all messages.
//!
//! It is up to the *sender* to ensure that the message in its concealed form can be stored
//! fully in the cover data.
//!
//! It is required for the *receiver* of the message to know the bit pattern and, optionally,
//! the length of the message, although the latter may be included in the former by
//! short-circuiting the function by identifying the last package byte index which contains
//! the message.
//!
//! ## Use with Various Formats
//!
//! Binary data is always represented in some sort of *format*. It is straightforward to
//! use this module with various file formats - a custom reader or writer can be provide
//! to the [`Carrier`] and [`Package`] in order to customize their behavior. For example,
//! to hide a PNG image inside a WAV audio file, use a WAV reader output as cover data
//! and PNG writer as package destination.
//!
//! ## Examples
//!
//! Concealing a secret message with embedded length:
//!
//! ```no_run
//! use asbs::{binary, Conceal};
//! use std::fs::File;
//!
//! // Define the bit pattern
//! let pattern = |i| Some(1u8 << (i % 3));
//!
//! // Define the payload
//! let payload = b"a very secret message";
//!
//! // Create a carrier with the given payload length, pattern, and output file
//! let mut carrier = binary::Carrier::with_embedded_len(
//!     payload.len(),
//!     pattern,
//!     File::create("package")?,
//! );
//!
//! // Write the payload hidden within the given cover file
//! carrier.conceal(
//!     payload.as_slice(),
//!     File::open("cover")?,
//! )?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Extracting a hidden message with embedded length:
//!
//! ```no_run
//! use asbs::{binary, Reveal};
//! use std::fs::File;
//!
//! // Define the bit pattern
//! let pattern = |_| Some(0b1010);
//!
//! // Create a package with the given pattern and input file
//! let mut package = binary::Package::with_embedded_len(
//!     pattern,
//!     File::open("package")?,
//! );
//!
//! // Write the extracted message into a file
//! package.reveal(File::create("message")?)?;
//! # Ok::<(), std::io::Error>(())
//! ```

mod bits;
mod carrier;
mod package;

pub use carrier::Carrier;
pub use package::Package;
