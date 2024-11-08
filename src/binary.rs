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
//! Hiding a message within a binary file:
//!
//! ```no_run
//! use asbs::{binary, Conceal};
//! use std::fs::File;
//!
//! // Define a bit pattern
//! let pattern = |i| Some(1u8 << (i % 3));
//!
//! // Open the cover file, which will hide our payload
//! let cover = File::open("cover")?;
//! let payload = b"a very secret message";
//!
//! // Initialize a package buffer
//! let mut package = Vec::new();
//!
//! // Create a carrier with a given pattern that will write to `package`
//! let mut carrier = binary::Carrier::new(pattern, &mut package);
//!
//! // Write the payload hidden within the given cover into `package`
//! carrier.conceal(payload.as_slice(), cover)?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Extracting a hidden message from a binary file:
//!
//! ```no_run
//! use asbs::{binary, Reveal};
//! use std::fs::File;
//!
//! // Define a uniform bit pattern
//! let pattern = |_| Some(0b_0010_00011);
//!
//! // Open the package file, which contains the sought message
//! let package = File::open("package")?;
//!
//! // Define message length
//! let message_len = 21;
//!
//! // Initialize a message buffer
//! let mut message = Vec::with_capacity(message_len);
//!
//! // Create a package with the given message length, pattern, and package file
//! let mut package = binary::Package::with_len(message_len, pattern, package);
//!
//! // Write the extracted message into `message`
//! package.reveal(&mut message)?;
//! # Ok::<(), std::io::Error>(())
//! ```

mod bits;
mod carrier;
mod package;

pub use carrier::Carrier;
pub use package::Package;
