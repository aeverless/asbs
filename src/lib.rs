//! # ASBS
//!
//! The **ASBS** (**A**rbitrarily **S**ignificant **B**it**s**) library provides the traits and
//! implementations useful for steganographic concealment and extraction of messages.
//!
//! ## Binary implementation
//!
//! The [`binary`] module can be used to encode messages in binary data with *bit patterns*,
//! which act as keys and should be shared with the receiver of the message. See its
//! [documentation][`binary`] for details.

use std::io;

pub mod binary;

/// A trait for objects able to conceal steganographic messages, or carriers.
///
/// Carriers are defined by a single required method, [`conceal`][Conceal::conceal],
/// which hides the payload in the given cover data.
///
/// # Examples
///
/// [`binary::Carrier`] can be used to conceal secret messages in binary data.
pub trait Conceal {
    /// Conceals the payload in the given cover and returns how many bytes were written in total.
    ///
    /// This function does not provide any guarantees about written data if `payload` cannot fit
    /// entirely inside `cover` in its concealed form. An implementation is free to truncate the
    /// contents in that case.
    ///
    /// # Errors
    ///
    /// This function returns any form of error encountered to the caller. If an error
    /// is returned, however, it is not guaranteed that no bytes were written.
    fn conceal<P: io::Read, C: io::Read>(self, payload: P, cover: C) -> io::Result<usize>;
}

/// A trait for objects able to reveal steganographic messages, or packages.
///
/// Packages are defined by a single required method, [`reveal`][Reveal::reveal],
/// which writes the hidden message to the output.
///
/// # Examples
///
/// [`binary::Package`] can be used to reveal secret messages hidden in binary data.
pub trait Reveal {
    /// Writes the hidden message into `output`, returning how many bytes were written.
    ///
    /// It is up to the implementations to establish a format and conditions under which
    /// the hidden message is interpreted.
    ///
    /// For instance, an implementation may prepend message length to the message while
    /// writing, or may provide the caller with a way to specify its length so that the
    /// function writes only as many bytes as needed.
    ///
    /// # Errors
    ///
    /// This function returns any form of error encountered to the caller. If an error
    /// is returned, however, it is not guaranteed that no bytes were written.
    fn reveal<W: io::Write>(self, output: W) -> io::Result<usize>;
}
