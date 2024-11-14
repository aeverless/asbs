use crate::{binary::bits, Reveal};
use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    ops::ControlFlow,
};

/// A binary package that contains a steganographic message.
///
/// It writes to the package writer in the [`reveal`][crate::Reveal::reveal] method until
/// either occurs:
///
/// 1. The underlying reader is empty, or
/// 2. The package no longer accepts writes, or
/// 3. The required length of bytes was written.
///
/// # Examples
///
/// Revealing a secret message of known length hidden within the package:
///
/// ```no_run
/// use asbs::{binary, Reveal};
/// use std::fs::File;
///
/// let pattern = |_| Some(0b_0010_00011);
/// let package = File::open("package")?;
///
/// let message_len = 21;
/// let mut message = Vec::with_capacity(message_len);
///
/// let mut package = binary::Package::with_len(message_len, pattern, package);
/// package.reveal(&mut message)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Package<P, R>
where
    P: FnMut(usize) -> Option<u8>,
    R: Read,
{
    pattern: P,
    reader: BufReader<R>,
    len: usize,
}

impl<P, R> Package<P, R>
where
    P: FnMut(usize) -> Option<u8>,
    R: Read,
{
    /// Creates a new [`Package<P, R>`] with the supplied message length, pattern, and reader.
    ///
    /// This function may be useful when you know expected message length and the bit
    /// pattern does not include an upper limit on the index.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let pattern = |i| Some(1u8 << (i % 3) + (i % 2));
    /// let package = File::open("package")?;
    /// let message_length = 32;
    ///
    /// let mut package = binary::Package::with_len(message_length, pattern, package);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn with_len(len: usize, pattern: P, reader: R) -> Self {
        Self {
            pattern,
            reader: BufReader::new(reader),
            len,
        }
    }

    /// Creates a new [`Package<P, R>`] with the supplied pattern and reader.
    ///
    /// This does not impose any limits upon the number of bytes that will be
    /// read from the package - if message length is known, use [`Package::with_len`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let pattern = |i| Some(if i % 64 > 32 { 0b_1001_0010 } else { 0b_0000_0011 });
    /// let package = File::open("package")?;
    ///
    /// let mut package = binary::Package::new(pattern, package);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(pattern: P, reader: R) -> Self {
        Self::with_len(usize::MAX, pattern, reader)
    }
}

impl<M, R> Reveal for &mut Package<M, R>
where
    M: FnMut(usize) -> Option<u8>,
    R: Read,
{
    type Err = io::Error;

    fn reveal<W: Write>(self, output: W) -> io::Result<usize> {
        let mut output = BufWriter::new(output);

        let mut payload_byte = 0u8;
        let mut bit_count = 0usize;

        let mut bytes_written = 0usize;

        let mut write_byte = |byte| -> Result<ControlFlow<()>, io::Error> {
            bytes_written += output.write(&[byte])?;

            Ok(if bytes_written < self.len {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            })
        };

        for (index, package_byte) in self.reader.by_ref().bytes().enumerate() {
            let Some(mask) = (self.pattern)(index) else {
                break;
            };

            let package_byte = package_byte?;
            for pow in bits::Ones::from(mask) {
                payload_byte |= ((package_byte >> pow) & 1) << bit_count;
                bit_count += 1;

                if bit_count < 8 {
                    continue;
                }

                if write_byte(payload_byte)?.is_break() {
                    return Ok(bytes_written);
                }

                bit_count = 0;
                payload_byte = 0;
            }
        }

        if bit_count > 0 {
            write_byte(payload_byte)?;
        }

        Ok(bytes_written)
    }
}
