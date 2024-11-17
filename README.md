# ASBS

The **ASBS** (**A**rbitrarily **S**ignificant **B**it**s**) library provides the traits and
implementations useful for steganographic concealment and extraction of messages.

## Binary Implementation

The library provides the `binary` module which can be used to encode messages in binary
data with *bit patterns*, which act as keys and should be shared with the receiver of
the message.

*Bit patterns* are defined as a function that takes a byte index and returns a bit mask
for the byte at that index. They can be used to significantly increase the entropy level
and thus hide the messages more effectively, as there's no one predetermined pattern that
is used for all messages.

See [`src/binary.rs`](src/binary.rs) for more details.

## Examples

Hiding a message within a binary file:

```rust
use asbs::{binary, Conceal};
use std::fs::File;

// Define the bit pattern
let pattern = |i| Some(1u8 << (i % 3));

// Define the payload
let payload = b"a very secret message";

// Create a carrier with the given payload length, pattern, and output file
let mut carrier = binary::Carrier::with_embedded_len(
    payload.len(),
    pattern,
    File::create("package")?,
);

// Write the payload hidden within the given cover file
carrier.conceal(
    payload.as_slice(),
    File::open("cover")?,
)?;
```

Extracting a hidden message from a binary file:

```rust
use asbs::{binary, Reveal};
use std::fs::File;

// Define the bit pattern
let pattern = |i| Some(1u8 << (i % 3));

// Create a package with the given pattern and input file
let mut package = binary::Package::with_embedded_len(
    pattern,
    File::open("package")?,
);

// Write the extracted message into a file
package.reveal(File::create("message")?)?;
```

## License

The library is licensed under either the [MIT License](LICENSE-MIT) or the [Apache-2.0 License](LICENSE-APACHE), at your option.

## Authors

Artemy Astakhov (contact at aeverless dot dev)
