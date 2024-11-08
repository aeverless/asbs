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

// Define a bit pattern
let pattern = |i| Some(1u8 << (i % 3));

// Open the cover file, which will hide our payload
let cover = File::open("cover")?;
let payload = b"a very secret message";

// Initialize a package buffer
let mut package = Vec::new();

// Create a carrier with a given pattern that will write to `package`
let mut carrier = binary::Carrier::new(pattern, &mut package);

// Write the payload hidden within the given cover into `package`
carrier.conceal(payload.as_slice(), cover)?;
```

Extracting a hidden message from a binary file:

```rust
use asbs::{binary, Reveal};
use std::fs::File;

// Define a uniform bit pattern
let pattern = |_| Some(0b_0010_00011);

// Open the package file, which contains the sought message
let package = File::open("package")?;

// Define message length
let message_len = 21;

// Initialize a message buffer
let mut message = Vec::with_capacity(message_len);

// Create a package with the given message length, pattern, and package file
let mut package = binary::Package::with_len(message_len, pattern, package);

// Write the extracted message into `message`
package.reveal(&mut message)?;
```

## License

The library is licensed under either the MIT License or Apache-2.0 License, at your option.

## Authors

Artemy Astakhov (contact at aeverless dot dev)
