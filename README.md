# Zigelf

Zig library for reading elf binaries.

Few of these exist but I wanted a more useful one as a library with an easier format to use.

Project currently parses the main parts of an elf 64 file. It does not support elf 32 files. It does not support different endianness. It's just what worked for my particular file right now.

So if you want to use this, probably:

- Make the types not enums, instead use the `std.elf` constants to compare and allow them to be nonexhaustive
- Make the names all conform to the `elf` man page
- Support 32 bit elf files
- Support different endianness

But overall it's a good start if you need to READ elf files in zig. I think.
