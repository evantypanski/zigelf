pub const Elf64Note = packed struct {
    namesz: u32,
    descsz: u32,
    type_: u32,
};

// A note, followed by its associated name and description
pub const Note = struct {
    inner: Elf64Note,
    // Offset in the elf file of the end of this note. Starting byte is the
    // first byte of the name, if it exists.
    offset: u64,
};
