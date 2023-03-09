const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const ABI = enum(u8) {
    SYSTEM_V = 0x00,
    HP_UX = 0x01,
    NET_BSD = 0x02,
    LINUX = 0x03,
    GNU_HURD = 0x04,
    SOLARIS = 0x06,
    AIX = 0x07,
    IRIX = 0x08,
    FREE_BSD = 0x09,
    TRU64 = 0x0A,
    NOVELL_MODESTO = 0x0B,
    OPEN_BSD = 0x0C,
    OPEN_VMS = 0x0D,
    NON_STOP_KERNEL = 0x0E,
    AROS = 0x0F,
    FENIX_OS = 0x10,
    NUXI_CLOUD_ABI = 0x11,
    STRATUS_TECHNOLOGIES_OPEN_VOS = 0x12,
};

// Note this is always the size of the 64 bit header unfortunately. :/
pub const FileHeader = packed struct {
    const Self = @This();

    mag0: u8,
    mag1: u8,
    mag2: u8,
    mag3: u8,
    class: u8,
    data: u8,
    version: u8,
    osabi: u8,
    abi_version: u8,

    padding: u56,

    target_specific: packed union {
        elf64: packed struct {
            e_type: u16,
            e_machine: u16,
            e_version: u32,
            e_entry: u64,
            e_phoff: u64,
            e_shoff: u64,
            e_flags: u32,
            e_ehsize: u16,
            e_phentsize: u16,
            e_phnum: u16,
            e_shentsize: u16,
            e_shnum: u16,
            e_shstrndx: u16,
        },
        elf32: packed struct {
            e_type: u16,
            e_machine: u16,
            e_version: u32,
            e_entry: u32,
            e_phoff: u32,
            e_shoff: u32,
            e_flags: u32,
            e_ehsize: u16,
            e_phentsize: u16,
            e_phnum: u16,
            e_shentsize: u16,
            e_shnum: u16,
            e_shstrndx: u16,
        },
    },

    // Initializes the file header from the file
    pub fn init(file: std.fs.File) !Self {
        var buf = [_]u8{0} ** 0x40;
        // TODO this should error if not read 0x40
        _ = try file.read(&buf);
        return @bitCast(FileHeader, buf);
    }

    pub fn isValid(self: Self) bool {
        return self.mag0 == 0x7F and self.mag1 == 0x45 and
            self.mag2 == 0x4c and self.mag3 == 0x46;
    }

    pub fn is64Bit(self: Self) bool {
        return self.class == 2;
    }

    pub fn endianness(self: Self) std.builtin.Endian {
        return if (self.data == 1)
            std.builtin.Endian.Little
        else
            std.builtin.Endian.Big;
    }

    pub fn abi(self: Self) ABI {
        return @intToEnum(ABI, self.osabi);
    }

    pub fn abiVersion(self: Self) u8 {
        return self.abi_version;
    }

    // Start "target specific" section
    // Until the entry point both have the same layout, so we can just use the
    // 32 bit one. After that we need to differentiate.
    pub fn objectType(self: Self) std.elf.ET {
        return @intToEnum(std.elf.ET, self.target_specific.elf32.e_type);
    }

    pub fn machine(self: Self) std.elf.EM {
        return @intToEnum(std.elf.EM, self.target_specific.elf32.e_machine);
    }

    pub fn elfVersion(self: Self) u32 {
        return self.target_specific.elf32.e_version;
    }

    // May be 32 or 64 bit. If needed as u32 that can be cast.
    pub fn entryAddress(self: Self) u64 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_entry
        else
            self.target_specific.elf32.e_entry;
    }

    // May be 32 or 64 bit. If needed as u32 that can be cast.
    pub fn programHeaderAddress(self: Self) u64 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_phoff
        else
            self.target_specific.elf32.e_phoff;
    }

    // Finds program header address for a specific number program header.
    // Zero indexed.
    pub fn programHeaderAddressForNum(self: Self, num: u64) u64 {
        assert(num < self.numProgramHeaders());
        const offset = num * self.programHeaderSize();
        return if (self.is64Bit())
            self.target_specific.elf64.e_phoff + offset
        else
            self.target_specific.elf32.e_phoff + offset;
    }

    // May be 32 or 64 bit. If needed as u32 that can be cast.
    pub fn sectionHeaderAddress(self: Self) u64 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_shoff
        else
            self.target_specific.elf32.e_shoff;
    }

    // Finds section header address for a specific number section header.
    // Zero indexed.
    pub fn sectionHeaderAddressForNum(self: Self, num: u64) u64 {
        assert(num < self.numSectionHeaders());
        const offset = num * self.sectionHeaderSize();
        return if (self.is64Bit())
            self.target_specific.elf64.e_shoff + offset
        else
            self.target_specific.elf32.e_shoff + offset;
    }

    pub fn flags(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_flags
        else
            self.target_specific.elf32.e_flags;
    }

    pub fn fileHeaderSize(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_ehsize
        else
            self.target_specific.elf32.e_ehsize;
    }

    pub fn programHeaderSize(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_phentsize
        else
            self.target_specific.elf32.e_phentsize;
    }

    pub fn numProgramHeaders(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_phnum
        else
            self.target_specific.elf32.e_phnum;
    }

    pub fn sectionHeaderSize(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_shentsize
        else
            self.target_specific.elf32.e_shentsize;
    }

    pub fn numSectionHeaders(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_shnum
        else
            self.target_specific.elf32.e_shnum;
    }

    pub fn sectionStringTableIndex(self: Self) u32 {
        return if (self.is64Bit())
            self.target_specific.elf64.e_shstrndx
        else
            self.target_specific.elf32.e_shstrndx;
    }
};

const ProgramType = enum(u32) {
    NULL = 0x00000000,
    LOAD = 0x00000001,
    DYNAMIC = 0x00000002,
    INTERP = 0x00000003,
    NOTE = 0x00000004,
    SHLIB = 0x00000005,
    PHDR = 0x00000006,
    TLS = 0x00000007,
    LOOS = 0x60000000,
    HIOS = 0x6FFFFFFF,
    LOPROC = 0x70000000,
    HIPROC = 0x7FFFFFFF,
    _,
};

pub const ProgramHeader64 = packed struct {
    p_type: ProgramType,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

pub const ProgramHeader32 = packed struct {
    p_type: ProgramType,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
};

const HeaderType = enum(u32) {
    NULL = 0x0,
    PROGBITS = 0x1,
    SYMTAB = 0x2,
    STRTAB = 0x3,
    RELA = 0x4,
    HASH = 0x5,
    DYNAMIC = 0x6,
    NOTE = 0x7,
    NOBITS = 0x8,
    REL = 0x9,
    SHLIB = 0xA,
    DYNSYM = 0xB,
    INIT_ARRAY = 0xE,
    FINI_ARRAY = 0xF,
    PREINIT_ARRAY = 0x10,
    GROUP = 0x11,
    SYMTAB_SHNDX = 0x12,
    NUM = 0x13,
    LOOS = 0x60000000,
    _,
};

pub const SectionHeader64 = packed struct {
    sh_name: u32,
    sh_type: HeaderType,
    sh_flags: enum(u64) {
        WRITE = 0x1,
        ALLOC = 0x2,
        EXECINSTR = 0x4,
        MERGE = 0x10,
        STRINGS = 0x20,
        INFO_LINK = 0x40,
        LINK_ORDER = 0x80,
        OS_NONCONFORMING = 0x100,
        GROUP = 0x200,
        TLS = 0x400,
        MASKOS = 0x0FF00000,
        MASKPROC = 0xF0000000,
        ORDERED = 0x4000000,
        EXCLUDE = 0x8000000,
    },
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

test "64 bit file header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    var buf = [_]u8{0} ** 0x40;
    _ = try file.read(&buf);
    const file_header = @bitCast(FileHeader, buf);
    try testing.expect(file_header.isValid());
    try testing.expect(file_header.is64Bit());
    try testing.expectEqual(file_header.endianness(), .Little);
    try testing.expectEqual(file_header.abi(), .SYSTEM_V);
    try testing.expectEqual(file_header.abiVersion(), 0);
    try testing.expectEqual(file_header.objectType(), .EXEC);
    try testing.expectEqual(file_header.machine(), .X86_64);
    try testing.expectEqual(file_header.elfVersion(), 1);
    try testing.expectEqual(file_header.entryAddress(), 0x401020);
    try testing.expectEqual(file_header.programHeaderAddress(), 0x40);
    try testing.expectEqual(file_header.sectionHeaderAddress(), 23192);
    try testing.expectEqual(file_header.flags(), 0);
    try testing.expectEqual(file_header.fileHeaderSize(), 64);
    try testing.expectEqual(file_header.programHeaderSize(), 56);
    try testing.expectEqual(file_header.numProgramHeaders(), 13);
    try testing.expectEqual(file_header.sectionHeaderSize(), 64);
    try testing.expectEqual(file_header.numSectionHeaders(), 32);
    try testing.expectEqual(file_header.sectionStringTableIndex(), 31);
}

test "32 bit file header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf32-nolink.out", .{ .mode = .read_only });
    var buf = [_]u8{0} ** 0x40;
    _ = try file.read(&buf);
    const file_header = @bitCast(FileHeader, buf);
    try testing.expect(file_header.isValid());
    try testing.expect(!file_header.is64Bit());
    try testing.expectEqual(file_header.endianness(), .Little);
    try testing.expectEqual(file_header.abi(), .SYSTEM_V);
    try testing.expectEqual(file_header.abiVersion(), 0);
    try testing.expectEqual(file_header.objectType(), .REL);
    try testing.expectEqual(file_header.machine(), .@"386");
    try testing.expectEqual(file_header.elfVersion(), 1);
    try testing.expectEqual(file_header.entryAddress(), 0x0); // None
    try testing.expectEqual(file_header.programHeaderAddress(), 0);
    try testing.expectEqual(file_header.sectionHeaderAddress(), 752);
    try testing.expectEqual(file_header.flags(), 0);
    try testing.expectEqual(file_header.fileHeaderSize(), 52);
    try testing.expectEqual(file_header.programHeaderSize(), 0);
    try testing.expectEqual(file_header.numProgramHeaders(), 0);
    try testing.expectEqual(file_header.sectionHeaderSize(), 40);
    try testing.expectEqual(file_header.numSectionHeaders(), 15);
    try testing.expectEqual(file_header.sectionStringTableIndex(), 1);
}

test "first 64 bit program header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try FileHeader.init(file);
    try file.seekTo(file_header.programHeaderAddress());

    var prog_buf = [_]u8{0} ** 0x38;
    _ = try file.read(&prog_buf);
    const prog_header = @bitCast(ProgramHeader64, prog_buf);
    try testing.expectEqual(prog_header.p_type, .PHDR);
}

test "third 64 bit program header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try FileHeader.init(file);
    try file.seekTo(file_header.programHeaderAddressForNum(2));

    var prog_buf = [_]u8{0} ** 0x38;
    _ = try file.read(&prog_buf);
    const prog_header = @bitCast(ProgramHeader64, prog_buf);
    try testing.expectEqual(prog_header.p_type, .LOAD);
}

test "first 64 bit section header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try FileHeader.init(file);
    try file.seekTo(file_header.sectionHeaderAddress());

    var sec_buf = [_]u8{0} ** 0x40;
    _ = try file.read(&sec_buf);
    const sec_header = @bitCast(SectionHeader64, sec_buf);
    try testing.expectEqual(sec_header.sh_type, .NULL);
}

test "third 64 bit section header parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try FileHeader.init(file);
    try file.seekTo(file_header.sectionHeaderAddressForNum(2));

    var sec_buf = [_]u8{0} ** 0x40;
    _ = try file.read(&sec_buf);
    const sec_header = @bitCast(SectionHeader64, sec_buf);
    try testing.expectEqual(sec_header.sh_type, .NOTE);
}
