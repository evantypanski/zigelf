const headers = @import("headers.zig");

const std = @import("std");
const testing = std.testing;

const ElfBind = enum(u4) {
    LOCAL = 0,
    GLOBAL = 1,
    WEAK = 2,
    LOOS = 10,
    HIOS = 12,
    LOPROC = 13,
    HIPROC = 15,
};

const ElfType = enum(u4) {
    NOTYPE = 0,
    OBJECT = 1,
    FUNC = 2,
    SECTION = 3,
    FILE = 4,
    LOOS = 10,
    HIOS = 12,
    LOPROC = 13,
    HIPROC = 15,
};

pub const Elf64Sym = packed struct {
    name: u32,
    info_type: ElfType,
    info_bind: ElfBind,
    other: u8,
    shndx: u16,
    value: u64,
    size: u32,
};

test "first symbol is zeroed out" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try headers.FileHeader.init(file);
    try file.seekTo(file_header.sectionHeaderAddressForNum(29));

    var sec_buf = [_]u8{0} ** 0x40;
    _ = try file.read(&sec_buf);
    const sec_header = @bitCast(headers.SectionHeader64, sec_buf);
    try file.seekTo(sec_header.sh_offset);

    var sym_buf = [_]u8{0} ** 0x14;
    _ = try file.read(&sym_buf);
    const sym = @bitCast(Elf64Sym, sym_buf);
    try testing.expectEqual(@bitCast(u160, sym), 0);
}

test "second symbol parses correctly" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const file_header = try headers.FileHeader.init(file);
    try file.seekTo(file_header.sectionHeaderAddressForNum(29));

    var sec_buf = [_]u8{0} ** 0x40;
    _ = try file.read(&sec_buf);
    const sec_header = @bitCast(headers.SectionHeader64, sec_buf);
    try file.seekTo(sec_header.sh_offset + sec_header.sh_entsize);

    var sym_buf = [_]u8{0} ** 0x14;
    _ = try file.read(&sym_buf);
    const sym = @bitCast(Elf64Sym, sym_buf);
    try testing.expectEqual(sym.info_type, .FILE);
    try testing.expectEqual(sym.info_bind, .LOCAL);
}
