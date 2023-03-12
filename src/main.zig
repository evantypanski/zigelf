const headers = @import("headers.zig");
const symbols = @import("symbols.zig");

const std = @import("std");
const testing = std.testing;

const ElfError = error{
    InvalidProgramHeader,
    InvalidSectionHeader,
    InvalidSymbol,
};

const Elf = struct {
    const Self = @This();

    file: std.fs.File,
    file_header: headers.FileHeader,
    program_headers: std.ArrayList(headers.ProgramHeader64),
    section_headers: std.ArrayList(headers.SectionHeader64),
    symbol_table: std.ArrayList(symbols.Elf64Sym),
    dynsym_table: std.ArrayList(symbols.Elf64Sym),

    symtab_index: ?u64,
    dynsym_index: ?u64,

    pub fn init(file: std.fs.File, allocator: std.mem.Allocator) !Self {
        const file_header = try headers.FileHeader.init(file);
        var self = Self{
            .file = file,
            .file_header = file_header,
            .program_headers = std.ArrayList(headers.ProgramHeader64).init(allocator),
            .section_headers = std.ArrayList(headers.SectionHeader64).init(allocator),
            .symbol_table = std.ArrayList(symbols.Elf64Sym).init(allocator),
            .dynsym_table = std.ArrayList(symbols.Elf64Sym).init(allocator),

            .symtab_index = null,
            .dynsym_index = null,
        };
        try self.parseHeaders();
        if (self.symtab_index) |symtab_index| {
            try self.parseSymbolTable(&self.symbol_table, self.section_headers.items[symtab_index]);
        }
        if (self.dynsym_index) |dynsym_index| {
            try self.parseSymbolTable(&self.dynsym_table, self.section_headers.items[dynsym_index]);
        }

        return self;
    }

    fn parseHeaders(self: *Self) !void {
        var prog_i: u32 = 0;
        while (prog_i < self.file_header.numProgramHeaders()) : (prog_i += 1) {
            try self.file.seekTo(self.file_header.programHeaderAddressForNum(prog_i));
            var prog_buf = [_]u8{0} ** 0x38;
            if (try self.file.read(&prog_buf) < 0x38) {
                return error.InvalidProgramHeader;
            }
            const prog_header = @bitCast(headers.ProgramHeader64, prog_buf);
            try self.program_headers.append(prog_header);
        }

        var sec_i: u32 = 0;
        while (sec_i < self.file_header.numSectionHeaders()) : (sec_i += 1) {
            try self.file.seekTo(self.file_header.sectionHeaderAddressForNum(sec_i));
            var sec_buf = [_]u8{0} ** 0x40;
            if (try self.file.read(&sec_buf) < 0x40) {
                return error.InvalidSectionHeader;
            }
            const sec_header = @bitCast(headers.SectionHeader64, sec_buf);
            try self.section_headers.append(sec_header);
            if (sec_header.sh_type == .SYMTAB) {
                self.symtab_index = sec_i;
            } else if (sec_header.sh_type == .DYNSYM) {
                self.dynsym_index = sec_i;
            }
        }
    }

    fn parseSymbolTable(self: Self, sym_table: *std.ArrayList(symbols.Elf64Sym), header: headers.SectionHeader64) !void {
        var parsed_so_far: u64 = 0;
        while (parsed_so_far < header.sh_size) : (parsed_so_far += header.sh_entsize) {
            try self.file.seekTo(header.sh_offset + parsed_so_far);
            var sym_buf = [_]u8{0} ** 0x14;
            if (try self.file.read(&sym_buf) < 0x14) {
                return error.InvalidSymbol;
            }
            const sym = @bitCast(symbols.Elf64Sym, sym_buf);
            try sym_table.append(sym);
        }
    }

    fn deinit(self: *const Self) void {
        self.program_headers.deinit();
        self.section_headers.deinit();
        self.symbol_table.deinit();
        self.dynsym_table.deinit();
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = headers;
    _ = symbols;
}

test "Elf file init/deinit without leak" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);
    elf.deinit();
}

test "Elf file gets correct headers" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    try testing.expect(elf.file_header.isValid());

    // Expect 32 section headers and that matches the file header
    try testing.expectEqual(elf.program_headers.items.len, 13);
    try testing.expectEqual(elf.program_headers.items.len, elf.file_header.numProgramHeaders());
    try testing.expectEqual(elf.program_headers.items[0].p_type, .PHDR);

    // Expect 32 section headers and that matches the file header
    try testing.expectEqual(elf.section_headers.items.len, 32);
    try testing.expectEqual(elf.section_headers.items.len, elf.file_header.numSectionHeaders());
    try testing.expectEqual(elf.section_headers.items[0].sh_type, .NULL);

    elf.deinit();
}

test "Elf file gets correct symbols" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);
    try testing.expectEqual(elf.symbol_table.items.len, 65);

    // First symbol all 0s
    try testing.expectEqual(@bitCast(u160, elf.symbol_table.items[0]), 0);

    // Other symbols have correct types
    try testing.expectEqual(elf.symbol_table.items[1].info_type, .FILE);
    try testing.expectEqual(elf.symbol_table.items[1].info_bind, .LOCAL);

    try testing.expectEqual(elf.symbol_table.items[5].info_type, .NOTYPE);
    try testing.expectEqual(elf.symbol_table.items[5].info_bind, .LOCAL);

    try testing.expectEqual(elf.symbol_table.items[12].info_type, .OBJECT);
    try testing.expectEqual(elf.symbol_table.items[12].info_bind, .LOCAL);

    // Dynsym
    try testing.expectEqual(@bitCast(u160, elf.dynsym_table.items[0]), 0);

    try testing.expectEqual(elf.dynsym_table.items[1].info_type, .FUNC);
    try testing.expectEqual(elf.dynsym_table.items[1].info_bind, .GLOBAL);

    try testing.expectEqual(elf.dynsym_table.items[2].info_type, .NOTYPE);
    try testing.expectEqual(elf.dynsym_table.items[2].info_bind, .WEAK);

    elf.deinit();
}
