const headers = @import("headers.zig");
const symbols = @import("symbols.zig");

const std = @import("std");
const testing = std.testing;

const ElfError = error{
    InvalidProgramHeader,
    InvalidSectionHeader,
    InvalidSymbol,
    InvalidStrtab,
    StringTableIndexOutOfBounds,
    StringTableDoesNotExist,
};

const Elf = struct {
    const Self = @This();

    allocator: std.mem.Allocator,

    file: std.fs.File,
    file_header: headers.FileHeader,
    program_headers: std.ArrayList(headers.ProgramHeader64),
    section_headers: std.ArrayList(headers.SectionHeader64),
    symbol_table: std.ArrayList(symbols.Elf64Sym),
    dynsym_table: std.ArrayList(symbols.Elf64Sym),

    section_header_string_table: ?[]u8,
    string_table: ?[]u8,
    dynstr_table: ?[]u8,

    symtab_index: ?u64,
    dynsym_index: ?u64,

    pub fn init(file: std.fs.File, allocator: std.mem.Allocator) !Self {
        const file_header = try headers.FileHeader.init(file);
        var self = Self{
            .allocator = allocator,
            .file = file,
            .file_header = file_header,
            .program_headers = std.ArrayList(headers.ProgramHeader64).init(allocator),
            .section_headers = std.ArrayList(headers.SectionHeader64).init(allocator),
            .symbol_table = std.ArrayList(symbols.Elf64Sym).init(allocator),
            .dynsym_table = std.ArrayList(symbols.Elf64Sym).init(allocator),

            .section_header_string_table = null,
            .string_table = null,
            .dynstr_table = null,

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

        const strtab_index = file_header.sectionStringTableIndex();
        if (strtab_index < self.section_headers.items.len) {
            try self.parseStringTableFromSection(self.section_headers.items[strtab_index], &self.section_header_string_table);

            // Now parse remaining symbol tables. Need to first have the shstrtab
            // so that we get names.
            try self.parseStringTablesByName();
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

    fn parseStringTableFromSection(self: Self, header: headers.SectionHeader64, string_table: *?[]u8) !void {
        var buf = try self.allocator.alloc(u8, header.sh_size);
        try self.file.seekTo(header.sh_offset);
        if (try self.file.read(buf) < header.sh_size) {
            return error.InvalidStrtab;
        }
        string_table.* = buf;
    }

    fn parseStringTablesByName(self: *Self) !void {
        for (self.section_headers.items) |header| {
            if (header.sh_type == .STRTAB) {
                const name = try self.nameOfSection(header);
                if (std.mem.eql(u8, name, ".strtab")) {
                    try self.parseStringTableFromSection(header, &self.string_table);
                } else if (std.mem.eql(u8, name, ".dynstr")) {
                    //try self.parseStringTableFromSection(header, &self.dynstr_table);
                }
            }
        }
    }

    // Returns string at index in string table
    fn stringAtIndex(self: Self, index: u8) ![]const u8 {
        var end_index = index;
        while (true) : (end_index += 1) {
            if (end_index > self.string_table.len) {
                return error.StringTableIndexOutOfBounds;
            }

            if (self.section_header_string_table[end_index] == 0) {
                break;
            }
        }

        return self.string_table[index..end_index];
    }

    fn nameOfSection(self: Self, section: headers.SectionHeader64) ![]const u8 {
        const string_table = self.section_header_string_table orelse return error.StringTableDoesNotExist;
        // Not quite sure how to make this cleaner
        // Start with end_index == start index, iterate until we see a 0
        var end_index = section.sh_name;
        while (true) : (end_index += 1) {
            if (end_index > string_table.len) {
                return error.StringTableIndexOutOfBounds;
            }

            if (string_table[end_index] == 0) {
                break;
            }
        }

        return string_table[section.sh_name..end_index];
    }

    // Takes index of where to search for the name
    fn nameOfSymbol(self: Self, index: u32) ![]const u8 {
        const string_table = self.string_table orelse return error.StringTableDoesNotExist;

        var end_index = index;

        while (true) : (end_index += 1) {
            if (end_index > string_table.len) {
                return error.StringTableIndexOutOfBounds;
            }

            if (string_table[end_index] == 0) {
                break;
            }
        }

        return string_table[index..end_index];
    }

    fn deinit(self: *const Self) void {
        self.program_headers.deinit();
        self.section_headers.deinit();
        self.symbol_table.deinit();
        self.dynsym_table.deinit();
        if (self.section_header_string_table) |section_header_string_table| {
            self.allocator.free(section_header_string_table);
        }
        if (self.string_table) |string_table| {
            self.allocator.free(string_table);
        }
        if (self.dynstr_table) |dynstr_table| {
            self.allocator.free(dynstr_table);
        }
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

test "Elf file finds .shstrtab" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    const header = elf.section_headers.items[elf.file_header.sectionStringTableIndex()];
    try testing.expectEqualStrings(try elf.nameOfSection(header), ".shstrtab");

    elf.deinit();
}

test "Elf file finds .strtab" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    try testing.expectEqualStrings(try elf.nameOfSymbol(elf.symbol_table.items[2].name), ".annobin_abi_note.c");

    elf.deinit();
}
