const headers = @import("headers.zig");
const symbols = @import("symbols.zig");
const notes = @import("notes.zig");

const std = @import("std");
const testing = std.testing;

const ElfError = error{
    InvalidProgramHeader,
    InvalidSectionHeader,
    InvalidSymbol,
    InvalidStrtab,
    InvalidRelocation,
    InvalidDyn,
    InvalidNote,
    StringTableIndexOutOfBounds,
    StringTableDoesNotExist,
    HeaderTypeMismatch,
};

const DynTag = enum(i64) {
    NULL = 0x0,
    NEEDED = 0x1,
    PLTRELSZ = 0x2,
    PLTGOT = 0x3,
    HASH = 0x4,
    STRTAB = 0x5,
    SYMTAB = 0x6,
    RELA = 0x7,
    RELASZ = 0x8,
    RELAENT = 0x9,
    STRSZ = 0xA,
    SYMENT = 0xB,
    INIT = 0xC,
    FINI = 0xD,
    SONAME = 0xE,
    RPATH = 0xF,
    SYMBOLIC = 0x10,
    REL = 0x11,
    RELSZ = 0x12,
    RELENT = 0x13,
    PLTREL = 0x14,
    DEBUG = 0x15,
    TEXTREL = 0x16,
    JMPREL = 0x17,
    BIND_NOW = 0x18,
    RUNPATH = 0x1D,
    LOOS = 0x6000000D,
    HIOS = 0x6FFFF000,
    LOPROC = 0x70000000,
    HIPROC = 0x7fffffff,
    _,
};

// This doesn't really fit anywhere else
// Tagged union for dynamic section
const Elf64Dyn = packed struct {
    const Self = @This();

    tag: DynTag,
    un: packed union {
        val: u64,
        ptr: u64,
    },

    // Selects if this should get un.val, un.ptr, or it's ignored.
    // Note that if we don't know what to select we will also return ignore,
    // so if there's OS-specific options you must determine those yourself.
    pub fn unionSelection(self: Self) enum { VAL, PTR, IGNORE } {
        switch (self.tag) {
            .NEEDED, .PLTRELSZ, .RELASZ, .RELAENT, .SYMENT, .SONAME, .RPATH, .RELSZ, .RELENT, .PLTREL, .RUNPATH => return .VAL,
            .PLTGOT, .HASH, .STRTAB, .SYMTAB, .RELA, .INIT, .FINI, .REL, .DEBUG, .JMPREL => return .PTR,
            else => return .IGNORE,
        }
    }
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

    dynamic_info: std.ArrayList(Elf64Dyn),

    section_header_string_table: ?[]u8,
    string_table: ?[]u8,
    dynstr_table: ?[]u8,

    symtab_index: ?u64,
    dynsym_index: ?u64,
    dynamic_index: ?u64,

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

            .dynamic_info = std.ArrayList(Elf64Dyn).init(allocator),

            .section_header_string_table = null,
            .string_table = null,
            .dynstr_table = null,

            .symtab_index = null,
            .dynsym_index = null,
            .dynamic_index = null,
        };
        try self.parseHeaders();
        if (self.symtab_index) |symtab_index| {
            try self.parseSymbolTable(&self.symbol_table, self.section_headers.items[symtab_index]);
        }
        if (self.dynsym_index) |dynsym_index| {
            try self.parseSymbolTable(&self.dynsym_table, self.section_headers.items[dynsym_index]);
        }
        if (self.dynamic_index) |dynamic_index| {
            try self.parseDynamicInfo(self.section_headers.items[dynamic_index]);
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
        const prog_size = @bitSizeOf(headers.ProgramHeader64) / 8;
        while (prog_i < self.file_header.numProgramHeaders()) : (prog_i += 1) {
            try self.file.seekTo(self.file_header.programHeaderAddressForNum(prog_i));
            var prog_buf = [_]u8{0} ** prog_size;
            if (try self.file.read(&prog_buf) < prog_size) {
                return error.InvalidProgramHeader;
            }
            const prog_header = @bitCast(headers.ProgramHeader64, prog_buf);
            try self.program_headers.append(prog_header);
        }

        var sec_i: u32 = 0;
        const sec_size = @bitSizeOf(headers.SectionHeader64) / 8;
        while (sec_i < self.file_header.numSectionHeaders()) : (sec_i += 1) {
            try self.file.seekTo(self.file_header.sectionHeaderAddressForNum(sec_i));
            var sec_buf = [_]u8{0} ** sec_size;
            if (try self.file.read(&sec_buf) < sec_size) {
                return error.InvalidSectionHeader;
            }
            const sec_header = @bitCast(headers.SectionHeader64, sec_buf);
            try self.section_headers.append(sec_header);
            if (sec_header.sh_type == .SYMTAB) {
                self.symtab_index = sec_i;
            } else if (sec_header.sh_type == .DYNSYM) {
                self.dynsym_index = sec_i;
            } else if (sec_header.sh_type == .DYNAMIC) {
                self.dynamic_index = sec_i;
            }
        }
    }

    fn parseSymbolTable(self: Self, sym_table: *std.ArrayList(symbols.Elf64Sym), header: headers.SectionHeader64) !void {
        var parsed_so_far: u64 = 0;
        const size = @bitSizeOf(symbols.Elf64Sym) / 8;
        while (parsed_so_far < header.sh_size) : (parsed_so_far += header.sh_entsize) {
            try self.file.seekTo(header.sh_offset + parsed_so_far);
            var sym_buf = [_]u8{0} ** size;
            if (try self.file.read(&sym_buf) < size) {
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

    fn findSectionByName(self: Self, target_name: []const u8) ?headers.SectionHeader64 {
        for (self.section_headers.items) |header| {
            const section_name = self.nameOfSection(header) catch continue;
            if (std.mem.eql(u8, section_name, target_name)) {
                return header;
            }
        }

        return null;
    }

    // Gets relocation structures without addends from the given header.
    // Caller is responsible for managing the returned structure's memory.
    fn getRelStructures(self: Self, header: headers.SectionHeader64) ![]symbols.Elf64Rel {
        return self.getRelStructuresInner(header, symbols.Elf64Rel);
    }

    // Gets relocation structures with addends from the given header.
    // Caller is responsible for managing the returned structure's memory.
    fn getRelStructuresAddend(self: Self, header: headers.SectionHeader64) ![]symbols.Elf64Rela {
        return self.getRelStructuresInner(header, symbols.Elf64Rela);
    }

    fn getRelStructuresInner(self: Self, header: headers.SectionHeader64, comptime rel_type: type) ![]rel_type {
        if (rel_type != symbols.Elf64Rel and rel_type != symbols.Elf64Rela) {
            @compileError("Can only get rel structures of relocation types");
        }

        if ((header.sh_type != .REL and rel_type == symbols.Elf64Rel) or
            (header.sh_type != .RELA and rel_type == symbols.Elf64Rela))
        {
            return error.HeaderTypeMismatch;
        }

        var buf = try self.allocator.alloc(rel_type, header.sh_size / header.sh_entsize);
        errdefer self.allocator.free(buf);

        var i: u64 = 0;
        // bitsizeof to avoid padding
        const size = @bitSizeOf(rel_type) / 8;
        while (i * header.sh_entsize < header.sh_size) : (i += 1) {
            try self.file.seekTo(header.sh_offset + i * header.sh_entsize);
            var rel_buf = [_]u8{0} ** size;
            if (try self.file.read(&rel_buf) < size) {
                return error.InvalidRelocation;
            }
            const rel = @bitCast(rel_type, rel_buf);
            buf[i] = rel;
        }

        return buf;
    }

    fn parseDynamicInfo(self: *Self, header: headers.SectionHeader64) !void {
        var parsed_so_far: u64 = 0;
        // bitsizeof to avoid padding
        const size = @bitSizeOf(Elf64Dyn) / 8;
        while (parsed_so_far < header.sh_size) : (parsed_so_far += header.sh_entsize) {
            try self.file.seekTo(header.sh_offset + parsed_so_far);
            var buf = [_]u8{0} ** size;
            if (try self.file.read(&buf) < size) {
                return error.InvalidSymbol;
            }
            const dyn = @bitCast(Elf64Dyn, buf);
            try self.dynamic_info.append(dyn);
        }
    }

    // Notes are parsed differently: They are a struct of known size, followed
    // by a name with a length described by its first field, followed by a
    // description with a length described by its second field.
    fn getNotes(self: Self, header: headers.SectionHeader64) !std.ArrayList(notes.Note) {
        if (header.sh_type != .NOTE) {
            return error.HeaderTypeMismatch;
        }
        var buf = std.ArrayList(notes.Note).init(self.allocator);
        errdefer buf.deinit();

        var note_offset: u64 = 0;
        // bitsizeof to avoid padding
        const size = @bitSizeOf(notes.Elf64Note) / 8;
        while (note_offset < header.sh_size) {
            try self.file.seekTo(header.sh_offset + note_offset);
            var note_buf = [_]u8{0} ** size;
            if (try self.file.read(&note_buf) < size) {
                return error.InvalidNote;
            }
            const elf_note = @bitCast(notes.Elf64Note, note_buf);

            // Parse name
            note_offset += size;

            const note = notes.Note{ .inner = elf_note, .offset = header.sh_offset + note_offset };
            try buf.append(note);
            note_offset += elf_note.namesz + elf_note.descsz;
        }

        return buf;
    }

    // Name of a given note.
    // Caller's responsibility to free it.
    fn nameOfNote(self: Self, note: notes.Note) !?[]const u8 {
        if (note.inner.namesz == 0) {
            return null;
        }
        try self.file.seekTo(note.offset);
        var buf = try self.allocator.alloc(u8, note.inner.namesz);
        if (try self.file.read(buf) < note.inner.namesz) {
            return error.InvalidNote;
        }
        return buf;
    }

    // Description of a given note.
    // Caller's responsibility to free it.
    fn descriptionOfNote(self: Self, note: notes.Note) !?[]const u8 {
        if (note.inner.descsz == 0) {
            return null;
        }
        try self.file.seekTo(note.offset + note.inner.namesz);
        var buf = try self.allocator.alloc(u8, note.inner.descsz);
        if (try self.file.read(buf) < note.inner.descsz) {
            return error.InvalidNote;
        }
        return buf;
    }

    fn deinit(self: *const Self) void {
        self.program_headers.deinit();
        self.section_headers.deinit();
        self.symbol_table.deinit();
        self.dynsym_table.deinit();
        self.dynamic_info.deinit();

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

test "Elf finds sections by name" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    try testing.expect(elf.findSectionByName(".got") != null);
    try testing.expect(elf.findSectionByName("my fun section") == null);

    elf.deinit();
}

test "Elf finds relocation structures" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    const section = elf.findSectionByName(".rela.dyn").?;
    const rela = try elf.getRelStructuresAddend(section);

    try testing.expectEqual(rela[0].offset, 0x403ff0);

    elf.allocator.free(rela);

    elf.deinit();
}

test "Elf finds dynamic info" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    // Readelf says this is 20, but it seems like it's actually 25 but the
    // last few sections are null.
    try testing.expectEqual(elf.dynamic_info.items.len, 25);
    try testing.expectEqual(elf.dynamic_info.items[0].tag, .NEEDED);
    try testing.expectEqual(elf.dynamic_info.items[1].tag, .INIT);
    try testing.expectEqual(elf.dynamic_info.items[2].tag, .FINI);

    // Last ones should all be null
    try testing.expectEqual(elf.dynamic_info.items[19].tag, .NULL);
    try testing.expectEqual(elf.dynamic_info.items[20].tag, .NULL);
    try testing.expectEqual(elf.dynamic_info.items[21].tag, .NULL);
    try testing.expectEqual(elf.dynamic_info.items[22].tag, .NULL);
    try testing.expectEqual(elf.dynamic_info.items[23].tag, .NULL);
    try testing.expectEqual(elf.dynamic_info.items[24].tag, .NULL);

    try testing.expectEqual(elf.dynamic_info.items[0].unionSelection(), .VAL);
    try testing.expectEqual(elf.dynamic_info.items[1].unionSelection(), .PTR);

    elf.deinit();
}

test "Elf finds notes" {
    const file = try std.fs.cwd().openFile("test/elf64-min.out", .{ .mode = .read_only });
    const elf = try Elf.init(file, std.testing.allocator);

    const section = elf.findSectionByName(".note.ABI-tag").?;
    const section_notes = try elf.getNotes(section);

    const name = try elf.nameOfNote(section_notes.items[0]);
    // Use starts with because the slice is null terminated
    try testing.expectStringStartsWith(name.?, "GNU");
    const desc = try elf.descriptionOfNote(section_notes.items[0]);
    // Description isn't really useful for us since it's the GNU ABI tag, just
    // make sure its length is 16.
    try testing.expectEqual(desc.?.len, 16);

    std.testing.allocator.free(name.?);
    std.testing.allocator.free(desc.?);
    section_notes.deinit();

    elf.deinit();
}
