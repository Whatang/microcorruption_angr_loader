import angr
from construct import (
    Byte,
    Const,
    Validator,
    Select,
    GreedyRange,
    NullTerminated,
    StringEncoded,
    GreedyBytes,
    Struct,
    Optional,
    FocusedSeq,
    Check,
    len_,
    this,
    Computed,
    Adapter,
    ListContainer,
)
from angr_platforms.msp430 import arch_msp430, lift_msp430, simos_msp430

MC_Address = Byte[4]
MC_Address_Padding = Const(b":   ")
MC_ByteVal = Byte[2]


class IsHexValidator(Validator):

    chars = set(b"abcdefABCDEF0123456789")

    def _validate(self, obj, context, path):
        return all(o in self.chars for o in obj)


MC_HexAddress = IsHexValidator(MC_Address)
MC_HexByteVal = IsHexValidator(MC_ByteVal)


class BigEndHexAdapter(Adapter):
    def _decode(self, obj, context, path):
        return int("".join(chr(x) for x in obj), 16)

    def _encode(self, obj, context, path):
        return ("%02x" % obj).encode("ascii")


MC_BigEndAddress = BigEndHexAdapter(MC_HexAddress)
MC_BigEndByte = BigEndHexAdapter(MC_HexByteVal)

NewLine = Select(Const(b"\x0d\x0a"), Const(b"\x0a"))
Spaces = GreedyRange(Const(b" "))

TerminatedString = lambda term, encoding="utf8": StringEncoded(
    NullTerminated(GreedyBytes, term=bytes(term, encoding)), encoding
)
TerminatedStringOrEOF = lambda term, encoding="utf8": StringEncoded(
    NullTerminated(GreedyBytes, term=bytes(term, encoding), require=False), encoding
)


class RemoveWindowsNewLine(Adapter):
    def _decode(self, obj, ctx, path):
        if len(obj) > 0 and obj[-1] == "\r":
            obj = obj[:-1]
        return obj

    def _encode(self, obj, ctx, path):
        return obj


LinuxNewLineTerminatedString = lambda encoding="utf8": TerminatedString("\n", encoding)
LinuxNewLineTerminatedStringOrEOF = lambda encoding="utf8": TerminatedStringOrEOF(
    "\n", encoding
)
NewLineTerminatedString = lambda encoding="utf8": RemoveWindowsNewLine(
    LinuxNewLineTerminatedString(encoding)
)
NewLineTerminatedStringOrEOF = lambda encoding="utf8": RemoveWindowsNewLine(
    LinuxNewLineTerminatedStringOrEOF(encoding)
)


MC_BytePair = Struct("b1" / MC_BigEndByte, "b2" / Optional(MC_BigEndByte), Const(b" "))


class FlattenByteList(Adapter):
    @staticmethod
    def _mc_get_byte_pair_as_list(obj):
        result = []
        result.append(obj.b1)
        if obj.b2 is not None:
            result.append(obj.b2)
        return result

    def _decode(self, obj, context, path):
        result = ListContainer()
        for o in obj:
            result.extend(self._mc_get_byte_pair_as_list(o))
        return result

    def _encode(self, obj, context, path):
        raise NotImplementedError()


MC_ByteList = FlattenByteList(GreedyRange(MC_BytePair + Spaces))

MC_ByteList.parse(b"3140 4830 1542 5c01 75f3 35d0 085a 3f40   ")

MC_Dump_Line = Struct(
    "address" / MC_BigEndAddress,
    MC_Address_Padding,
    "bytevals" / MC_ByteList,
    Check(len_(this.bytevals) > 0),
    Check(len_(this.bytevals) <= 16),
    NewLineTerminatedStringOrEOF(),
)


MC_Section_End = Struct(
    "address" / MC_BigEndAddress, MC_Address_Padding, Const(b"*"), Spaces, NewLine
)

MC_Section = Struct(
    "lines" / GreedyRange(MC_Dump_Line),
    Check(len_(this.lines) > 0),
    Optional(MC_Section_End),
    "address" / Computed(this.lines[0].address),
    "length"
    / Computed(
        this.lines[-1].address - this.lines[0].address + len_(this.lines[-1].bytevals)
    ),
)


MC_Dump = Struct("sections" / GreedyRange(MC_Section))


class MC_Loader(angr.cle.backends.Backend):
    def __init__(self, path, *args, **kwargs):
        parsed = MC_Dump.parse_file(path)
        super(MC_Loader, self).__init__(
            path, arch="msp430", entry_point=0x4400, *args, **kwargs
        )
        # Set this so that there's enough space for the extern_object.
        # Since the memory dump fills up the 16-bit entire memory space,
        # there is nowhere left for the extern_object to go. Making the
        # architecture pretend to be 32 bits for a while makes it work.
        # This feels really hacky, and it may well break something subtle
        # elsewhere.
        self.arch.bits = 32

        self._max_addr = 0xFFFF
        self._min_addr = 0x0
        self.memory.add_backer(0, b"\x00" * 0x10000)
        for section in parsed.sections:
            print(
                "Loading data with 0x%0x bytes at address 0x%04x"
                % (section.length, section.address)
            )
            self.memory.store(section.address, self._make_section(section))
        # This is the return from the interrupt: might be more nicely done with
        # a syscall or hook? It doesn't show up in the memory dump, so we add it
        # in manually here.
        self.memory.store(0x10, b"\x30\x41")

    def make_symbols(self, disassembly_path):
        print("parsing")
        parsed = MC_Disassembly_Parser.parse_file(disassembly_path)
        for sym_location in parsed.symbols:
            self._make_symbol(sym_location.address, sym_location.symbol)

    def _make_symbol(self, address, name):
        if name in self._symbol_cache:
            return
        print(f"Making {name} at {address:x}")
        new_sym = angr.cle.backends.symbol.Symbol(
            owner=self,
            name=name,
            relative_addr=address,
            size=2,
            sym_type=angr.cle.backends.symbol.SymbolType.TYPE_FUNCTION,
        )
        self._symbol_cache[name] = new_sym

    def get_symbol(self, name):
        return self._symbol_cache.get(name, None)

    @staticmethod
    def _make_section(section):
        bytevals = b""
        for line in section.lines:
            bytevals += bytes(line.bytevals)
        return bytevals

    @property
    def max_addr(self):
        return self._max_addr

    @property
    def min_addr(self):
        return self._min_addr

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        parsed = MC_Dump.parse_stream(stream)
        stream.seek(0)
        return len(parsed.sections) > 0


angr.cle.register_backend("microcorruption", MC_Loader)


def mc_project(path, disassembly_path=None, hook_standard=True, *args, **kwargs):
    """Load and return a microcorruption angr project.
    
    Arguments:
        path {Str} -- Path to the microcorruption memory dump file.
    
    Keyword Arguments:
        disassembly_path {Str} -- If given, path to the disassembly file for hooking symbols. (default: {None})
    
    Returns:
        angr.Project -- A loaded project.
    """
    proj = angr.Project(path, *args, main_opts={"backend": "microcorruption"}, **kwargs)
    proj.loader.main_object.arch.bits = 16
    if disassembly_path is not None:
        if hook_standard:
            hook_mc_symbols(disassembly_path, proj)
        else:
            parse_symbols(proj, disassembly_path)
    return proj


_simprocs = {
    "puts": simos_msp430.MCputs,
    "getsn": simos_msp430.MCgetsn,
    "__stop_progExec__": simos_msp430.MCstopexec,
}

MC_Symbol = Select(
    FocusedSeq("name", Const(b"<"), "name" / TerminatedString(">")),
    FocusedSeq("name", Const(b"."), "name" / TerminatedString(":")),
)

MC_Symbol_Line = Struct(
    "address" / MC_BigEndAddress,
    Spaces,
    "symbol" / MC_Symbol,
    NewLineTerminatedStringOrEOF(),
)
MC_Instruction = FocusedSeq(
    "i",
    "i" / GreedyRange(FocusedSeq("x", "x" / MC_BigEndAddress, Const(b" "))),
    Check(lambda ctx: (len(ctx.i) > 0 and len(ctx.i) < 4)),
)
MC_Instruction_Line = Struct(
    "address" / MC_BigEndAddress,
    Const(b":"),
    Spaces,
    "disassembly"
    / Struct(
        "instruction_bytes" / MC_Instruction,
        Spaces,
        "disassembly" / NewLineTerminatedStringOrEOF(),
    ),
)
MC_String_Line = Struct(
    "address" / MC_BigEndAddress,
    Const(b":"),
    Spaces,
    Const(b'"'),
    "string" / TerminatedString('"'),
    NewLineTerminatedStringOrEOF(),
)
MC_Bad_Line = "badline" / NewLineTerminatedString()
MC_Disassembly_Line = Select(
    MC_Symbol_Line, MC_Instruction_Line, MC_String_Line, MC_Bad_Line
)
MC_Disassembly_Parser = Struct(
    "lines" / GreedyRange(MC_Disassembly_Line),
    "symbols" / Computed(lambda ctx: [l for l in ctx.lines if hasattr(l, "symbol")]),
    "disassembly"
    / Computed(lambda ctx: [l for l in ctx.lines if hasattr(l, "disassembly")]),
    "strings" / Computed(lambda ctx: [l for l in ctx.lines if hasattr(l, "string")]),
)


def parse_symbols(proj, disassembly_path):
    proj.loader.main_object.make_symbols(disassembly_path)


def get_default_hooks():
    """Get the default hooking map of symbols to hook implementations.
    
    This is the default mapping of symbol strings to SimProcedure sub-classes
    which will be hooked by hook_mc_symbols. If you want to use different
    hooks, modify what this function returns then pass it to hook_mc_symbols.
    
    Returns:
        Dictionary -- Maps strings to SimProcedure implementations.
    """
    return _simprocs.copy()


def hook_mc_symbols(disassembly_path, angr_project, simprocs=None):
    parse_symbols(angr_project, disassembly_path)
    if simprocs is None:
        simprocs = _simprocs
    for sym_name in simprocs.keys():
        print(f"Hooking {sym_name} with {simprocs[sym_name]}")
        angr_project.hook_symbol(sym_name, simprocs[sym_name]())

