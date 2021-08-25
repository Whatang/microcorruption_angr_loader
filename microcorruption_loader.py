import angr
import cle
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
from angr_platforms.msp430 import lift_msp430, simos_msp430

_MC_Address = Byte[4]
_MC_ByteVal = Byte[2]


class _IsHexValidator(Validator):

    chars = set(b"abcdefABCDEF0123456789")

    def _validate(self, obj, context, path):
        return all(o in self.chars for o in obj)


_MC_HexAddress = _IsHexValidator(_MC_Address)
_MC_HexByteVal = _IsHexValidator(_MC_ByteVal)


class _BigEndHexAdapter(Adapter):
    def _decode(self, obj, context, path):
        return int("".join(chr(x) for x in obj), 16)

    def _encode(self, obj, context, path):
        return ("%02x" % obj).encode("ascii")


_MC_BigEndAddress = _BigEndHexAdapter(_MC_HexAddress)
_MC_BigEndByte = _BigEndHexAdapter(_MC_HexByteVal)

_NewLine = Select(Const(b"\x0d\x0a"), Const(b"\x0a"))
_Spaces = GreedyRange(Const(b" "))

TerminatedString = lambda term, encoding="utf8": StringEncoded(
    NullTerminated(GreedyBytes, term=bytes(term, encoding)), encoding
)
TerminatedStringOrEOF = lambda term, encoding="utf8": StringEncoded(
    NullTerminated(GreedyBytes, term=bytes(term, encoding), require=False), encoding
)


class _RemoveWindowsNewLine(Adapter):
    def _decode(self, obj, ctx, path):
        if len(obj) > 0 and obj[-1] == "\r":
            obj = obj[:-1]
        return obj

    def _encode(self, obj, ctx, path):
        return obj


_LinuxNewLineTerminatedString = lambda encoding="utf8": TerminatedString("\n", encoding)
_LinuxNewLineTerminatedStringOrEOF = lambda encoding="utf8": TerminatedStringOrEOF(
    "\n", encoding
)
NewLineTerminatedString = lambda encoding="utf8": _RemoveWindowsNewLine(
    _LinuxNewLineTerminatedString(encoding)
)
NewLineTerminatedStringOrEOF = lambda encoding="utf8": _RemoveWindowsNewLine(
    _LinuxNewLineTerminatedStringOrEOF(encoding)
)


_MC_BytePair = Struct(
    "b1" / _MC_BigEndByte, "b2" / Optional(_MC_BigEndByte), Const(b" ")
)


class _FlattenByteList(Adapter):
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


_MC_ByteList = _FlattenByteList(GreedyRange(_MC_BytePair + _Spaces))

_MC_Dump_Line = Struct(
    "address" / _MC_BigEndAddress,
    Const(b":"),
    _Spaces,
    "bytevals" / _MC_ByteList,
    Check(len_(this.bytevals) > 0),
    Check(len_(this.bytevals) <= 16),
    NewLineTerminatedStringOrEOF(),
)


_MC_Section_End = Struct(
    "address" / _MC_BigEndAddress, Const(b":"), _Spaces, Const(b"*"), _Spaces, _NewLine
)

_MC_Section = Struct(
    "lines" / GreedyRange(_MC_Dump_Line),
    Check(len_(this.lines) > 0),
    Optional(_MC_Section_End),
    "address" / Computed(this.lines[0].address),
    "length"
    / Computed(
        this.lines[-1].address - this.lines[0].address + len_(this.lines[-1].bytevals)
    ),
)


MC_Dump_Parser = Struct("sections" / GreedyRange(_MC_Section))


class MC_Loader(cle.Backend):
    def __init__(
        self,
        path,
        binary_stream,
        safe_area=-1,
        explicit_sections=False,
        *args,
        **kwargs,
    ):
        super(MC_Loader, self).__init__(
            path,
            binary_stream=binary_stream,
            arch="msp430",
            entry_point=0x4400,
            *args,
            **kwargs,
        )

        if not explicit_sections:
            self._load_from_initial_state(path, safe_area)
        else:
            self._load_explicit_sections(path)

    def _load_from_initial_state(self, path, safe_area):
        parsed = MC_Dump_Parser.parse_file(path)

        self.arch.bits = 32

        self._min_addr = 0x0
        self._max_addr = 0xFFFF
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

    def _load_explicit_sections(self, path):
        parsed = MC_Dump_Parser.parse_file(path)

        self.arch.bits = 16

        self._max_addr = 0xFFFF
        self._min_addr = 0x0
        for section in parsed.sections:
            print(
                "Loading data with 0x%0x bytes at address 0x%04x"
                % (section.length, section.address)
            )
            self.memory.add_backer(section.address, b"\x00" * section.length)
            self.memory.store(section.address, self._make_section(section))
        self.memory.add_backer(0x10, b"\x00" * 16)
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
        parsed = MC_Dump_Parser.parse_stream(stream)
        stream.seek(0)
        return len(parsed.sections) > 0


angr.cle.register_backend("microcorruption", MC_Loader)


def mc_project(
    path,
    disassembly_path=None,
    hook_standard=True,
    explicit_sections=False,
    safe_area=-1,
    *args,
    **kwargs,
):
    """Load and return a microcorruption angr project.

    Arguments:
        path {Str} -- Path to the microcorruption memory dump file.

    Keyword Arguments:
        disassembly_path {Str} -- If given, path to the disassembly file for hooking symbols. (default: {None})
        hook_standard {Bool} -- Hooks getsn, puts, and __stop_progExec__ with angr_platforms implementations if True. (default: {True})
        explicit_sections {Bool} -- If set to True, only create backed memory for the bytes that are explicitly specified in the memory dump. (default: {False})
        safe_area {int} - If given, an area of 0x200 bytes in memory which angr can safely use for bookkeeping. (default: {-1})

    Returns:
        angr.Project -- A loaded project.
    """
    # Create the project
    proj = angr.Project(
        path,
        *args,
        main_opts={
            "backend": "microcorruption",
            "explicit_sections": explicit_sections,
            "safe_area": safe_area,
        },
        load_options={"rebase_granularity": 8},
        **kwargs,
    )
    # Set the number of bits in the architecture back to 16: see the hack in
    # the MC_Loader __init__ function above.
    proj.loader.main_object.arch.bits = 16
    # If we have a path to a disassembly file, parse it and possibly do some
    # hooking.
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
    "strcpy": angr.SIM_PROCEDURES["libc"]["strcpy"],
    "memset": angr.SIM_PROCEDURES["libc"]["memset"],
}

_MC_Symbol = Select(
    FocusedSeq("name", Const(b"<"), "name" / TerminatedString(">")),
    FocusedSeq("name", Const(b"."), "name" / TerminatedString(":")),
)

_MC_Symbol_Line = Struct(
    "address" / _MC_BigEndAddress,
    _Spaces,
    "symbol" / _MC_Symbol,
    NewLineTerminatedStringOrEOF(),
)
_MC_Instruction = FocusedSeq(
    "i",
    "i" / GreedyRange(FocusedSeq("x", "x" / _MC_BigEndAddress, Const(b" "))),
    Check(lambda ctx: (len(ctx.i) > 0 and len(ctx.i) < 4)),
)
_MC_Instruction_Line = Struct(
    "address" / _MC_BigEndAddress,
    Const(b":"),
    _Spaces,
    "disassembly"
    / Struct(
        "instruction_bytes" / _MC_Instruction,
        _Spaces,
        "disassembly" / NewLineTerminatedStringOrEOF(),
    ),
)
_MC_String_Line = Struct(
    "address" / _MC_BigEndAddress,
    Const(b":"),
    _Spaces,
    Const(b'"'),
    "string" / TerminatedString('"'),
    NewLineTerminatedStringOrEOF(),
)
_MC_Bad_Line = "badline" / NewLineTerminatedString()
_MC_Disassembly_Line = Select(
    _MC_Symbol_Line, _MC_Instruction_Line, _MC_String_Line, _MC_Bad_Line
)
MC_Disassembly_Parser = Struct(
    "lines" / GreedyRange(_MC_Disassembly_Line),
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
        print(f"Hooking {sym_name} with {simprocs[sym_name]}: ", end="")
        success = angr_project.hook_symbol(sym_name, simprocs[sym_name]())
        print(f"{success}")

