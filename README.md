# Microcorruption backend for angr

An [angr](https://angr.io) backend for memory dumps and disassembly from the [microcorruption CTF](https://microcorruption.com/). It creates an angr project for the MSP430 implementation in [angr-platforms](https://github.com/angr/angr-platforms).

## Installation

```bash
pip install git+https://github.com/Whatang/microcorruption_angr_loader.git
```

Or, if you've cloned this repo locally, you can do:

```bash
pip install .
```

If you need/want to develop this module while using it, install an editable version:

```bash
pip install -e .
```

## Usage

You need to copy the contents of a challenge's live memory dump window into a file, e.g. `memory_dump.txt`. This file should contain the unchanged copied & pasted text from the memory dump window on the microcorruption website.

```python
import microcorruption_loader
proj = microcorruption_loader.mc_project("memory_dump.txt")
```

This creates an `angr.Project` object ready for you to analyze. You should create it this way rather than using the microcorruption backend directly because we need to wrap a hack around the project creation to make it work. See [Implementation Details](#implementation-details) below if you're interested.

### Symbol hooking

Once you have loaded the memory dump into your angr project, you may want to hook the `getsn`, `puts`, and `__stop_progExec__` functions used by many of the challenges. To do this you need to copy the contents of the Disassembly window from the microcorruption site into a file, which can then be parsed to find symbols.

The symbol parsing and hooking can be done in 2 ways.

1. Hook them into an existing project:

   ```python
   microcorruption_loader.hook_mc_symbols("disassembly.txt", proj)
   ```

2. Do it all at the time of loading the project:

   ```python
   proj = microcorruption_loader.mc_project("memory_dump.txt",
                                            "disassembly.txt")
   ```

Note that **all** symbols in the disassembly are parsed out and added to the loader, not just those which are hooked.

### Symbol parsing

To **just** parse out the symbols from the disassembly without hooking with the standard hooks, you can do either of the following:

1. Parse the disassembly and create symbols for an existing project:

   ```python
   microcorruption_loader.parse_symbols("disassembly.txt", proj)
   ```

2. Parse the symbols when loading the project, and explicitly don't hook the standard functions:

   ```python
   proj = microcorruption_loader.mc_project("memory_dump.txt", 
                                            "disassembly.txt",
                                            hook_standard=False)
P   ```

## Implementation Details

There are 2 main things to discuss here: the parsing of the two files, and the reason for wrapping the creation of the angr Project object.

### Parsing

[Construct](https://construct.readthedocs.io/) is used to build parsers for both the memory dump and disassembly view.

For the memory dump, each line is parsed to retrieve the bytes indicated and the address that they are at. These lines are consolidated into "sections", which are stored into memory by the backend.

Parsing the disassembly view is more complicated. Each line can be either a symbol, a disassembled instruction, or string data. There's also the possibility that there's a line which can't be parsed as any of those, so we allow for that too. The parser just works out which of the line types is which and parses accordingly, then creates lists of symbols, dissassembly lines, and strings. The symbols are loaded into the project along with their address - nothing is done with the other lines at present, but they're there if you wanted to use them yourself.

### Project creation

There's a hack in the creation of the project. The MSP430 is a 16-bit platform, so the addresses avaiable run from 0x0 to 0xFFFF. All these addresses are used/assigned in the creation of the `angr` project: every byte is initially set to zero, then values are assigned from the parsed memory dump.

However, angr itself needs some storage in the address space to keep track of symbols and various other things. I confess I don't really understand why this has to be tracked in the project's address space, but it seems to be the case. Unfortunately if the entire address space is full then angr can't find anywhere to store its bookkeeping information. I asssume this isn't really a problem on 32-bit platforms since there's usually plenty of unused memory available, but our loader already uses the entire address space. Therefore angr errors when we try to load a project, because it can't assign anywhere in memory for its "external" object.

This is where the hack comes in. At the time of memory creation, we tell angr that the architecture is 32-bits. This lets angr find some available memory at 0x10000, which is of course outside the "real" address space. Then, once angr has successfully loaded everything up, we change the architecture size back to 16-bits.

Since this is such a nasty hack, it's entirely possible that something unpleasant/unforeseen will happen, but it seems to have been working OK so far.

An alternative approach would be to only add backed memory for the known "sections" parsed from the memory dump file. The problem with that is that some of the challenges write to memory which is not obviously allocated at startup. This would cause two issues: firstly, we'd risk angr using some memory which was later addressed by the target program itself. Secondly, even if that didn't happen, the program would error when it tried to read/write the unknown memory since we wouldn't have told angr about it.

This could possibly be mitigated by adding a facility to reserve certain memory sections, but the existing solution is easier for the time being. However, if the option `explicit_sections=True` is passed to the `mc_project` function then this technique is used: memory is only created and assigned for those bytes which are explicitly specified in the memory dump, and the "temporarily 32-bit architecture" hack is not used. One way of using this is to run the challenge binary in the microcorruption debugger up to a point where (you hope) all memory that is going to be used is now assigned and listed in the memory view. You can then copy and paste the live contents of the memory window as your memory dump, and let angr find somewhere in the remaining memory to put its stuff.
