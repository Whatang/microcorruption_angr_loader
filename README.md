# Microcorruption backend for angr

An [angr](https://angr.io) backend for live memory dumps from the [microcorruption CTF](https://microcorruption.com/). It loads a project for the MSP430 implementation in [angr-platforms](https://github.com/angr/angr-platforms).

## Installation

```bash
pip install git+https://github.com/Whatang/microcorruption_angr_loader.git
```

## Usage

You need to copy the contents of a challenge's live memory dump window into a file, e.g. "memory_dump.txt".

```python
import microcorruption_loader
proj = microcorruption_loader.mc_project("memory_dump.txt")
```

This creates an `angr.Project` ready for you to analyze. You should create it this way rather than using the microcorruption backend directly because we need to wrap some hacking around the project creation to make it work. See "Implementation Details" below if you're interested.

### Symbol hooking

Once you have loaded the memory dump into your angr project, you may want to hook the `getsn`, `puts`, and `__stop_progExec__` functions used by many of the challenges. To do this you need to copy the contents of the Disassembly window from the microcorruption site into a file, which can then be parsed to find symbols.

The symbol parsing and hooking can be done in 2 ways.

1. Hook them into an existing project:

   ```python
   microcorruption_loader.hook_mc_symbols("disassembly.txt", proj)
   ```

2. Do it all at the time of loading the project:

   ```python
   proj = microcorruption_loader.mc_project("memory_dump.txt", "disassembly.txt")
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
   proj = microcorruption_loader.mc_project("memory_dump.txt", "disassembly.txt"
                                            hook_standard=False)
   ```

## Implementation Details

There are 2 main things to discuss here: the parsing of the two files, and the reason for wrapping the creation of the angr Project object.

### Parsing

**TODO**: write this up.

### Project creation

**TODO**: write this up.
