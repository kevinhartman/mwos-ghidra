# Microware OS9 Ghidra Extensions
This repo contains Ghidra loaders and analyzers for working with Microware OS9 memory modules.

Currently, only MIPS program and driver modules are supported.

## Analyzer
- Since OS9 uses a shared memory map (no virtual addresses), all code and data references are accessed via offsets from two CPU registers initialized by the OS: the CP and GP registers, respectively. For MIPS variants, Ghidra supports data references calculated / accessed through the GP ($31), but does not support code references via the CP ($30). The analyzer included in this repo adds support for this. This functionality is added directly to the built-in MIPS Constant Reference Analyzer (option `(Microware OS9) Assume CP value`). Note that you may need to run this analysis multiple times consecutively to discover all functions.

## Loader
- The program module loader can load OS9 program modules and also fixes data references / performs proper relocations.
- The driver loader works, but doesn't seem to provide a very nice decompilation. There's probably a few things I'm missing regarding how the official linker lays these out / some assumptions we could make to improve the disassembly. Currently, if the driver is for an SBF device, you'll get SBF entry points added to the disassembly if you provide the path to a device descriptor for the device in the loader's options.
