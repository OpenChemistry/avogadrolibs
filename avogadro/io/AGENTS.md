# avogadro/io

Readers and writers for structure and trajectory formats (CJSON, CML, PDB,
SDF/MDL, XYZ, VASP, LAMMPS, GROMACS, DCD, TRR, Turbomole, SMILES, ...), the
`FileFormat` base class, `FileFormatManager`, and compressed-stream support.
Quantum chemistry program output belongs in `quantumio` instead.

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere.

## Why it is separate

`IO` depends only on `Core`, so formats work from the Python package and the
command-line converters as well as the GUI. libarchive, HDF5 and MMTF are
optional (`USE_LIBARCHIVE`, `USE_HDF5`, `USE_MMTF`) and are off in the Python
wheel build; code that uses them must be guarded.

## Every file is untrusted input

Readers get files from users, downloads and other programs, and are fuzzed
nightly in CI. A reader must never crash, hang or allocate without limit on
bad input.

- Check every count, size and index read from a file before using it to
  index, loop or allocate: against `atomCount()`, against what was already
  read, and against what is left in the stream.
- On failure, call `appendError()` with a message a user can act on (which
  line, what was expected) and return `false`.
- The `FileFormat` entry points (`readMolecule()`, `readString()` and their
  write counterparts) catch exceptions thrown by the standard library or
  nlohmann JSON, but that is only a safety net, and fuzz builds turn it off on
  purpose. An exception escaping a reader is a bug.
- Parse numbers with `Core::lexicalCast<double>` (locale-independent), not
  `stream >> double`, `std::stod` or `strtod`. Loop over lines with
  `Core::getLine`. Expect CRLF line endings and trailing whitespace.
- Store coordinates in Ångström. Convert from Bohr or fractional coordinates
  when reading, using the constants in `core/avogadrocore.h` and `UnitCell`.

## Adding a format

1. Subclass `FileFormat` and implement `read()`/`write()`,
   `supportedOperations()`, `newInstance()`, `identifier()`, `name()`,
   `description()`, `specificationUrl()`, `fileExtensions()` and `mimeTypes()`.
   Return only the operations you really support (read-only and write-only
   formats are fine).
2. Override `contentPatterns()` if the format shares a generic extension such
   as `.out` or `.log`.
3. Register it in the `FileFormatManager` constructor
   ([fileformatmanager.cpp](fileformatmanager.cpp)).
4. Add a test in `tests/io/` that reads a sample file from avogadrodata and,
   if the format can be written, round-trips it.
5. Add the extension to the `fuzz` list in
   [tests/io/CMakeLists.txt](../../tests/io/CMakeLists.txt).

Per-call options arrive as a JSON string in `options()`; read them with
`boolOption()`, `stringOption()` and the other helpers in `FileFormat` rather
than parsing the string yourself.
