/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <cstdio>
#include <cstdlib>
#include <memory>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

namespace {

// FUZZ_INPUT_FORMAT is a file extension, and readString() simply returns false
// when no registered format claims it for reading -- so a typo, or a format
// that turns out to be write-only, produces a target that runs happily and
// tests nothing. "qcschema" did exactly that for a while (the extension is
// "qcjson"). Fail loudly instead.
bool checkFormatIsReadable()
{
  // newFormatFromFileExtension() hands back an owned instance, and this job
  // fuzzes with detect_leaks=1, so take ownership of it.
  const std::unique_ptr<FileFormat> format(
    FileFormatManager::instance().newFormatFromFileExtension(
      FUZZ_INPUT_FORMAT, FileFormat::Read | FileFormat::String));
  if (format == nullptr) {
    std::fprintf(stderr,
                 "no registered format reads strings with extension '%s' -- "
                 "this fuzz target would test nothing\n",
                 FUZZ_INPUT_FORMAT);
    std::abort();
  }
  return true;
}

} // namespace

// FUZZ_INPUT_FORMAT is defined in the build system
// e.g., "cjson", "sdf", "xyz", etc.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  static const bool readable = checkFormatIsReadable();
  (void)readable;

  std::string input(reinterpret_cast<const char*>(Data), Size);

  Molecule molecule;
  FileFormatManager::instance().readString(molecule, input, FUZZ_INPUT_FORMAT);

  return 0;
}
