/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "genericoutput.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/io/xyzformat.h>

#include "gamessus.h"
#include "molden.h"
#include "nwchemlog.h"
#include "orca.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace Avogadro::QuantumIO {

namespace {

using Io::FileFormat;

bool startsWith(const std::string& text, const std::string& prefix)
{
  return text.size() >= prefix.size() &&
         text.compare(0, prefix.size(), prefix) == 0;
}

/**
 * The lower-cased extension of @a fileName, without the dot, or an empty
 * string if there is none. Delegates are looked up by extension, and ".log"
 * and ".out" do not map to the same set of formats, so the real extension
 * matters. Windows users routinely have ".LOG" and ".OUT" files, and the
 * format map is keyed on lower case.
 */
std::string lowerExtension(const std::string& fileName)
{
  // Only a dot in the last path component names an extension. Searching the
  // whole path would read "C:\work.v1\gaussian-output" as the extension
  // "v1\gaussian-output"; both separators are checked because a Windows path
  // can use either.
  const std::string::size_type separator = fileName.find_last_of("/\\");
  const std::string::size_type start =
    (separator == std::string::npos) ? 0 : separator + 1;

  const std::string::size_type dot = fileName.find_last_of('.');
  if (dot == std::string::npos || dot < start || dot + 1 >= fileName.size())
    return std::string();

  std::string extension = fileName.substr(dot + 1);
  std::transform(extension.begin(), extension.end(), extension.begin(),
                 [](unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return extension;
}

} // namespace

GenericOutput::GenericOutput() {}

GenericOutput::~GenericOutput() {}

std::string GenericOutput::identifier() const
{
  const std::lock_guard<std::mutex> lock(m_identifierMutex);
  return m_identifier;
}

std::vector<std::string> GenericOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("out");
  extensions.emplace_back("output");
  extensions.emplace_back("log");
  return extensions;
}

std::vector<std::string> GenericOutput::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GenericOutput::read(std::istream& in, Core::Molecule& molecule)
{
  // check the stream line-by-line until we see the program name
  FileFormat* reader = nullptr;
  // How the reader was chosen, so the error message can say what actually ran.
  std::string detected;

  std::string line;
  while (std::getline(in, line)) {
    if (line.find("Northwest Computational Chemistry Package") !=
        std::string::npos) {
      // NWChem
      reader = new NWChemLog;
      detected = "NWChem";
      break;
    } else if (line.find("GAMESS VERSION") != std::string::npos) {
      // GAMESS-US .. don't know if we can read Firefly or GAMESS-UK
      reader = new GAMESSUSOutput;
      detected = "GAMESS-US";
      break;
    } else if (line.find("[Molden Format]") != std::string::npos) {
      // molden with .out extension
      reader = new MoldenFile;
      detected = "Molden";
      break;
    } else if (line.find("O   R   C   A") != std::string::npos) {
      // ORCA reader
      reader = new ORCAOutput;
      detected = "ORCA";
      break;
    } else if (line.find("xtb:") != std::string::npos) {
      // xtb reader
      reader = new Io::XyzFormat;
      detected = "xtb";
      break;
    }
  }

  // Look the fallbacks up under the extension actually being read: the
  // sniffing above has already failed, so the delegate is chosen purely by
  // extension, and Gaussian ".log" files are not registered under "out".
  std::string extension = lowerExtension(fileName());
  if (extension.empty())
    extension = "out";

  // if we didn't find a program name, check for cclib or OpenBabel
  std::vector<const FileFormat*> candidates;
  if (reader == nullptr) {
    // check what output is available
    candidates = Io::FileFormatManager::instance().fileFormatsFromFileExtension(
      extension, FileFormat::File | FileFormat::Read);

    // cclib recognizes more programs than the Open Babel readers do, so give
    // it first refusal. Two passes, rather than one loop that stops at either:
    // a single pass takes whichever happened to be registered first, which is
    // Open Babel as often as not.
    for (const FileFormat* candidate : candidates) {
      if (candidate->name() == "cclib") { // avogadro-cclib plugin
        reader = candidate->newInstance();
        detected = "cclib plugin";
        break;
      }
    }

    if (reader == nullptr) {
      // Open Babel's own "Generic Output file format" sniffs the file the
      // same way this reader does and covers Gaussian, Q-Chem, MOPAC, PWSCF
      // and more. Every other Open Babel format registered for this extension
      // is tied to one program, so picking one of those at random hands the
      // file to the wrong parser. Matched loosely, since the identifier is
      // built from whatever description the installed obabel prints.
      for (const FileFormat* candidate : candidates) {
        const std::string candidateIdentifier = candidate->identifier();
        if (startsWith(candidateIdentifier, "OpenBabel") &&
            candidateIdentifier.find("Generic Output") != std::string::npos) {
          reader = candidate->newInstance();
          detected = "Open Babel";
          break;
        }
      }
    }

    if (reader == nullptr) {
      for (const FileFormat* candidate : candidates) {
        if (startsWith(candidate->identifier(), "OpenBabel")) {
          reader = candidate->newInstance();
          detected = "Open Babel";
          break;
        }
      }
    }
  }

  // Reset every time to be sure we don't return the *last* identifier.
  // Work out the new value before taking the lock and take it exactly once:
  // m_identifierMutex is not recursive, so locking it a second time here
  // deadlocks this thread, and identifier() then blocks every caller too.
  std::string identifier("Avogadro: Generic Output");
  if (reader != nullptr)
    identifier = reader->identifier();

  {
    const std::lock_guard<std::mutex> lock(m_identifierMutex);
    m_identifier = identifier;
  }

  // rewind the stream
  in.seekg(0, std::ios::beg);
  in.clear();

  if (reader == nullptr) {
    std::ostringstream error;
    error << "Could not determine the program used to generate this output "
             "file.\n"
          << "No fallback reader is registered for \"." << extension
          << "\" files: neither the cclib plugin nor an Open Babel format "
             "was found.\n"
          << "Install the cclib plugin, or check that Open Babel is available, "
             "then reopen the file.";
    appendError(error.str());
    return false;
  }

  // Every delegate reads from the file rather than the stream, so a stream or
  // string read has nothing to hand it. Say so instead of failing silently in
  // FileFormat::open().
  if (fileName().empty()) {
    appendError("Detected " + detected + " (" + identifier +
                "), but that reader needs a file path and this output was "
                "read from a stream.");
    delete reader;
    return false;
  }

  const bool success = reader->readFile(fileName(), molecule);
  if (!success) {
    std::ostringstream error;
    error << "Detected " << detected << ", but reading \"" << fileName()
          << "\" with \"" << identifier << "\" failed.";
    appendError(error.str());

    // Whatever the delegate itself has to say is the most specific
    // information available - pass it through rather than dropping it.
    const std::string readerError = reader->error();
    if (!readerError.empty())
      appendError(readerError, false);
    else
      appendError("The reader did not report a reason.", false);
  }

  delete reader;
  return success;
}

} // namespace Avogadro::QuantumIO
