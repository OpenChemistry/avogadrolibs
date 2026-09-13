/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_BENCHMARK_COMMON_H
#define AVOGADRO_BENCHMARK_COMMON_H

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace Avogadro::Benchmarks {

namespace fs = std::filesystem;

inline bool parseUnsigned(const std::string& text, std::size_t& value)
{
  try {
    std::size_t consumed = 0;
    const auto parsed = std::stoull(text, &consumed);
    if (consumed != text.size())
      return false;
    value = static_cast<std::size_t>(parsed);
    return true;
  } catch (...) {
    return false;
  }
}

inline bool parseDouble(const std::string& text, double& value)
{
  try {
    std::size_t consumed = 0;
    const double parsed = std::stod(text, &consumed);
    if (consumed != text.size())
      return false;
    value = parsed;
    return true;
  } catch (...) {
    return false;
  }
}

inline fs::path resolvePath(const std::string& dataRoot,
                            const std::string& file)
{
  const fs::path p(file);
  return p.is_absolute() ? p : fs::path(dataRoot) / p;
}

inline bool isPdbFile(const fs::path& path)
{
  std::string ext = path.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return ext == ".pdb" || ext == ".ent";
}

// Drop CONECT records and collapse alt-loc 'A' onto blank. The bundled PDB
// reader does not handle alt-loc atom doubling; without this shim residues
// with multiple conformations get duplicated atoms that wreck the optimizer.
inline std::string sanitizePdbInput(const std::string& input)
{
  std::istringstream stream(input);
  std::ostringstream cleaned;
  std::string line;
  while (std::getline(stream, line)) {
    if (line.rfind("CONECT", 0) == 0)
      continue;

    if ((line.rfind("ATOM", 0) == 0 || line.rfind("HETATM", 0) == 0) &&
        line.size() > 16) {
      const char altLoc = line[16];
      if (altLoc != ' ' && altLoc != 'A')
        continue;
      if (altLoc == 'A')
        line[16] = ' ';
    }

    cleaned << line << '\n';
  }
  return cleaned.str();
}

inline bool readMoleculeFromPath(const fs::path& moleculePath,
                                 Core::Molecule& molecule)
{
  auto& manager = Io::FileFormatManager::instance();
  if (!isPdbFile(moleculePath))
    return manager.readFile(molecule, moleculePath.string());

  std::ifstream file(moleculePath, std::ios::in);
  if (!file)
    return false;

  std::ostringstream buffer;
  buffer << file.rdbuf();
  const std::string sanitized = sanitizePdbInput(buffer.str());
  if (sanitized.empty())
    return false;

  if (manager.readString(molecule, sanitized, "pdb"))
    return true;

  return manager.readFile(molecule, moleculePath.string());
}

} // namespace Avogadro::Benchmarks

#endif // AVOGADRO_BENCHMARK_COMMON_H
