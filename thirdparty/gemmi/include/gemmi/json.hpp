// Copyright 2017 Global Phasing Ltd.

/// @file
/// @brief Reading JSON formats (mmJSON and CIF-JSON) into CIF documents.

#ifndef GEMMI_JSON_HPP_
#define GEMMI_JSON_HPP_

#include <utility>      // for forward
#include "cifdoc.hpp"   // for Document, etc
#include "fileutil.hpp" // for read_file_into_buffer

namespace gemmi {
namespace cif {

/// Parse mmJSON format from a buffer (with in-place mutation).
///
/// mmJSON is the macromolecular JSON format used by PDBj for structure data.
/// This function parses JSON in-place, modifying the input buffer as a side effect
/// for efficiency. If you need to preserve the original buffer, make a copy first.
///
/// @param buffer Pointer to buffer containing mmJSON data (will be modified)
/// @param size   Number of bytes in the buffer
/// @param name   Optional source name for error messages (default: "mmJSON")
/// @return Parsed CIF document
GEMMI_DLL Document read_mmjson_insitu(char* buffer, std::size_t size,
                                      const std::string& name="mmJSON");

/// Read and parse an mmJSON file from disk.
///
/// Convenience function that loads the file into memory and parses it.
/// The entire file is read into a buffer for parsing.
///
/// @param path Path to the mmJSON file (may end with .gz for gzip compression)
/// @return Parsed CIF document
inline Document read_mmjson_file(const std::string& path) {
  CharArray buffer = read_file_into_buffer(path);
  return read_mmjson_insitu(buffer.data(), buffer.size(), path);
}

/// Read and parse mmJSON from an input source (file or stream).
///
/// Template function supporting both file paths and stream inputs.
/// Reads data from the input source into a buffer, then parses.
///
/// @tparam T An input type with is_stdin() and path() methods
/// @param input The input source to read from
/// @return Parsed CIF document
template<typename T>
Document read_mmjson(T&& input) {
  std::string name = input.is_stdin() ? "stdin" : input.path();
  CharArray buffer = read_into_buffer(std::forward<T>(input));
  return read_mmjson_insitu(buffer.data(), buffer.size(), name);
}

} // namespace cif
} // namespace gemmi
#endif
