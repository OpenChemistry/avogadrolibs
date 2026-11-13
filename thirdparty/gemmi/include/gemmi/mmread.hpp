/// @file
/// @brief Auto-detect and read any supported coordinate file format
///        (PDB, mmCIF, mmJSON, or chemical component).

// Copyright 2017 Global Phasing Ltd.
//
// Read any supported coordinate file. Usually, mmread_gz.hpp is preferred.

#ifndef GEMMI_MMREAD_HPP_
#define GEMMI_MMREAD_HPP_

#include "cif.hpp"       // for cif::read
#include "fail.hpp"      // for fail
#include "input.hpp"     // for BasicInput
#include "json.hpp"      // for read_mmjson
#include "mmcif.hpp"     // for make_structure_from_block, ...
#include "model.hpp"     // for Structure
#include "pdb.hpp"       // for read_pdb
#include "util.hpp"      // for iends_with

namespace gemmi {

/// Detect file format from filename extension.
/// @param path File path or name
/// @return Detected format (Pdb, Mmcif, Mmjson) or Unknown if no match
inline CoorFormat coor_format_from_ext(const std::string& path) {
  if (iends_with(path, ".pdb") || iends_with(path, ".ent"))
    return CoorFormat::Pdb;
  if (iends_with(path, ".cif") || iends_with(path, ".mmcif"))
    return CoorFormat::Mmcif;
  if (iends_with(path, ".json"))
    return CoorFormat::Mmjson;
  return CoorFormat::Unknown;
}

/// Detect file format by examining file content.
/// Heuristic detection based on content: looks for JSON '{', CIF 'data_',
/// or falls back to PDB format if neither is found.
/// @param buf   Pointer to buffer start
/// @param end   Pointer to buffer end
/// @return Detected format (Pdb, Mmcif, Mmjson) or Unknown if buffer too small
inline CoorFormat coor_format_from_content(const char* buf, const char* end) {
  while (buf < end - 8) {
    if (std::isspace(*buf)) {
      ++buf;
    } else if (*buf == '#') {
      while (buf < end - 8 && *buf != '\n')
        ++buf;
    } else if (*buf == '{') {
      return CoorFormat::Mmjson;
    } else if (ialpha4_id(buf) == ialpha4_id("data") && buf[4] == '_') {
      return CoorFormat::Mmcif;
    } else {
      return CoorFormat::Pdb;
    }
  }
  return CoorFormat::Unknown;
}

/// Build Structure from a CIF document, optionally detecting chemical components.
/// If possible_chemcomp is true, checks whether the document is a chemical
/// component file and parses it accordingly; otherwise treats as normal mmCIF.
/// @param doc                A CIF document; moved into this function
/// @param possible_chemcomp  If true, check for and handle CCD/monomer library files
/// @param save_doc           Optional pointer to receive the document; only populated if
///                           the input is mmCIF (not a chemical component)
/// @return A Structure parsed from the document
inline Structure make_structure_from_doc(cif::Document&& doc, bool possible_chemcomp,
                                         cif::Document* save_doc=nullptr) {
  if (possible_chemcomp) {
    // check for special case - refmac dictionary or CCD file
    int n = check_chemcomp_block_number(doc);
    if (n != -1)
      return make_structure_from_chemcomp_block(doc.blocks[n]);
  }
  return make_structure(std::move(doc), save_doc);
}

/// Read a Structure from a memory buffer.
/// Detects or uses specified format to parse the buffer.
/// Note: When reading JSON, the input buffer is modified in-place (optimization).
/// @param data      Pointer to file data; may be modified if JSON format
/// @param size      Size of data buffer in bytes
/// @param path      File path or name (used for error messages and format detection)
/// @param format    File format (Unknown = auto-detect, Detect = content-based detection)
/// @param save_doc  Optional pointer to receive the parsed CIF document
/// @return A Structure parsed from the buffer
/// @throws Throws on parse errors or if format cannot be determined
inline Structure read_structure_from_memory(char* data, size_t size,
                                            const std::string& path,
                                            CoorFormat format=CoorFormat::Unknown,
                                            cif::Document* save_doc=nullptr) {
  if (save_doc)
    save_doc->clear();
  if (format == CoorFormat::Unknown || format == CoorFormat::Detect)
    format = coor_format_from_content(data, data + size);
  if (format == CoorFormat::Pdb)
    return read_pdb_from_memory(data, size, path);
  if (format == CoorFormat::Mmcif)
    return make_structure_from_doc(cif::read_memory(data, size, path.c_str()),
                                   true, save_doc);
  if (format == CoorFormat::Mmjson)
    return make_structure(cif::read_mmjson_insitu(data, size, path), save_doc);
  fail("wrong format of coordinate file " + path);
}

/// @deprecated Use read_structure_from_memory() instead.
/// Read a Structure from a character array buffer.
/// @param data      Pointer to file data
/// @param size      Size of data buffer in bytes
/// @param path      File path or name
/// @param save_doc  Optional pointer to receive the parsed CIF document
/// @return A Structure parsed from the buffer with format auto-detected
inline Structure read_structure_from_char_array(char* data, size_t size,
                                                const std::string& path,
                                                cif::Document* save_doc=nullptr) {
  return read_structure_from_memory(data, size, path, CoorFormat::Unknown, save_doc);
}

/// @brief Read a Structure from an input source.
/// @tparam T       Input type (e.g., BasicInput, FileStream) with path() and create_stream()
/// Generic template that works with file paths, streams, and memory sources.
/// Optionally detects format from filename extension or content.
/// @param input    Input source; format is inferred from extension or content
/// @param format   File format to use: Unknown (detect by extension),
///                 Detect (load entire file and detect by content),
///                 or explicit format (Pdb, Mmcif, Mmjson, ChemComp)
/// @param save_doc Optional pointer to receive the parsed CIF document
/// @return A Structure parsed from the input
/// @throws Throws on I/O errors, parse errors, or if format cannot be determined
template<typename T>
Structure read_structure(T&& input, CoorFormat format=CoorFormat::Unknown,
                         cif::Document* save_doc=nullptr) {
  if (format == CoorFormat::Detect) {
    CharArray mem = read_into_buffer(input);
    return read_structure_from_memory(mem.data(), mem.size(), input.path(), format, save_doc);
  }
  if (save_doc)
    save_doc->clear();
  if (format == CoorFormat::Unknown)
    format = coor_format_from_ext(input.basepath());
  switch (format) {
    case CoorFormat::Pdb:
      return read_pdb(input);
    case CoorFormat::Mmcif:
      return make_structure(cif::read(input), save_doc);
    case CoorFormat::Mmjson: {
      Structure st = make_structure(cif::read_mmjson(input), save_doc);
      st.input_format = CoorFormat::Mmjson;
      return st;
    }
    case CoorFormat::ChemComp:
      return make_structure_from_chemcomp_doc(cif::read(input), save_doc);
    case CoorFormat::Unknown:
    case CoorFormat::Detect:
      fail("Unknown format of " +
           (input.path().empty() ? "coordinate file" : input.path()) + ".");
  }
  unreachable();
}

/// Read a Structure from a file.
/// Convenience wrapper for read_structure() with a file path.
/// Format is detected from filename extension by default.
/// @param path   Path to coordinate file
/// @param format File format to use: Unknown (detect by extension) or explicit format
/// @return A Structure parsed from the file
/// @throws Throws on I/O or parse errors
inline Structure read_structure_file(const std::string& path,
                                     CoorFormat format=CoorFormat::Unknown) {
  return read_structure(BasicInput(path), format);
}

} // namespace gemmi
#endif
