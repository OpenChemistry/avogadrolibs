/// @file
/// @brief Read PDB file format and store coordinates in a Structure.
///
/// Implements PDB format parsing per the wwPDB specification v3.3:
/// https://www.wwpdb.org/documentation/file-format-content/format33/v3.3.html
///
/// Enhancements beyond standard PDB:
/// - Two-character chain IDs (columns 21-22)
/// - Segment ID parsing (columns 73-76)
/// - Hybrid-36 serial numbers for > 99,999 atoms
/// - Hybrid-36 sequence IDs for sequences > 9,999 residues
/// - Extended REMARK lines (up to 120 characters)

// Copyright 2017 Global Phasing Ltd.
//
// Read the PDB file format and store it in Structure.
//
// Based on the format spec:
// https://www.wwpdb.org/documentation/file-format-content/format33/v3.3.html
// + support for two-character chain IDs (columns 21 and 22)
// + read segment ID (columns 73-76)
// + read hybrid-36 serial numbers (http://cci.lbl.gov/hybrid_36/)
// + hybrid-36 sequence id for sequences longer than 9999 (no such examples)
// + allow for longer REMARK lines (up to 120 characters)

#ifndef GEMMI_PDB_HPP_
#define GEMMI_PDB_HPP_

#include "input.hpp"    // for FileStream
#include "model.hpp"    // for Structure, ...

namespace gemmi {

/// Test if the first 4 columns of a PDB record match a given record type.
/// Case-insensitive comparison; space and NUL characters in @a s are
/// treated as equivalent for matching purposes.
/// @param s      PDB record line (must have >= 4 characters)
/// @param record Uppercase record name to match (e.g., "ATOM", "HETATM")
/// @return True if the record names match
inline bool is_record_type4(const char* s, const char* record) {
  return ialpha4_id(s) == ialpha4_id(record);
}

/// Test if the first 3 columns of a PDB record match a given record type.
/// Used for 3-character records like TER where the 4th character varies.
/// Matches "TER ", "TER\n", "TER\r", "TER\t" but not "TERE" or "TER1".
/// @param s      PDB record line (must have >= 4 characters)
/// @param record Uppercase record name to match (e.g., "TER", "END")
/// @return True if the first 3 characters of the record match
inline bool is_record_type3(const char* s, const char* record) {
  return (ialpha4_id(s) & ~0xf) == ialpha4_id(record);
}

/// Parse REMARK 290 records to extract crystallographic symmetry operations.
/// REMARK 290 contains the rotation and translation operators (NCS or crystal symmetry).
/// Parses operations in triplet notation (e.g., "X,Y,Z" or "-X,-Y,-Z+1/2").
/// @param raw_remarks Vector of PDB REMARK record lines
/// @return Vector of crystallographic operations (Op structures with rotation
///         matrix and translation vector)
GEMMI_DLL std::vector<Op> read_remark_290(const std::vector<std::string>& raw_remarks);

/// Populate a Structure by parsing a PDB stream.
/// Parses all ATOM/HETATM records and metadata from the stream, populating
/// the Structure with models, chains, residues, and atoms.
/// @param line_reader Stream to read PDB records from
/// @param source      Source name/path (used in error messages)
/// @param st          Structure to populate with parsed coordinates
/// @param options     Parsing options (line length, TER handling, skip remarks, etc.)
/// @throws Throws on parse errors or invalid records
GEMMI_DLL void populate_structure_from_pdb_stream(AnyStream& line_reader,
                                                  const std::string& source,
                                                  Structure& st,
                                                  PdbReadOptions options);

/// Populate a Structure by parsing PDB data from a memory buffer.
/// Convenience wrapper around populate_structure_from_pdb_stream().
/// @param data    Pointer to PDB file contents
/// @param size    Size of the buffer in bytes
/// @param name    Source name/path (used in error messages)
/// @param st      Structure to populate with parsed coordinates
/// @param options Parsing options; defaults to standard PDB settings
/// @throws Throws on parse errors or invalid records
inline void populate_structure_from_pdb_memory(const char* data, size_t size,
                                               const std::string& name,
                                               Structure& st,
                                               PdbReadOptions options={}) {
  MemoryStream stream{data, size};
  populate_structure_from_pdb_stream(stream, name, st, options);
}

/// Populate a Structure by parsing PDB data from a string.
/// Convenience wrapper around populate_structure_from_pdb_memory().
/// @param str     String containing PDB file contents
/// @param name    Source name/path (used in error messages)
/// @param st      Structure to populate with parsed coordinates
/// @param options Parsing options; defaults to standard PDB settings
/// @throws Throws on parse errors or invalid records
inline void populate_structure_from_pdb_string(const std::string& str,
                                              const std::string& name,
                                              Structure& st,
                                              PdbReadOptions options={}) {
  populate_structure_from_pdb_memory(str.c_str(), str.length(), name, st, options);
}

/// Read a Structure from a PDB stream.
/// Convenience wrapper around populate_structure_from_pdb_stream().
/// @param line_reader Stream to read PDB records from
/// @param source      Source name/path (used in error messages)
/// @param options     Parsing options (line length, TER handling, skip remarks, etc.)
/// @return A new Structure parsed from the PDB stream
/// @throws Throws on parse errors or invalid records
inline Structure read_pdb_from_stream(AnyStream& line_reader,
                                      const std::string& source,
                                      PdbReadOptions options) {
  gemmi::Structure st;
  populate_structure_from_pdb_stream(line_reader, source, st, options);
  return st;
};

/// Read a Structure from a PDB file.
/// @param path    Path to PDB file
/// @param options Parsing options; defaults to standard PDB settings
/// @return A new Structure parsed from the file
/// @throws Throws on I/O or parse errors
inline Structure read_pdb_file(const std::string& path,
                               PdbReadOptions options={}) {
  FileStream stream(path.c_str(), "rb");
  return read_pdb_from_stream(stream, path, options);
}

/// Read a Structure from a PDB-format memory buffer.
/// @param data    Pointer to PDB file contents
/// @param size    Size of the buffer in bytes
/// @param name    Source name/path (used in error messages)
/// @param options Parsing options; defaults to standard PDB settings
/// @return A new Structure parsed from the buffer
/// @throws Throws on parse errors or invalid records
inline Structure read_pdb_from_memory(const char* data, size_t size,
                                      const std::string& name,
                                      PdbReadOptions options={}) {
  MemoryStream stream{data, size};
  return read_pdb_from_stream(stream, name, options);
}

/// Read a Structure from a PDB-format string.
/// @param str     String containing PDB file contents
/// @param name    Source name/path (used in error messages)
/// @param options Parsing options; defaults to standard PDB settings
/// @return A new Structure parsed from the string
/// @throws Throws on parse errors or invalid records
inline Structure read_pdb_string(const std::string& str,
                                 const std::string& name,
                                 PdbReadOptions options={}) {
  return read_pdb_from_memory(str.c_str(), str.length(), name, options);
}

/// @brief Read a Structure from a PDB input source.
/// @tparam T      Input type (e.g., BasicInput, FileStream) with path() and create_stream()
/// Generic template for file paths, streams, and other input types.
/// @param input   Input source
/// @param options Parsing options; defaults to standard PDB settings
/// @return A new Structure parsed from the input
/// @throws Throws on I/O or parse errors
template<typename T>
inline Structure read_pdb(T&& input, PdbReadOptions options={}) {
  return read_pdb_from_stream(*input.create_stream(), input.path(), options);
}

} // namespace gemmi
#endif
