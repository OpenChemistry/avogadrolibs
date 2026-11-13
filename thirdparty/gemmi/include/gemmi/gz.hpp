// Copyright 2017 Global Phasing Ltd.
//
// Functions for transparent reading of gzipped files. Uses zlib.

#ifndef GEMMI_GZ_HPP_
#define GEMMI_GZ_HPP_
#include <string>
#include "fail.hpp"     // GEMMI_DLL
#include "input.hpp"    // BasicInput
#include "util.hpp"     // iends_with

namespace gemmi {

/// @brief String describing zlib version and build information.
GEMMI_DLL extern const char* const zlib_description;

/// Estimate uncompressed size of a gzipped file.
/// @brief Estimate the decompressed size of a .gz file.
/// @param path path to gzipped file
/// @return estimated uncompressed size in bytes
GEMMI_DLL size_t estimate_uncompressed_size(const std::string& path);

/// @brief Stream wrapper for reading gzipped files.
/// @details Implements AnyStream interface for transparent gzip reading (using zlib).
struct GEMMI_DLL GzStream final : public AnyStream {
  /// Create a gzip stream from a zlib gzFile pointer.
  /// @brief Construct stream from gzFile handle.
  /// @param f_ opaque gzFile pointer
  GzStream(void* f_) : f(f_) {}
  /// Read a line from the stream.
  /// @brief Read next line into buffer.
  /// @param line buffer to store line
  /// @param size maximum bytes to read (including null terminator)
  /// @return pointer to line or null if end of file
  char* gets(char* line, int size) override;
  /// Read a single character.
  /// @brief Get next byte from stream.
  /// @return character as int, or -1 for end of file
  int getc() override;
  /// Read a block of data.
  /// @brief Read specified number of bytes.
  /// @param buf buffer to read into
  /// @param len number of bytes to read
  /// @return true if exactly len bytes were read
  bool read(void* buf, size_t len) override;
  /// Skip forward in stream.
  /// @brief Advance stream position without reading.
  /// @param n number of bytes to skip
  /// @return true if skip succeeded
  bool skip(size_t n) override;
  /// Get current position.
  /// @brief Report stream position.
  /// @return current byte offset in stream
  long tell() override;
  /// Read remainder of stream.
  /// @brief Read all remaining data as string.
  /// @return remaining stream contents as std::string
  std::string read_rest() override;

private:
  void* f;  // implementation detail
};

/// @brief Input source that transparently handles gzipped files.
/// @details Manages both regular and gzipped files with automatic detection.
class GEMMI_DLL MaybeGzipped : public BasicInput {
public:
  /// Open a file (compressed or uncompressed).
  /// @brief Initialize reader for file that may be gzipped.
  /// @param path file path (may end in .gz)
  explicit MaybeGzipped(const std::string& path);
  /// Close file resources.
  /// @brief Destructor.
  ~MaybeGzipped();
  /// Read from gzipped file with error checking.
  /// @brief Read bytes from gzipped stream.
  /// @param buf buffer to read into
  /// @param len number of bytes to read
  /// @return number of bytes read
  /// @throws std::runtime_error on gzip read error
  size_t gzread_checked(void* buf, size_t len);
  /// Check if file is gzip compressed.
  /// @brief Test whether file has .gz extension.
  /// @return true if path ends with .gz
  bool is_compressed() const { return iends_with(path(), ".gz"); }
  /// Get path without .gz extension.
  /// @brief Remove .gz suffix if present.
  /// @return path without extension, or original path if not gzipped
  std::string basepath() const {
    return is_compressed() ? path().substr(0, path().size() - 3) : path();
  }

  /// Decompress entire file into buffer.
  /// @brief Load gzipped or plain file contents into memory.
  /// @param limit maximum decompressed size (0 = unlimited)
  /// @return CharArray with file contents
  /// @throws std::runtime_error if decompression fails or size limit exceeded
  CharArray uncompress_into_buffer(size_t limit=0);

  /// Create a stream reader for this file.
  /// @brief Create appropriate stream object (GzStream or FileStream).
  /// @return unique_ptr to AnyStream for reading file
  std::unique_ptr<AnyStream> create_stream();

private:
  void* file_ = nullptr;
};

} // namespace gemmi

#endif
