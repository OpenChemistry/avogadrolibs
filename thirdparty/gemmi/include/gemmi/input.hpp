// Copyright 2018 Global Phasing Ltd.
//
// Input abstraction.
// Used to decouple file reading and decompression.

#ifndef GEMMI_INPUT_HPP_
#define GEMMI_INPUT_HPP_

#include <cstddef> // for ptrdiff_t
#include <cstdio>  // for FILE, fseek, fread
#include <cstring> // for memchr
#include <string>
#include "fileutil.hpp"  // for fileptr_t

namespace gemmi {

/// @brief Base class for stream abstractions (FileStream, MemoryStream, GzStream).
struct AnyStream {
  virtual ~AnyStream() = default;

  /// @brief Read a line of text into a buffer.
  /// @param line Output buffer for the line
  /// @param size Maximum number of characters to read
  /// @return Pointer to line on success, nullptr if end of stream reached
  virtual char* gets(char* line, int size) = 0;

  /// @brief Read a single character from the stream.
  /// @return Next character, or EOF if end of stream reached
  virtual int getc() = 0;

  /// @brief Read a block of binary data.
  /// @param buf Output buffer
  /// @param len Number of bytes to read
  /// @return True if successfully read exactly len bytes, false otherwise
  virtual bool read(void* buf, size_t len) = 0;

  /// @brief Get current position in the stream.
  /// @return Current byte offset
  virtual long tell() = 0;

  /// @brief Skip ahead in the stream.
  /// @param n Number of bytes to skip
  /// @return True if skip succeeded
  virtual bool skip(size_t n) = 0;

  /// @brief Read remaining data in the stream.
  /// @return String containing remaining data, or empty string if none
  virtual std::string read_rest() { return {}; }

  /// @brief Read a line and discard any overflow.
  /// @param line Output buffer
  /// @param size Maximum characters to read
  /// @return Length of line read (including newline if present)
  size_t copy_line(char* line, int size) {
    if (!gets(line, size))
      return 0;
    size_t len = std::strlen(line);
    // If a line is longer than size we discard the rest of it.
    if (len > 0 && line[len-1] != '\n')
      for (int c = getc(); c > 0 /* not 0 nor EOF */ && c != '\n'; c = getc())
        continue;
    return len;
  };
};

/// @brief Stream abstraction for reading from files or stdin.
struct FileStream final : public AnyStream {
  /// @brief Open a file stream from a FILE* pointer.
  /// @param f_ Existing FILE* pointer (not closed on destruction)
  FileStream(std::FILE* f_) : f(f_, needs_fclose{false}) {}

  /// @brief Open a file stream from a file path.
  /// @param path File path (use "-" for stdin)
  /// @param mode File open mode ("rb", "r", etc.)
  FileStream(const char* path, const char* mode) : f(file_open_or(path, mode, stdin)) {}

  /// @brief Read a line of text from the file.
  /// @param line Output buffer
  /// @param size Maximum characters to read
  /// @return Pointer to line, or nullptr if at end of file
  char* gets(char* line, int size) override { return std::fgets(line, size, f.get()); }

  /// @brief Read a single character from the file.
  /// @return Next character, or EOF if at end of file
  int getc() override { return std::fgetc(f.get()); }

  /// @brief Read a block of binary data from the file.
  /// @param buf Output buffer
  /// @param len Number of bytes to read
  /// @return True if successfully read exactly len bytes
  bool read(void* buf, size_t len) override { return std::fread(buf, len, 1, f.get()) == 1; }

  /// @brief Read all remaining data from current position to end of file.
  /// @return String containing remaining data
  std::string read_rest() override {
    std::string ret;
    int c = std::fgetc(f.get());
    if (c != EOF) {
      ret += (char)c;
      char buf[512];
      for (;;) {
        size_t n = std::fread(buf, 1, sizeof(buf), f.get());
        ret.append(buf, n);
        if (n != sizeof(buf))
          break;
      }
    }
    return ret;
  }

  /// @brief Get current file position.
  /// @return Current byte offset in file
  long tell() override {
    return std::ftell(f.get());
  }

  /// @brief Skip ahead in the file.
  /// @param n Number of bytes to skip
  /// @return True if successfully skipped
  bool skip(size_t n) override {
#if defined(_MSC_VER)
    int result = _fseeki64(f.get(), (std::ptrdiff_t)n, SEEK_CUR);
#elif defined(__MINGW32__)
    int result = fseeko(f.get(), (_off_t)n, SEEK_CUR);
#else
    int result = std::fseek(f.get(), (long)n, SEEK_CUR);
#endif
    if (result != 0) {
      char buf[512];
      while (n >= sizeof(buf)) {
        if (std::fread(buf, sizeof(buf), 1, f.get()) != 1)
          return false;
        n -= sizeof(buf);
      }
      if (n > 0 && std::fread(buf, n, 1, f.get()) != 1)
        return false;
    }
    return true;
  }

private:
  fileptr_t f;
};

/// @brief Stream abstraction for reading from memory buffers.
struct MemoryStream final : public AnyStream {
  /// @brief Create a stream from a memory buffer.
  /// @param start_ Pointer to start of buffer
  /// @param size Size of buffer in bytes
  MemoryStream(const char* start_, size_t size)
    : start(start_), end(start_ + size), cur(start_) {}

  /// @brief Read a line of text from the buffer.
  /// @param line Output buffer
  /// @param size Maximum characters to read
  /// @return Pointer to line, or nullptr if at end of buffer
  char* gets(char* line, int size) override {
    --size; // fgets reads in at most one less than size characters
    if (cur >= end)
      return nullptr;
    if (size > end - cur)
      size = int(end - cur);
    const char* nl = (const char*) std::memchr(cur, '\n', size);
    size_t len = nl ? nl - cur + 1 : size;
    std::memcpy(line, cur, len);
    line[len] = '\0';
    cur += len;
    return line;
  }

  /// @brief Read a single character from the buffer.
  /// @return Next character, or EOF if at end of buffer
  int getc() override { return cur < end ? *cur++ : EOF; }

  /// @brief Read a block of binary data from the buffer.
  /// @param buf Output buffer
  /// @param len Number of bytes to read
  /// @return True if successfully read exactly len bytes
  bool read(void* buf, size_t len) override {
    if (cur + len > end)
      return false;
    std::memcpy(buf, cur, len);
    cur += len;
    return true;
  }

  /// @brief Read all remaining data from current position to end of buffer.
  /// @return String containing remaining data
  std::string read_rest() override {
    const char* last = cur;
    cur = end;
    return std::string(last, end);
  }

  /// @brief Get current position in the buffer.
  /// @return Current byte offset
  long tell() override {
    return cur - start;
  }

  /// @brief Skip ahead in the buffer.
  /// @param n Number of bytes to skip
  /// @return True if skip did not exceed buffer end
  bool skip(size_t n) override {
    cur += n;
    return cur < end;
  }

private:
  const char* const start;
  const char* const end;
  const char* cur;
};

/// @brief Input source abstraction for file paths.
class BasicInput {
public:
  /// @brief Initialize with a file path.
  /// @param path File path (use "-" for stdin)
  explicit BasicInput(const std::string& path) : path_(path) {}

  /// @brief Get the input path.
  /// @return Input path
  const std::string& path() const { return path_; }

  /// @brief Get the base path for reading (same as path() for non-compressed files).
  /// @return Base path
  const std::string& basepath() const { return path_; }

  /// @brief Check if this input source is stdin.
  /// @return True if path is "-"
  bool is_stdin() const { return path() == "-"; }

  /// @brief Check if the input source is compressed.
  /// @return False for BasicInput (always uncompressed)
  bool is_compressed() const { return false; }

  /// @brief Read whole file into memory (for compatibility with MaybeGzipped interface).
  /// @details The size parameter is unused; present for interface compatibility.
  /// @return Empty CharArray (no decompression for BasicInput)
  CharArray uncompress_into_buffer(size_t=0) { return {}; }

  /// @brief Create a stream for sequential reading.
  /// @return Unique pointer to a FileStream
  std::unique_ptr<AnyStream> create_stream() {
    return std::unique_ptr<AnyStream>(new FileStream(path().c_str(), "rb"));
  }

private:
  std::string path_;
};

} // namespace gemmi
#endif
