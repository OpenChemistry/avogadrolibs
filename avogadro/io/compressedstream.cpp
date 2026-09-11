/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "compressedstream.h"

#include <algorithm>
#include <cstring>
#include <locale>

#ifdef AVO_USE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#include <zlib.h>
#endif

namespace Avogadro::Io {

namespace {
constexpr std::size_t kInvalidChunk = static_cast<std::size_t>(-1);

#ifdef AVO_USE_LIBARCHIVE
/**
 * libarchive's error string is NULL whenever it has no message to give, which
 * includes ordinary end of data, so it can never be concatenated directly.
 */
std::string archiveError(struct archive* handle, const char* fallback)
{
  const char* message =
    (handle != nullptr) ? archive_error_string(handle) : nullptr;
  return std::string("libarchive: ") +
         (message != nullptr ? message : fallback);
}
#endif
} // namespace

// ============================================================================
// DecompressingStreamBufPrivate
// ============================================================================

class DecompressingStreamBufPrivate
{
public:
  static constexpr std::size_t kChunkSize = 65536;

  DecompressingStreamBufPrivate(std::unique_ptr<std::istream> source_,
                                Compression type_,
                                std::uint64_t maxDecodedSize_)
    : source(std::move(source_)), type(type_), maxDecodedSize(maxDecodedSize_)
  {
  }

  ~DecompressingStreamBufPrivate()
  {
#ifdef AVO_USE_LIBARCHIVE
    if (zstreamOpen)
      inflateEnd(&zstream);
    if (archiveHandle != nullptr)
      archive_read_free(archiveHandle);
#endif
  }

  DecompressingStreamBufPrivate(const DecompressingStreamBufPrivate&) = delete;
  DecompressingStreamBufPrivate& operator=(
    const DecompressingStreamBufPrivate&) = delete;

  /**
   * Append one more decoded chunk (up to kChunkSize bytes) to chunks. Returns
   * false when nothing more could be produced -- either because decoding is
   * already finished (atEndFlag), the size limit was hit, or a hard error
   * occurred. A chunk that was partially filled before EOF/error is still
   * kept.
   */
  bool decodeNextChunk()
  {
    if (atEndFlag)
      return false;

    if (!checkedSupport) {
      checkedSupport = true;
      if (!compressionSupported(type)) {
        errorMsg = compressionName(type) +
                   " decompression is not supported in this build";
        atEndFlag = true;
        return false;
      }
    }

    if (maxDecodedSize != 0 && decodedSize >= maxDecodedSize) {
      hitLimitFlag = true;
      errorMsg = "decompressed data exceeds the maxDecompressedSize limit "
                 "of " +
                 std::to_string(maxDecodedSize) +
                 " bytes; raise the maxDecompressedSize option";
      atEndFlag = true;
      return false;
    }

    std::unique_ptr<char[]> chunk(new (std::nothrow) char[kChunkSize]);
    if (!chunk) {
      errorMsg = "out of memory while decompressing";
      atEndFlag = true;
      return false;
    }

    std::size_t len = 0;
#ifdef AVO_USE_LIBARCHIVE
    if (type == Compression::Gzip)
      decodeGzipChunk(chunk.get(), kChunkSize, len);
    else
      decodeArchiveChunk(chunk.get(), kChunkSize, len);
#else
    (void)chunk;
#endif

    if (len == 0)
      return false;

    chunks.push_back(std::move(chunk));
    decodedSize += len;
    return true;
  }

  std::size_t chunkLength(std::size_t index) const
  {
    if (index + 1 < chunks.size())
      return kChunkSize;
    std::uint64_t priorBytes = static_cast<std::uint64_t>(index) * kChunkSize;
    return static_cast<std::size_t>(decodedSize - priorBytes);
  }

#ifdef AVO_USE_LIBARCHIVE
  void decodeGzipChunk(char* outBuf, std::size_t outCap, std::size_t& outLen)
  {
    outLen = 0;

    if (!zstreamOpen) {
      std::memset(&zstream, 0, sizeof(zstream));
      // 15 window bits, +32 auto-detects the gzip header (and would also
      // accept a bare zlib stream, which we never see here since detection
      // already required the gzip magic).
      if (inflateInit2(&zstream, 15 + 32) != Z_OK) {
        errorMsg = "failed to initialize the gzip decompressor";
        atEndFlag = true;
        return;
      }
      zstreamOpen = true;
    }

    zstream.next_out = reinterpret_cast<Bytef*>(outBuf);
    zstream.avail_out = static_cast<uInt>(outCap);

    while (zstream.avail_out > 0) {
      if (zstream.avail_in == 0) {
        source->read(inBuf, sizeof(inBuf));
        std::streamsize n = source->gcount();
        if (n <= 0) {
          // Input exhausted. If we never completed a member, this is a
          // truncated stream and must be reported as an error; if we did,
          // it is simply the clean end of the data.
          if (!sawStreamEnd) {
            errorMsg = "truncated gzip stream: input ended before the gzip "
                       "trailer";
          }
          finishZlib();
          break;
        }
        zstream.next_in = reinterpret_cast<Bytef*>(inBuf);
        zstream.avail_in = static_cast<uInt>(n);
      }

      int ret = inflate(&zstream, Z_NO_FLUSH);
      if (ret == Z_STREAM_END) {
        sawStreamEnd = true;

        // Concatenated gzip members are legal and common (`cat a.gz b.gz`).
        // Peek at whatever bytes remain to decide whether another member
        // follows or this is trailing garbage / the true end.
        if (zstream.avail_in < 3) {
          std::size_t have = zstream.avail_in;
          std::memmove(inBuf, zstream.next_in, have);
          source->read(inBuf + have, sizeof(inBuf) - have);
          std::streamsize n = source->gcount();
          if (n > 0)
            have += static_cast<std::size_t>(n);
          zstream.next_in = reinterpret_cast<Bytef*>(inBuf);
          zstream.avail_in = static_cast<uInt>(have);
        }

        if (zstream.avail_in == 0) {
          // Nothing left at all: a clean end of data.
          finishZlib();
          break;
        }

        if (detectCompression(reinterpret_cast<const char*>(zstream.next_in),
                              zstream.avail_in) == Compression::Gzip) {
          if (inflateReset2(&zstream, 15 + 32) != Z_OK) {
            errorMsg = "failed to reset the gzip decompressor for a "
                       "concatenated member";
            finishZlib();
            break;
          }
          // Each member carries its own trailer, so the next one has to end
          // cleanly in its own right. Without clearing this, a file whose
          // second member is truncated would be accepted on the strength of
          // the first member having ended properly.
          sawStreamEnd = false;
          continue;
        }

        // Trailing garbage after a complete stream is not an error; stop
        // here and keep what has been decoded, matching `gzip -d`.
        finishZlib();
        break;
      }

      if (ret != Z_OK && ret != Z_BUF_ERROR) {
        errorMsg = std::string("gzip decompression error: ") +
                   (zstream.msg != nullptr ? zstream.msg : "corrupt data");
        finishZlib();
        break;
      }
      // Z_OK / Z_BUF_ERROR: loop again, topping up input as needed or
      // stopping once the output buffer is full.
    }

    outLen = outCap - zstream.avail_out;
  }

  void finishZlib()
  {
    atEndFlag = true;
    if (zstreamOpen) {
      inflateEnd(&zstream);
      zstreamOpen = false;
    }
  }

  static la_ssize_t archiveReadCallback(struct archive*, void* clientData,
                                        const void** buffer)
  {
    auto* self = static_cast<DecompressingStreamBufPrivate*>(clientData);
    self->source->read(self->archiveReadBuf, sizeof(self->archiveReadBuf));
    std::streamsize n = self->source->gcount();
    *buffer = self->archiveReadBuf;
    return static_cast<la_ssize_t>(n);
  }

  bool initArchiveReader()
  {
    archiveHandle = archive_read_new();
    if (archiveHandle == nullptr) {
      errorMsg = "failed to create the libarchive reader";
      return false;
    }

    int filterResult = ARCHIVE_FATAL;
    int expectedFilter = ARCHIVE_FILTER_NONE;
    switch (type) {
      case Compression::Bzip2:
        filterResult = archive_read_support_filter_bzip2(archiveHandle);
        expectedFilter = ARCHIVE_FILTER_BZIP2;
        break;
      case Compression::Xz:
        filterResult = archive_read_support_filter_xz(archiveHandle);
        expectedFilter = ARCHIVE_FILTER_XZ;
        break;
      case Compression::Zstd:
        filterResult = archive_read_support_filter_zstd(archiveHandle);
        expectedFilter = ARCHIVE_FILTER_ZSTD;
        break;
      default:
        errorMsg = compressionName(type) +
                   " decompression is not supported in this build";
        archive_read_free(archiveHandle);
        archiveHandle = nullptr;
        return false;
    }

    if (filterResult != ARCHIVE_OK) {
      errorMsg =
        compressionName(type) + " decompression is not supported in this build";
      archive_read_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    archive_read_support_format_raw(archiveHandle);
    archive_read_support_format_empty(archiveHandle);
    archive_read_set_read_callback(archiveHandle, &archiveReadCallback);
    archive_read_set_callback_data(archiveHandle, this);

    if (archive_read_open1(archiveHandle) != ARCHIVE_OK) {
      errorMsg = archiveError(archiveHandle, "read failed");
      archive_read_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    struct archive_entry* entry = nullptr;
    int headerResult = archive_read_next_header(archiveHandle, &entry);
    if (headerResult == ARCHIVE_EOF) {
      // No entry at all, which is how an empty payload round-trips. Report it
      // as a clean end of data rather than an error: the caller sees zero
      // bytes and an empty error(), exactly like reading an empty plain file.
      archive_read_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }
    if (headerResult != ARCHIVE_OK && headerResult != ARCHIVE_WARN) {
      errorMsg = archiveError(archiveHandle, "read failed");
      archive_read_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    // Mandatory guard: without a registered, natively supported filter,
    // format_raw silently hands back the still-compressed bytes as if they
    // were the file contents (filter code ARCHIVE_FILTER_NONE). Refuse that.
    if (archive_filter_code(archiveHandle, 0) != expectedFilter) {
      errorMsg =
        compressionName(type) + " decompression is not supported in this build";
      archive_read_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    return true;
  }

  void decodeArchiveChunk(char* buf, std::size_t cap, std::size_t& outLen)
  {
    outLen = 0;

    if (!archiveInitialized) {
      archiveInitialized = true;
      if (!initArchiveReader()) {
        atEndFlag = true;
        return;
      }
    }
    if (archiveHandle == nullptr) {
      atEndFlag = true;
      return;
    }

    while (outLen < cap) {
      la_ssize_t n =
        archive_read_data(archiveHandle, buf + outLen, cap - outLen);
      if (n < 0) {
        errorMsg = archiveError(archiveHandle, "read failed");
        atEndFlag = true;
        return;
      }
      if (n == 0) {
        atEndFlag = true;
        return;
      }
      outLen += static_cast<std::size_t>(n);
    }
  }
#endif // AVO_USE_LIBARCHIVE

  std::unique_ptr<std::istream> source;
  Compression type;
  std::uint64_t maxDecodedSize;

  std::vector<std::unique_ptr<char[]>> chunks;
  std::uint64_t decodedSize = 0;
  bool atEndFlag = false;
  bool hitLimitFlag = false;
  bool checkedSupport = false;
  std::string errorMsg;
  std::size_t currentChunkIndex = kInvalidChunk;

#ifdef AVO_USE_LIBARCHIVE
  // gzip / zlib state.
  z_stream zstream{};
  bool zstreamOpen = false;
  bool sawStreamEnd = false;
  char inBuf[kChunkSize];

  // bzip2 / xz / zstd / libarchive state.
  bool archiveInitialized = false;
  struct archive* archiveHandle = nullptr;
  char archiveReadBuf[kChunkSize];
#endif
};

// ============================================================================
// DecompressingStreamBuf
// ============================================================================

DecompressingStreamBuf::DecompressingStreamBuf(
  std::unique_ptr<std::istream> source, Compression type,
  std::uint64_t maxDecodedSize)
  : d(new DecompressingStreamBufPrivate(std::move(source), type,
                                        maxDecodedSize))
{
  setg(nullptr, nullptr, nullptr);
}

DecompressingStreamBuf::~DecompressingStreamBuf() = default;

Compression DecompressingStreamBuf::compression() const
{
  return d->type;
}

std::string DecompressingStreamBuf::error() const
{
  return d->errorMsg;
}

bool DecompressingStreamBuf::hitSizeLimit() const
{
  return d->hitLimitFlag;
}

std::uint64_t DecompressingStreamBuf::decodedSize() const
{
  return d->decodedSize;
}

bool DecompressingStreamBuf::atEnd() const
{
  return d->atEndFlag;
}

DecompressingStreamBuf::int_type DecompressingStreamBuf::underflow()
{
  if (gptr() != nullptr && gptr() < egptr())
    return traits_type::to_int_type(*gptr());

  std::size_t nextIndex =
    (d->currentChunkIndex == kInvalidChunk) ? 0 : d->currentChunkIndex + 1;

  if (nextIndex >= d->chunks.size()) {
    if (!d->decodeNextChunk())
      return traits_type::eof();
  }

  if (nextIndex >= d->chunks.size())
    return traits_type::eof();

  std::size_t len = d->chunkLength(nextIndex);
  char* base = d->chunks[nextIndex].get();
  setg(base, base, base + len);
  d->currentChunkIndex = nextIndex;

  if (len == 0)
    return traits_type::eof();
  return traits_type::to_int_type(*gptr());
}

std::streamsize DecompressingStreamBuf::xsgetn(char* s, std::streamsize count)
{
  std::streamsize total = 0;
  while (total < count) {
    if (!(gptr() != nullptr && gptr() < egptr())) {
      if (underflow() == traits_type::eof())
        break;
    }
    std::ptrdiff_t avail = egptr() - gptr();
    std::streamsize n = std::min<std::streamsize>(avail, count - total);
    if (n <= 0)
      break;
    std::memcpy(s + total, gptr(), static_cast<std::size_t>(n));
    gbump(static_cast<int>(n));
    total += n;
  }
  return total;
}

DecompressingStreamBuf::pos_type DecompressingStreamBuf::seekoff(
  off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which)
{
  if (!(which & std::ios_base::in))
    return pos_type(off_type(-1));

  constexpr std::size_t kChunk = DecompressingStreamBufPrivate::kChunkSize;

  // Absolute position implied by the current get area. All of this logic is
  // kept inline in the two overrides that the header actually declares
  // (rather than factored into extra private members) so the public headers
  // do not need to change.
  auto currentAbsolutePos = [this]() -> std::uint64_t {
    std::uint64_t base =
      (d->currentChunkIndex == kInvalidChunk)
        ? 0
        : static_cast<std::uint64_t>(d->currentChunkIndex) * kChunk;
    std::ptrdiff_t offset = (gptr() != nullptr) ? (gptr() - eback()) : 0;
    return base + static_cast<std::uint64_t>(offset);
  };

  std::int64_t target = 0;
  if (dir == std::ios_base::beg) {
    target = off;
  } else if (dir == std::ios_base::cur) {
    target = static_cast<std::int64_t>(currentAbsolutePos()) + off;
  } else if (dir == std::ios_base::end) {
    while (d->decodeNextChunk()) {}
    target = static_cast<std::int64_t>(d->decodedSize) + off;
  } else {
    return pos_type(off_type(-1));
  }

  if (target < 0)
    return pos_type(off_type(-1));

  std::uint64_t utarget = static_cast<std::uint64_t>(target);
  if (utarget > d->decodedSize) {
    while (d->decodedSize < utarget && d->decodeNextChunk()) {}
    if (utarget > d->decodedSize)
      return pos_type(off_type(-1));
  }

  if (utarget == d->decodedSize) {
    if (d->chunks.empty()) {
      setg(nullptr, nullptr, nullptr);
      d->currentChunkIndex = kInvalidChunk;
    } else {
      std::size_t lastIndex = d->chunks.size() - 1;
      char* base = d->chunks[lastIndex].get();
      std::size_t len = d->chunkLength(lastIndex);
      setg(base, base + len, base + len);
      d->currentChunkIndex = lastIndex;
    }
  } else {
    std::size_t index = static_cast<std::size_t>(utarget / kChunk);
    std::size_t offset = static_cast<std::size_t>(utarget % kChunk);
    char* base = d->chunks[index].get();
    std::size_t len = d->chunkLength(index);
    setg(base, base + offset, base + len);
    d->currentChunkIndex = index;
  }

  return pos_type(static_cast<off_type>(utarget));
}

DecompressingStreamBuf::pos_type DecompressingStreamBuf::seekpos(
  pos_type pos, std::ios_base::openmode which)
{
  return seekoff(off_type(pos), std::ios_base::beg, which);
}

// ============================================================================
// DecompressingIStream
// ============================================================================

DecompressingIStream::DecompressingIStream(std::unique_ptr<std::istream> src,
                                           Compression type,
                                           std::uint64_t maxDecodedSize)
  : std::istream(&m_buf), m_buf(std::move(src), type, maxDecodedSize)
{
}

DecompressingIStream::~DecompressingIStream() = default;

// ============================================================================
// CompressingStreamBufPrivate
// ============================================================================

class CompressingStreamBufPrivate
{
public:
  static constexpr std::size_t kWriteChunkSize = 65536;

  CompressingStreamBufPrivate(std::unique_ptr<std::ostream> sink_,
                              Compression type_)
    : sink(std::move(sink_)), type(type_)
  {
  }

  ~CompressingStreamBufPrivate()
  {
#ifdef AVO_USE_LIBARCHIVE
    if (zstreamOpen)
      deflateEnd(&zstream);
    if (archiveHandle != nullptr)
      archive_write_free(archiveHandle);
#endif
  }

  CompressingStreamBufPrivate(const CompressingStreamBufPrivate&) = delete;
  CompressingStreamBufPrivate& operator=(const CompressingStreamBufPrivate&) =
    delete;

  bool write(const char* data, std::size_t len)
  {
    if (!errorMsg.empty())
      return false;

    if (!initialized) {
      initialized = true;
      bool ok;
#ifdef AVO_USE_LIBARCHIVE
      if (type == Compression::Gzip)
        ok = initGzipWriter();
      else
        ok = initArchiveWriter();
#else
      ok = false;
      errorMsg = "compressed file writing is not supported in this build";
#endif
      if (!ok)
        return false;
    }

    if (len == 0)
      return true;

#ifdef AVO_USE_LIBARCHIVE
    if (type == Compression::Gzip)
      return writeGzip(data, len);
    return writeArchive(data, len);
#else
    (void)data;
    return false;
#endif
  }

  bool finishCodec()
  {
    if (!initialized) {
      if (!write(nullptr, 0))
        return false;
    }
#ifdef AVO_USE_LIBARCHIVE
    bool ok = (type == Compression::Gzip) ? finishGzip() : finishArchive();
    return ok && errorMsg.empty();
#else
    return errorMsg.empty();
#endif
  }

#ifdef AVO_USE_LIBARCHIVE
  bool initGzipWriter()
  {
    std::memset(&zstream, 0, sizeof(zstream));
    // 15 window bits + 16 selects a gzip wrapper (CRC32 + ISIZE trailer).
    if (deflateInit2(&zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
      errorMsg = "failed to initialize the gzip compressor";
      return false;
    }
    zstreamOpen = true;
    return true;
  }

  bool writeGzip(const char* data, std::size_t len)
  {
    zstream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
    zstream.avail_in = static_cast<uInt>(len);

    char outBuf[kWriteChunkSize];
    do {
      zstream.next_out = reinterpret_cast<Bytef*>(outBuf);
      zstream.avail_out = static_cast<uInt>(sizeof(outBuf));
      int ret = deflate(&zstream, Z_NO_FLUSH);
      if (ret == Z_STREAM_ERROR) {
        errorMsg = "gzip compression error";
        return false;
      }
      std::size_t produced = sizeof(outBuf) - zstream.avail_out;
      if (produced > 0) {
        sink->write(outBuf, static_cast<std::streamsize>(produced));
        if (!sink->good()) {
          errorMsg = "failed writing compressed data to the output stream";
          return false;
        }
      }
    } while (zstream.avail_out == 0);
    return true;
  }

  bool finishGzip()
  {
    if (!zstreamOpen)
      return true;

    char outBuf[kWriteChunkSize];
    int ret = Z_OK;
    bool ok = true;
    do {
      zstream.next_out = reinterpret_cast<Bytef*>(outBuf);
      zstream.avail_out = static_cast<uInt>(sizeof(outBuf));
      ret = deflate(&zstream, Z_FINISH);
      std::size_t produced = sizeof(outBuf) - zstream.avail_out;
      if (produced > 0) {
        sink->write(outBuf, static_cast<std::streamsize>(produced));
        if (!sink->good()) {
          errorMsg = "failed writing compressed data to the output stream";
          ok = false;
          break;
        }
      }
    } while (ret != Z_STREAM_END && ret != Z_STREAM_ERROR);

    if (ret == Z_STREAM_ERROR) {
      if (errorMsg.empty())
        errorMsg = "gzip compression error while finishing";
      ok = false;
    }

    deflateEnd(&zstream);
    zstreamOpen = false;
    sink->flush();
    return ok;
  }

  static la_ssize_t archiveWriteCallback(struct archive*, void* clientData,
                                         const void* buffer, std::size_t length)
  {
    auto* self = static_cast<CompressingStreamBufPrivate*>(clientData);
    self->sink->write(static_cast<const char*>(buffer),
                      static_cast<std::streamsize>(length));
    if (!self->sink->good()) {
      self->errorMsg = "failed writing compressed data to the output stream";
      return -1;
    }
    return static_cast<la_ssize_t>(length);
  }

  bool initArchiveWriter()
  {
    archiveHandle = archive_write_new();
    if (archiveHandle == nullptr) {
      errorMsg = "failed to create the libarchive writer";
      return false;
    }

    int filterResult = ARCHIVE_FATAL;
    switch (type) {
      case Compression::Bzip2:
        filterResult = archive_write_add_filter_bzip2(archiveHandle);
        break;
      case Compression::Xz:
        filterResult = archive_write_add_filter_xz(archiveHandle);
        break;
      case Compression::Zstd:
        filterResult = archive_write_add_filter_zstd(archiveHandle);
        break;
      default:
        errorMsg =
          compressionName(type) + " compression is not supported in this build";
        archive_write_free(archiveHandle);
        archiveHandle = nullptr;
        return false;
    }

    if (filterResult != ARCHIVE_OK) {
      errorMsg =
        compressionName(type) + " compression is not supported in this build";
      archive_write_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    archive_write_set_format_raw(archiveHandle);
    // Mandatory: without these, libarchive pads the final block to 10240
    // bytes (tar heritage), which corrupts small payloads and breaks
    // concatenation.
    archive_write_set_bytes_per_block(archiveHandle, 0);
    archive_write_set_bytes_in_last_block(archiveHandle, 1);

    if (archive_write_open(archiveHandle, this, nullptr, &archiveWriteCallback,
                           nullptr) != ARCHIVE_OK) {
      errorMsg = archiveError(archiveHandle, "write failed");
      archive_write_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, "data");
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    // archive_entry_set_size() is deliberately not called: the raw writer
    // streams data and does not require a declared size.
    int headerResult = archive_write_header(archiveHandle, entry);
    archive_entry_free(entry);
    if (headerResult != ARCHIVE_OK) {
      errorMsg = archiveError(archiveHandle, "write failed");
      archive_write_free(archiveHandle);
      archiveHandle = nullptr;
      return false;
    }

    return true;
  }

  bool writeArchive(const char* data, std::size_t len)
  {
    std::size_t written = 0;
    while (written < len) {
      la_ssize_t n =
        archive_write_data(archiveHandle, data + written, len - written);
      if (n < 0) {
        if (errorMsg.empty())
          errorMsg = archiveError(archiveHandle, "write failed");
        return false;
      }
      if (n == 0) {
        errorMsg = "libarchive: write stalled";
        return false;
      }
      written += static_cast<std::size_t>(n);
    }
    return true;
  }

  bool finishArchive()
  {
    if (archiveHandle == nullptr)
      return errorMsg.empty();

    bool ok = true;
    if (archive_write_close(archiveHandle) != ARCHIVE_OK) {
      if (errorMsg.empty())
        errorMsg = archiveError(archiveHandle, "write failed");
      ok = false;
    }
    archive_write_free(archiveHandle);
    archiveHandle = nullptr;
    sink->flush();
    return ok;
  }
#endif // AVO_USE_LIBARCHIVE

  std::unique_ptr<std::ostream> sink;
  Compression type;
  bool initialized = false;
  bool finished = false;
  std::string errorMsg;

  // The streambuf's put area lives here (rather than as a data member of the
  // public CompressingStreamBuf class) so the public header's class layout
  // never needs to change.
  static constexpr std::size_t kPutBufferSize = 65536;
  char putBuffer[kPutBufferSize];

#ifdef AVO_USE_LIBARCHIVE
  z_stream zstream{};
  bool zstreamOpen = false;

  struct archive* archiveHandle = nullptr;
#endif
};

// ============================================================================
// CompressingStreamBuf
// ============================================================================

CompressingStreamBuf::CompressingStreamBuf(std::unique_ptr<std::ostream> sink,
                                           Compression type)
  : d(new CompressingStreamBufPrivate(std::move(sink), type))
{
  setp(d->putBuffer, d->putBuffer + sizeof(d->putBuffer));
}

CompressingStreamBuf::~CompressingStreamBuf()
{
  finish();
}

std::string CompressingStreamBuf::error() const
{
  return d->errorMsg;
}

bool CompressingStreamBuf::flushPutArea()
{
  std::ptrdiff_t n = pptr() - pbase();
  bool ok = true;
  if (n > 0)
    ok = d->write(pbase(), static_cast<std::size_t>(n));
  setp(d->putBuffer, d->putBuffer + sizeof(d->putBuffer));
  return ok;
}

CompressingStreamBuf::int_type CompressingStreamBuf::overflow(int_type ch)
{
  if (!flushPutArea())
    return traits_type::eof();

  if (!traits_type::eq_int_type(ch, traits_type::eof())) {
    *pptr() = traits_type::to_char_type(ch);
    pbump(1);
  }
  return traits_type::not_eof(ch);
}

std::streamsize CompressingStreamBuf::xsputn(const char* s,
                                             std::streamsize count)
{
  std::streamsize total = 0;
  while (total < count) {
    std::ptrdiff_t space = epptr() - pptr();
    std::streamsize chunk = std::min<std::streamsize>(space, count - total);
    if (chunk > 0) {
      std::memcpy(pptr(), s + total, static_cast<std::size_t>(chunk));
      pbump(static_cast<int>(chunk));
      total += chunk;
    }
    if (total < count) {
      if (!flushPutArea())
        break;
    }
  }
  return total;
}

int CompressingStreamBuf::sync()
{
  return flushPutArea() ? 0 : -1;
}

bool CompressingStreamBuf::finish()
{
  if (d->finished)
    return d->errorMsg.empty();

  bool flushOk = flushPutArea();
  bool codecOk = d->finishCodec();
  d->finished = true;
  return flushOk && codecOk;
}

// ============================================================================
// CompressingOStream
// ============================================================================

CompressingOStream::CompressingOStream(std::unique_ptr<std::ostream> sink,
                                       Compression type)
  : std::ostream(&m_buf), m_buf(std::move(sink), type)
{
}

CompressingOStream::~CompressingOStream() = default;

// ============================================================================
// wrapIfCompressed
// ============================================================================

std::unique_ptr<std::istream> wrapIfCompressed(
  std::unique_ptr<std::istream> source, std::string& error,
  std::uint64_t maxDecodedSize)
{
  error.clear();

  char magic[compressionMagicSize];
  source->read(magic, sizeof(magic));
  std::streamsize n = source->gcount();
  Compression type =
    detectCompression(magic, static_cast<std::size_t>(n < 0 ? 0 : n));

  // Rewind: the source is a fresh ifstream/istringstream, hence seekable.
  source->clear();
  source->seekg(0);

  if (type == Compression::None) {
    source->imbue(std::locale::classic());
    return source;
  }

  if (!compressionSupported(type)) {
    if (!compressionAvailable())
      error = "compressed files are not supported in this build";
    else
      error =
        compressionName(type) + " decompression is not supported in this build";
    return nullptr;
  }

  auto decompressed = std::unique_ptr<DecompressingIStream>(
    new DecompressingIStream(std::move(source), type, maxDecodedSize));
  decompressed->imbue(std::locale::classic());
  return decompressed;
}

} // namespace Avogadro::Io
