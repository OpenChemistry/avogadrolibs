/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_COMPRESSEDSTREAM_H
#define AVOGADRO_IO_COMPRESSEDSTREAM_H

#include "avogadroioexport.h"

#include "compression.h"

#include <cstdint>
#include <istream>
#include <memory>
#include <ostream>
#include <streambuf>
#include <string>

namespace Avogadro::Io {

/**
 * @brief The default ceiling on decompressed data, in bytes.
 *
 * A few kilobytes of gzip can expand to gigabytes, so a hostile or simply
 * broken file could otherwise exhaust memory while the application is doing
 * nothing more dangerous than opening a molecule. Raise or remove it per read
 * with the "maxDecompressedSize" file format option.
 */
constexpr std::uint64_t defaultMaxDecompressedSize = 2ULL * 1024 * 1024 * 1024;

class DecompressingStreamBufPrivate;
class CompressingStreamBufPrivate;

/**
 * @class DecompressingStreamBuf compressedstream.h
 * <avogadro/io/compressedstream.h>
 * @brief A stream buffer that decompresses another stream on demand.
 *
 * Decoded bytes are produced lazily, a block at a time, and every block is
 * retained, so the buffer is seekable in both directions even though the
 * underlying codecs are not. Seeking forward decodes as far as the target;
 * seeking to the end decodes everything. That matters because several readers
 * measure a file by seeking to its end (DCD and TRR take block lengths from
 * the file itself) and others rewind to re-read a record (MDL, Molden), so
 * they would not work against a forward only stream.
 *
 * The cost is memory: a reader that seeks to the end of a compressed
 * trajectory holds the whole decompressed trajectory. That is what the size
 * limit is for.
 */
class AVOGADROIO_EXPORT DecompressingStreamBuf : public std::streambuf
{
public:
  /**
   * @brief Wrap @a source, which must be positioned at the first byte.
   * @param source The compressed stream. Ownership is taken, and it is read
   * incrementally rather than all at once.
   * @param type The codec, as determined by detectCompression().
   * @param maxDecodedSize The ceiling on decoded bytes; 0 means no ceiling.
   */
  DecompressingStreamBuf(
    std::unique_ptr<std::istream> source, Compression type,
    std::uint64_t maxDecodedSize = defaultMaxDecompressedSize);
  ~DecompressingStreamBuf() override;

  DecompressingStreamBuf(const DecompressingStreamBuf&) = delete;
  DecompressingStreamBuf& operator=(const DecompressingStreamBuf&) = delete;

  /**
   * @brief The error encountered while decoding, if any.
   *
   * Empty while all is well. A truncated file, a failed integrity check or a
   * breach of the size limit all leave a message here. Callers must check this
   * after reading, because a decoding failure surfaces to the reader as an
   * ordinary end of stream, which most parsers treat as a short but valid
   * file.
   */
  std::string error() const;

  /** @return True if decoding stopped because the size limit was reached. */
  bool hitSizeLimit() const;

  /** @return The number of bytes decoded so far. */
  std::uint64_t decodedSize() const;

protected:
  int_type underflow() override;
  std::streamsize xsgetn(char* s, std::streamsize count) override;
  pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                   std::ios_base::openmode which = std::ios_base::in |
                                                   std::ios_base::out) override;
  pos_type seekpos(pos_type pos,
                   std::ios_base::openmode which = std::ios_base::in |
                                                   std::ios_base::out) override;

private:
  std::unique_ptr<DecompressingStreamBufPrivate> d;
};

/**
 * @class DecompressingIStream compressedstream.h
 * <avogadro/io/compressedstream.h>
 * @brief An input stream over compressed data.
 */
class AVOGADROIO_EXPORT DecompressingIStream : public std::istream
{
public:
  /**
   * @brief Decompress @a source.
   * @param source The compressed stream, positioned at its first byte.
   * Ownership is taken.
   * @param type The codec, as determined by detectCompression().
   * @param maxDecodedSize The ceiling on decoded bytes; 0 means no ceiling.
   */
  DecompressingIStream(
    std::unique_ptr<std::istream> source, Compression type,
    std::uint64_t maxDecodedSize = defaultMaxDecompressedSize);
  ~DecompressingIStream() override;

  /** @copydoc DecompressingStreamBuf::error() */
  std::string error() const { return m_buf.error(); }
  /** @copydoc DecompressingStreamBuf::hitSizeLimit() */
  bool hitSizeLimit() const { return m_buf.hitSizeLimit(); }
  /** @copydoc DecompressingStreamBuf::decodedSize() */
  std::uint64_t decodedSize() const { return m_buf.decodedSize(); }

private:
  DecompressingStreamBuf m_buf;
};

/**
 * @class CompressingStreamBuf compressedstream.h
 * <avogadro/io/compressedstream.h>
 * @brief A stream buffer that compresses into another stream.
 */
class AVOGADROIO_EXPORT CompressingStreamBuf : public std::streambuf
{
public:
  /**
   * @brief Compress everything written here into @a sink.
   * @param sink The stream to write compressed bytes to. Ownership is taken.
   * @param type The codec to encode with, which must not be
   * Compression::None.
   */
  CompressingStreamBuf(std::unique_ptr<std::ostream> sink, Compression type);
  ~CompressingStreamBuf() override;

  CompressingStreamBuf(const CompressingStreamBuf&) = delete;
  CompressingStreamBuf& operator=(const CompressingStreamBuf&) = delete;

  /**
   * @brief Flush the codec and write the trailer.
   *
   * Must happen before the sink is closed or the output is unreadable, so the
   * destructor calls this too. Calling it twice is harmless.
   *
   * @return True if the stream was finished cleanly.
   */
  bool finish();

  /** @return The error encountered while encoding, empty if none. */
  std::string error() const;

protected:
  int_type overflow(int_type ch = traits_type::eof()) override;
  std::streamsize xsputn(const char* s, std::streamsize count) override;
  int sync() override;

private:
  /**
   * Hand everything sitting in the put area to the codec and reset it. The
   * put area itself lives in the private implementation, but this has to be a
   * member here because it manipulates the protected streambuf pointers.
   * @return False once the codec has failed; see error().
   */
  bool flushPutArea();

  std::unique_ptr<CompressingStreamBufPrivate> d;
};

/**
 * @class CompressingOStream compressedstream.h
 * <avogadro/io/compressedstream.h>
 * @brief An output stream that compresses what is written to it.
 */
class AVOGADROIO_EXPORT CompressingOStream : public std::ostream
{
public:
  /**
   * @brief Compress into @a sink using @a type.
   * @param sink The stream to write compressed bytes to. Ownership is taken.
   * @param type The codec to encode with, which must not be
   * Compression::None.
   */
  CompressingOStream(std::unique_ptr<std::ostream> sink, Compression type);
  ~CompressingOStream() override;

  /** @copydoc CompressingStreamBuf::finish() */
  bool finish() { return m_buf.finish(); }
  /** @copydoc CompressingStreamBuf::error() */
  std::string error() const { return m_buf.error(); }

private:
  CompressingStreamBuf m_buf;
};

/**
 * @brief Wrap @a source in a decompressor if it holds compressed data.
 *
 * The first bytes are read and matched against the known magic numbers. Plain
 * data is not copied or buffered: the same stream is handed back, rewound, so
 * the overwhelmingly common uncompressed case costs one small read.
 *
 * @param source The stream to examine, positioned at its first byte. Ownership
 * is taken in every case, including failure.
 * @param error Set to a message when the data is compressed with a codec this
 * build cannot decode, and cleared otherwise.
 * @param maxDecodedSize The ceiling on decoded bytes; 0 means no ceiling.
 * @return The stream to read from, or nullptr when @a error was set.
 */
AVOGADROIO_EXPORT std::unique_ptr<std::istream> wrapIfCompressed(
  std::unique_ptr<std::istream> source, std::string& error,
  std::uint64_t maxDecodedSize = defaultMaxDecompressedSize);

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_COMPRESSEDSTREAM_H
