/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/io/compressedstream.h>
#include <avogadro/io/compression.h>

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/io/sdfformat.h>
#include <avogadro/io/xyzformat.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using Avogadro::Core::Molecule;
using Avogadro::Io::CompressingOStream;
using Avogadro::Io::Compression;
using Avogadro::Io::compressionAvailable;
using Avogadro::Io::compressionExtension;
using Avogadro::Io::compressionExtensions;
using Avogadro::Io::compressionFromExtension;
using Avogadro::Io::compressionMagicSize;
using Avogadro::Io::compressionName;
using Avogadro::Io::compressionSupported;
using Avogadro::Io::DecompressingIStream;
using Avogadro::Io::defaultMaxDecompressedSize;
using Avogadro::Io::detectCompression;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using Avogadro::Io::PdbFormat;
using Avogadro::Io::SdfFormat;
using Avogadro::Io::stripCompressionSuffix;
using Avogadro::Io::wrapIfCompressed;
using Avogadro::Io::XyzFormat;

namespace {

const std::string kCompressedDir =
  std::string(AVOGADRO_DATA) + "/data/compressed/";
const std::string kXyzDir = std::string(AVOGADRO_DATA) + "/data/xyz/";

std::string slurpFile(const std::string& path)
{
  std::ifstream f(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(f),
                     std::istreambuf_iterator<char>());
}

std::string slurpStream(std::istream& in)
{
  return std::string(std::istreambuf_iterator<char>(in),
                     std::istreambuf_iterator<char>());
}

// Opens a fixture (or any path) through wrapIfCompressed(). On failure the
// returned pointer is null and *error explains why.
std::unique_ptr<std::istream> openWrapped(
  const std::string& path, std::string* error,
  std::uint64_t maxDecodedSize = defaultMaxDecompressedSize)
{
  auto source =
    std::unique_ptr<std::istream>(new std::ifstream(path, std::ios::binary));
  return wrapIfCompressed(std::move(source), *error, maxDecodedSize);
}

// A small deterministic PRNG (Numerical Recipes LCG) so payloads are
// reproducible across runs without needing to ship large fixtures.
std::string pseudoRandomPayload(std::size_t length, unsigned seed = 12345u)
{
  std::string data;
  data.reserve(length);
  unsigned x = seed;
  for (std::size_t i = 0; i < length; ++i) {
    x = x * 1103515245u + 12345u;
    data.push_back(static_cast<char>((x >> 16) & 0xff));
  }
  return data;
}

// A payload that compresses extremely well: a short phrase repeated.
std::string compressiblePayload(std::size_t length)
{
  std::string data;
  data.reserve(length + 64);
  const std::string phrase = "The quick brown fox jumps over the lazy dog. ";
  while (data.size() < length)
    data += phrase;
  data.resize(length);
  return data;
}

bool commandAvailable(const std::string& name)
{
  std::string probe = "command -v " + name + " > /dev/null 2>&1";
  return std::system(probe.c_str()) == 0;
}

// Compresses payload with CompressingOStream using writes of the given slice
// size (0 means "write it all in a single call"). Returns the compressed
// bytes. Reading the underlying ostringstream while cs is still alive is
// fine because finish() has already been called -- see compressedstream.h.
std::string compress(const std::string& payload, Compression type,
                     std::size_t sliceSize)
{
  auto sink = std::unique_ptr<std::ostream>(new std::ostringstream());
  auto* rawSink = static_cast<std::ostringstream*>(sink.get());
  CompressingOStream cs(std::move(sink), type);

  std::size_t step =
    (sliceSize == 0) ? std::max<std::size_t>(payload.size(), 1) : sliceSize;
  for (std::size_t pos = 0; pos < payload.size(); pos += step) {
    std::size_t n = std::min(step, payload.size() - pos);
    cs.write(payload.data() + static_cast<std::ptrdiff_t>(pos),
             static_cast<std::streamsize>(n));
  }
  EXPECT_TRUE(cs.finish());
  EXPECT_TRUE(cs.error().empty());
  return rawSink->str();
}

std::string decode(const std::string& compressed, Compression type,
                   std::string* error, std::uint64_t maxDecodedSize = 0)
{
  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream in(std::move(source), type, maxDecodedSize);
  std::string out = slurpStream(in);
  *error = in.error();
  return out;
}

const std::string kPdbDir = std::string(AVOGADRO_DATA) + "/data/pdb/";
const std::string kSdfDir = std::string(AVOGADRO_DATA) + "/data/sdf/";

// Detects the codec from a file's leading bytes, for checking that a written
// file really starts with the expected magic number.
Compression fileMagic(const std::string& path)
{
  std::ifstream f(path, std::ios::binary);
  char magic[compressionMagicSize] = {};
  f.read(magic, sizeof(magic));
  auto n = f.gcount();
  return detectCompression(magic, static_cast<std::size_t>(n < 0 ? 0 : n));
}

// Atom-by-atom comparison used to prove a molecule read from compressed data
// matches the same molecule read from its uncompressed reference file.
void expectMoleculesMatch(const Molecule& a, const Molecule& b)
{
  ASSERT_EQ(a.atomCount(), b.atomCount());
  for (Avogadro::Index i = 0; i < a.atomCount(); ++i) {
    SCOPED_TRACE(i);
    EXPECT_EQ(a.atom(i).atomicNumber(), b.atom(i).atomicNumber());
    EXPECT_DOUBLE_EQ(a.atom(i).position3d().x(), b.atom(i).position3d().x());
    EXPECT_DOUBLE_EQ(a.atom(i).position3d().y(), b.atom(i).position3d().y());
    EXPECT_DOUBLE_EQ(a.atom(i).position3d().z(), b.atom(i).position3d().z());
  }
}

} // namespace

// ============================================================================
// 1. compressionFromExtension / compressionExtension / compressionName /
//    compressionExtensions
// ============================================================================

TEST(CompressionTest, ExtensionRoundTrip)
{
  EXPECT_EQ(compressionFromExtension("gz"), Compression::Gzip);
  EXPECT_EQ(compressionFromExtension("bz2"), Compression::Bzip2);
  EXPECT_EQ(compressionFromExtension("xz"), Compression::Xz);
  EXPECT_EQ(compressionFromExtension("zst"), Compression::Zstd);
  EXPECT_EQ(compressionFromExtension("zstd"), Compression::Zstd);

  // Case insensitivity.
  EXPECT_EQ(compressionFromExtension("GZ"), Compression::Gzip);
  EXPECT_EQ(compressionFromExtension("Bz2"), Compression::Bzip2);
  EXPECT_EQ(compressionFromExtension("Xz"), Compression::Xz);
  EXPECT_EQ(compressionFromExtension("ZST"), Compression::Zstd);
  EXPECT_EQ(compressionFromExtension("ZsTd"), Compression::Zstd);

  // Unknown / empty extensions.
  EXPECT_EQ(compressionFromExtension(""), Compression::None);
  EXPECT_EQ(compressionFromExtension("tar"), Compression::None);
  EXPECT_EQ(compressionFromExtension("zip"), Compression::None);
  EXPECT_EQ(compressionFromExtension("xyz"), Compression::None);

  // compressionExtension() round trips back to the canonical (lower case,
  // "zst" not "zstd") spelling.
  EXPECT_EQ(compressionExtension(Compression::Gzip), "gz");
  EXPECT_EQ(compressionExtension(Compression::Bzip2), "bz2");
  EXPECT_EQ(compressionExtension(Compression::Xz), "xz");
  EXPECT_EQ(compressionExtension(Compression::Zstd), "zst");
  EXPECT_EQ(compressionExtension(Compression::None), "");

  for (Compression type : { Compression::Gzip, Compression::Bzip2,
                            Compression::Xz, Compression::Zstd }) {
    EXPECT_EQ(compressionFromExtension(compressionExtension(type)), type);
  }

  // Human readable names.
  EXPECT_EQ(compressionName(Compression::Gzip), "gzip");
  EXPECT_EQ(compressionName(Compression::Bzip2), "bzip2");
  EXPECT_EQ(compressionName(Compression::Xz), "xz");
  EXPECT_EQ(compressionName(Compression::Zstd), "zstd");
  EXPECT_EQ(compressionName(Compression::None), "");
}

TEST(CompressionTest, CompressionExtensionsList)
{
  std::vector<std::string> extensions = compressionExtensions();
  // Every extension in the list must be recognized, and both "zst" and
  // "zstd" must be present since the caller (file dialog filters) needs both
  // spellings offered even though they map to the same codec.
  for (const auto& ext : extensions)
    EXPECT_NE(compressionFromExtension(ext), Compression::None) << ext;

  auto contains = [&](const std::string& ext) {
    return std::find(extensions.begin(), extensions.end(), ext) !=
           extensions.end();
  };
  EXPECT_TRUE(contains("gz"));
  EXPECT_TRUE(contains("bz2"));
  EXPECT_TRUE(contains("xz"));
  EXPECT_TRUE(contains("zst"));
  EXPECT_TRUE(contains("zstd"));
}

// ============================================================================
// 2. stripCompressionSuffix
// ============================================================================

TEST(CompressionTest, StripCompressionSuffix)
{
  Compression type;

  EXPECT_EQ(stripCompressionSuffix("a.xyz.gz", &type), "a.xyz");
  EXPECT_EQ(type, Compression::Gzip);

  // Only the final extension is considered.
  EXPECT_EQ(stripCompressionSuffix("a.tar.gz", &type), "a.tar");
  EXPECT_EQ(type, Compression::Gzip);

  EXPECT_EQ(stripCompressionSuffix("a.gz", &type), "a");
  EXPECT_EQ(type, Compression::Gzip);

  // Not a compression extension: unchanged, type reset to None.
  EXPECT_EQ(stripCompressionSuffix("a.xyz", &type), "a.xyz");
  EXPECT_EQ(type, Compression::None);

  // Case insensitive on the extension; the stem keeps its original case.
  EXPECT_EQ(stripCompressionSuffix("A.XYZ.GZ", &type), "A.XYZ");
  EXPECT_EQ(type, Compression::Gzip);

  // A dot in a directory component must not be mistaken for the extension.
  // Here the final component's own extension (.xyz) is not a compression
  // suffix, so the whole path is returned unchanged despite the earlier dot
  // in "v1.2".
  EXPECT_EQ(stripCompressionSuffix("/opt/v1.2/water.xyz", &type),
            "/opt/v1.2/water.xyz");
  EXPECT_EQ(type, Compression::None);

  // Same directory structure, but this time the final component really is
  // compressed: the directory's dot must still be ignored.
  EXPECT_EQ(stripCompressionSuffix("/opt/v1.2/water.gz", &type),
            "/opt/v1.2/water");
  EXPECT_EQ(type, Compression::Gzip);

  // No dot in a directory component either -- the lone dot in "v1.2" sits
  // before the final path separator and must not be treated as an extension.
  EXPECT_EQ(stripCompressionSuffix("/opt/v1.2/water", &type),
            "/opt/v1.2/water");
  EXPECT_EQ(type, Compression::None);

  // No dot anywhere.
  EXPECT_EQ(stripCompressionSuffix("water", &type), "water");
  EXPECT_EQ(type, Compression::None);

  // A dotfile with no extension at all (the dot is the first character of
  // the base name) is deliberately left unchanged.
  EXPECT_EQ(stripCompressionSuffix(".gz", &type), ".gz");
  EXPECT_EQ(type, Compression::None);

  // Both path separator styles.
  EXPECT_EQ(stripCompressionSuffix("dir/sub/water.xyz.gz", &type),
            "dir/sub/water.xyz");
  EXPECT_EQ(type, Compression::Gzip);
  EXPECT_EQ(stripCompressionSuffix("C:\\Users\\geoff\\water.xyz.gz", &type),
            "C:\\Users\\geoff\\water.xyz");
  EXPECT_EQ(type, Compression::Gzip);

  // The type out-parameter is optional.
  EXPECT_EQ(stripCompressionSuffix("a.xyz.gz"), "a.xyz");
  EXPECT_EQ(stripCompressionSuffix("a.xyz"), "a.xyz");
}

// ============================================================================
// 3. detectCompression
// ============================================================================

TEST(CompressionTest, DetectCompressionMagics)
{
  const char gzip[] = { '\x1f', '\x8b', '\x08', 0, 0, 0 };
  const char bzip2[] = { 'B', 'Z', 'h', '1', 0, 0 };
  const char xz[] = { '\xfd', '7', 'z', 'X', 'Z', 0 };
  const char zstd[] = { '\x28', '\xb5', '\x2f', '\xfd', 0, 0 };

  EXPECT_EQ(detectCompression(gzip, sizeof(gzip)), Compression::Gzip);
  EXPECT_EQ(detectCompression(bzip2, sizeof(bzip2)), Compression::Bzip2);
  EXPECT_EQ(detectCompression(xz, sizeof(xz)), Compression::Xz);
  EXPECT_EQ(detectCompression(zstd, sizeof(zstd)), Compression::Zstd);

  // bzip2 accepts any block-size digit '1'-'9'.
  for (char digit = '1'; digit <= '9'; ++digit) {
    char buf[4] = { 'B', 'Z', 'h', digit };
    EXPECT_EQ(detectCompression(buf, sizeof(buf)), Compression::Bzip2) << digit;
  }

  // compressionMagicSize must be enough to identify every codec.
  EXPECT_GE(compressionMagicSize, static_cast<std::size_t>(6));
}

TEST(CompressionTest, DetectCompressionNearMisses)
{
  // gzip requires compression method 0x08 in the third byte.
  const char notGzip[] = { '\x1f', '\x8b', '\x07', 0, 0, 0 };
  EXPECT_EQ(detectCompression(notGzip, sizeof(notGzip)), Compression::None);

  // bzip2 requires a block-size digit '1'-'9' in the fourth byte.
  const char bzipZero[] = { 'B', 'Z', 'h', '0' };
  EXPECT_EQ(detectCompression(bzipZero, sizeof(bzipZero)), Compression::None);
  const char bzipLetter[] = { 'B', 'Z', 'h', 'x' };
  EXPECT_EQ(detectCompression(bzipLetter, sizeof(bzipLetter)),
            Compression::None);

  // zstd requires 0xfd as the fourth byte, not 0xfc.
  const char notZstd[] = { '\x28', '\xb5', '\x2f', '\xfc' };
  EXPECT_EQ(detectCompression(notZstd, sizeof(notZstd)), Compression::None);

  // Ordinary text.
  const std::string text = "not compressed at all";
  EXPECT_EQ(detectCompression(text.data(), text.size()), Compression::None);
}

TEST(CompressionTest, DetectCompressionShortBuffers)
{
  const char gzip[] = { '\x1f', '\x8b', '\x08', 0, 0, 0 };
  const char bzip2[] = { 'B', 'Z', 'h', '1', 0, 0 };
  const char xz[] = { '\xfd', '7', 'z', 'X', 'Z', 0 };
  const char zstd[] = { '\x28', '\xb5', '\x2f', '\xfd', 0, 0 };

  for (std::size_t len = 0; len <= 5; ++len) {
    SCOPED_TRACE(len);
    EXPECT_EQ(detectCompression(gzip, len),
              len >= 3 ? Compression::Gzip : Compression::None);
    EXPECT_EQ(detectCompression(bzip2, len),
              len >= 4 ? Compression::Bzip2 : Compression::None);
    // xz needs all 6 magic bytes, so every length in 0..5 must be None: this
    // is the important boundary, proving a partial magic is never accepted.
    EXPECT_EQ(detectCompression(xz, len), Compression::None);
    EXPECT_EQ(detectCompression(zstd, len),
              len >= 4 ? Compression::Zstd : Compression::None);
  }
}

TEST(CompressionTest, DetectCompressionNullPointer)
{
  EXPECT_EQ(detectCompression(nullptr, 0), Compression::None);
  EXPECT_EQ(detectCompression(nullptr, 10), Compression::None);
}

// ============================================================================
// 4. Each methane.xyz.<codec> decodes byte for byte to methane.xyz
// ============================================================================

TEST(CompressionTest, DecodeMethaneFullSlurpAllCodecs)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const std::string methane = slurpFile(kXyzDir + "methane.xyz");
  const struct
  {
    const char* fixture;
    Compression type;
  } cases[] = { { "methane.xyz.gz", Compression::Gzip },
                { "methane.xyz.bz2", Compression::Bzip2 },
                { "methane.xyz.xz", Compression::Xz },
                { "methane.xyz.zst", Compression::Zstd } };

  for (const auto& c : cases) {
    SCOPED_TRACE(c.fixture);
    if (!compressionSupported(c.type)) {
      // Documented limitation of this build (e.g. xz without liblzma); see
      // the class-level comment on compressionSupported().
      continue;
    }
    std::string error;
    auto stream = openWrapped(kCompressedDir + c.fixture, &error);
    ASSERT_NE(stream, nullptr) << error;
    auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
    ASSERT_NE(decompressing, nullptr);
    std::string got = slurpStream(*stream);
    EXPECT_TRUE(decompressing->error().empty()) << decompressing->error();
    EXPECT_EQ(got, methane);
  }
}

TEST(CompressionTest, DecodeMethaneGetlineLoopAllCodecs)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const std::string methane = slurpFile(kXyzDir + "methane.xyz");
  const struct
  {
    const char* fixture;
    Compression type;
  } cases[] = { { "methane.xyz.gz", Compression::Gzip },
                { "methane.xyz.bz2", Compression::Bzip2 },
                { "methane.xyz.xz", Compression::Xz },
                { "methane.xyz.zst", Compression::Zstd } };

  for (const auto& c : cases) {
    SCOPED_TRACE(c.fixture);
    if (!compressionSupported(c.type))
      continue;

    std::string error;
    auto stream = openWrapped(kCompressedDir + c.fixture, &error);
    ASSERT_NE(stream, nullptr) << error;

    std::istringstream reference(methane);
    std::string gotLine, refLine;
    int lineNumber = 0;
    while (std::getline(reference, refLine)) {
      ++lineNumber;
      ASSERT_TRUE(static_cast<bool>(std::getline(*stream, gotLine)))
        << "missing line " << lineNumber;
      EXPECT_EQ(gotLine, refLine) << "line " << lineNumber;
    }
    // The decoded stream must not have extra lines beyond the reference.
    EXPECT_FALSE(static_cast<bool>(std::getline(*stream, gotLine)))
      << "unexpected extra line: " << gotLine;
  }
}

TEST(CompressionTest, DecodeMethaneNamedGzipHeader)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  // gzip -N stores the original file name and mtime in the header; that
  // metadata must be ignored and the payload decoded normally.
  const std::string methane = slurpFile(kXyzDir + "methane.xyz");
  std::string error;
  auto stream = openWrapped(kCompressedDir + "methane-named.xyz.gz", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_EQ(slurpStream(*stream), methane);
}

// ============================================================================
// 5. multi-members.xyz.<codec> decodes to methane.xyz followed by H2O.xyz
// ============================================================================

TEST(CompressionTest, MultiMembersConcatenation)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const std::string expected =
    slurpFile(kXyzDir + "methane.xyz") + slurpFile(kXyzDir + "H2O.xyz");

  const struct
  {
    const char* fixture;
    Compression type;
  } cases[] = { { "multi-members.xyz.gz", Compression::Gzip },
                { "multi-members.xyz.bz2", Compression::Bzip2 },
                { "multi-members.xyz.xz", Compression::Xz },
                { "multi-members.xyz.zst", Compression::Zstd } };

  for (const auto& c : cases) {
    SCOPED_TRACE(c.fixture);
    if (!compressionSupported(c.type))
      continue;

    std::string error;
    auto stream = openWrapped(kCompressedDir + c.fixture, &error);
    ASSERT_NE(stream, nullptr) << error;
    auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
    ASSERT_NE(decompressing, nullptr);
    // Gzip in particular must not stop after decoding only the first member:
    // `cat a.gz b.gz` is a legal, common gzip stream.
    std::string got = slurpStream(*stream);
    EXPECT_TRUE(decompressing->error().empty()) << decompressing->error();
    EXPECT_EQ(got, expected);
  }
}

// ============================================================================
// 6. misnamed.xyz is detected as gzip from content despite the plain name
// ============================================================================

TEST(CompressionTest, MisnamedGzipDetectedByContent)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const std::string methane = slurpFile(kXyzDir + "methane.xyz");
  std::string error;
  auto stream = openWrapped(kCompressedDir + "misnamed.xyz", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_NE(dynamic_cast<DecompressingIStream*>(stream.get()), nullptr)
    << "content sniffing should have wrapped this file despite its name";
  EXPECT_EQ(slurpStream(*stream), methane);
}

// ============================================================================
// 7. A plain uncompressed file passes through wrapIfCompressed unwrapped
// ============================================================================

TEST(CompressionTest, PlainFilePassesThroughUnwrapped)
{
  const std::string methane = slurpFile(kXyzDir + "methane.xyz");
  std::string error;
  auto stream = openWrapped(kXyzDir + "methane.xyz", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_TRUE(error.empty());
  EXPECT_EQ(dynamic_cast<DecompressingIStream*>(stream.get()), nullptr)
    << "a plain file must not be wrapped in a decompressor";
  EXPECT_EQ(slurpStream(*stream), methane);
}

// ============================================================================
// 8. Damaged input must produce a non-empty error()
// ============================================================================

TEST(CompressionTest, TruncatedInputsReportError)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const struct
  {
    const char* fixture;
    Compression type;
  } cases[] = { { "truncated.xyz.gz", Compression::Gzip },
                { "truncated.xyz.xz", Compression::Xz },
                { "truncated.xyz.zst", Compression::Zstd } };

  for (const auto& c : cases) {
    SCOPED_TRACE(c.fixture);
    if (!compressionSupported(c.type))
      continue;

    std::string error;
    auto stream = openWrapped(kCompressedDir + c.fixture, &error);
    ASSERT_NE(stream, nullptr) << error;
    auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
    ASSERT_NE(decompressing, nullptr);
    slurpStream(*stream);
    EXPECT_FALSE(decompressing->error().empty())
      << c.fixture << " decoded without reporting an error";
  }
}

TEST(CompressionTest, MagicOnlyGzipReportsError)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  // Gzip magic followed by bytes that are not a valid deflate stream.
  std::string error;
  auto stream = openWrapped(kCompressedDir + "magic-only.gz", &error);
  ASSERT_NE(stream, nullptr) << error;
  auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
  ASSERT_NE(decompressing, nullptr);
  slurpStream(*stream);
  EXPECT_FALSE(decompressing->error().empty());
}

// corrupt.xyz.gz has a single bit flipped well inside the deflate body of an
// otherwise well-formed gzip stream. libarchive's own bzip2/xz/zstd filters
// do not verify a whole-stream checksum the way gzip's trailer CRC32 does,
// so a corruption like this could silently decode to slightly wrong bytes
// under those filters. That is exactly why gzip is decoded with zlib
// directly instead of through libarchive: zlib validates the CRC32 in the
// gzip trailer against what it actually inflated, and must reject this file.
TEST(CompressionTest, CorruptGzipCaughtByCrc)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string error;
  auto stream = openWrapped(kCompressedDir + "corrupt.xyz.gz", &error);
  ASSERT_NE(stream, nullptr) << error;
  auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
  ASSERT_NE(decompressing, nullptr);
  slurpStream(*stream);
  EXPECT_FALSE(decompressing->error().empty())
    << "a single flipped bit in the gzip body must be caught, either by the "
       "deflate decoder itself or by the trailer's CRC32";
}

// ============================================================================
// 9. empty.xyz.gz yields zero bytes with an empty error()
// ============================================================================

TEST(CompressionTest, EmptyGzipDecodesToZeroBytes)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string error;
  auto stream = openWrapped(kCompressedDir + "empty.xyz.gz", &error);
  ASSERT_NE(stream, nullptr) << error;
  auto* decompressing = dynamic_cast<DecompressingIStream*>(stream.get());
  ASSERT_NE(decompressing, nullptr);
  std::string got = slurpStream(*stream);
  EXPECT_TRUE(got.empty());
  EXPECT_TRUE(decompressing->error().empty());
}

// ============================================================================
// 10. Size cap
// ============================================================================

TEST(CompressionTest, SizeCapStopsAtLimit)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  auto source = std::unique_ptr<std::istream>(
    new std::ifstream(kCompressedDir + "zeros-4mib.gz", std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 65536);
  slurpStream(stream);
  EXPECT_TRUE(stream.hitSizeLimit());
  EXPECT_FALSE(stream.error().empty());
  EXPECT_NE(stream.error().find("maxDecompressedSize"), std::string::npos)
    << stream.error();
}

TEST(CompressionTest, SizeCapUnlimitedDecodesFullPayload)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  auto source = std::unique_ptr<std::istream>(
    new std::ifstream(kCompressedDir + "zeros-4mib.gz", std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);
  std::string got = slurpStream(stream);
  EXPECT_EQ(got.size(), static_cast<std::size_t>(4194304));
  EXPECT_TRUE(stream.error().empty());
  EXPECT_FALSE(stream.hitSizeLimit());
}

// ============================================================================
// 11. Seeking
// ============================================================================

namespace {

// ~3 MiB compressed in-test so decoding spans many 64 KiB chunks
// (DecompressingStreamBufPrivate::kChunkSize).
std::string seekTestPayload()
{
  return pseudoRandomPayload(3u * 1024 * 1024, 987654321u);
}

std::string seekTestCompressed(const std::string& payload)
{
  return compress(payload, Compression::Gzip, 0);
}

} // namespace

TEST(CompressionTest, SeekToEndGivesTrueSize)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);
  stream.seekg(0, std::ios::end);
  EXPECT_EQ(static_cast<std::uint64_t>(stream.tellg()), payload.size());
}

TEST(CompressionTest, SeekAbsolutePositionsAcrossChunks)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);

  const std::size_t positions[] = { 0,     1,     65535,
                                    65536, 65537, payload.size() - 8 };
  for (std::size_t pos : positions) {
    SCOPED_TRACE(pos);
    stream.clear();
    stream.seekg(static_cast<std::streamoff>(pos));
    char buf[8];
    stream.read(buf, sizeof(buf));
    ASSERT_EQ(stream.gcount(), 8);
    EXPECT_EQ(std::string(buf, 8), payload.substr(pos, 8));
  }
}

TEST(CompressionTest, SeekRelativeToCurrent)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);

  stream.seekg(100);
  stream.seekg(50, std::ios::cur); // now at 150
  char forward[4];
  stream.read(forward, sizeof(forward));
  ASSERT_EQ(stream.gcount(), 4);
  EXPECT_EQ(std::string(forward, 4), payload.substr(150, 4));

  stream.clear();
  stream.seekg(-100, std::ios::cur); // 154 - 100 = 54
  char backward[4];
  stream.read(backward, sizeof(backward));
  ASSERT_EQ(stream.gcount(), 4);
  EXPECT_EQ(std::string(backward, 4), payload.substr(54, 4));
}

TEST(CompressionTest, SeekPastEndFails)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);
  stream.seekg(static_cast<std::streamoff>(payload.size() + 1000));
  EXPECT_TRUE(stream.fail());
}

TEST(CompressionTest, TellgAfterGetline)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);
  // The pseudo-random payload is long enough that a '\n' byte (1/256 chance
  // per byte) is certain to appear well before the end.
  ASSERT_NE(payload.find('\n'), std::string::npos);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);
  std::string line;
  ASSERT_TRUE(static_cast<bool>(std::getline(stream, line)));
  // getline() consumes the line plus the delimiter it stopped on.
  EXPECT_EQ(static_cast<std::uint64_t>(stream.tellg()), line.size() + 1);
}

TEST(CompressionTest, SeekToEndThenRewindReadsAll)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string payload = seekTestPayload();
  std::string compressed = seekTestCompressed(payload);

  auto source = std::unique_ptr<std::istream>(
    new std::istringstream(compressed, std::ios::binary));
  DecompressingIStream stream(std::move(source), Compression::Gzip, 0);
  stream.seekg(0, std::ios::end);
  stream.seekg(0);
  std::string all = slurpStream(stream);
  EXPECT_EQ(all, payload);
}

// ============================================================================
// 12. Write path, for every supported codec
// ============================================================================

namespace {

void expectWriteRoundTrip(Compression type)
{
  if (!compressionSupported(type)) {
    GTEST_SKIP() << compressionName(type) << " is not supported in this build";
  }

  // Crossing a few of the decoder's 64 KiB chunk boundaries is all the sliced
  // write cases need in order to exercise the buffer seams, so they use a
  // 192 KiB payload rather than a megabyte. The megabyte runs as a single
  // write only: it adds little beyond the smaller sizes, and it is what made
  // bzip2, far the slowest codec here, dominate the whole suite's runtime.
  constexpr std::size_t kSpansChunks = 192 * 1024;
  constexpr std::size_t kLarge = 1u << 20;
  const std::size_t lengths[] = { 0, 7, kSpansChunks, kLarge };
  const std::size_t slices[] = { 1, 13, 65537, 0 }; // 0 == single call

  for (std::size_t len : lengths) {
    // Compressible and incompressible data take different paths through every
    // codec, so the sizes big enough to matter try both.
    std::vector<std::string> payloads;
    payloads.push_back(pseudoRandomPayload(len));
    if (len == kSpansChunks)
      payloads.push_back(compressiblePayload(len));

    for (const std::string& payload : payloads) {
      for (std::size_t slice : slices) {
        // A slice size of 1 would mean a million-plus write() calls on the
        // larger payloads; only exercise it for the small ones.
        if (slice == 1 && len > 4096)
          continue;
        if (len == kLarge && slice != 0)
          continue;

        SCOPED_TRACE(::testing::Message()
                     << "len=" << len << " slice=" << slice);
        std::string encoded = compress(payload, type, slice);

        ASSERT_FALSE(encoded.empty() && !payload.empty());
        if (!encoded.empty()) {
          Compression detected = detectCompression(
            encoded.data(), std::min(encoded.size(), compressionMagicSize));
          EXPECT_EQ(detected, type)
            << "encoded output does not start with the expected magic bytes";
        }

        std::string error;
        std::string decoded = decode(encoded, type, &error);
        EXPECT_TRUE(error.empty()) << error;
        EXPECT_EQ(decoded, payload);
      }
    }
  }
}

} // namespace

TEST(CompressionTest, WriteRoundTripGzip)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectWriteRoundTrip(Compression::Gzip);
}

TEST(CompressionTest, WriteRoundTripBzip2)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectWriteRoundTrip(Compression::Bzip2);
}

TEST(CompressionTest, WriteRoundTripXz)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectWriteRoundTrip(Compression::Xz);
}

TEST(CompressionTest, WriteRoundTripZstd)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectWriteRoundTrip(Compression::Zstd);
}

// ============================================================================
// 13. Destruction without finish() still produces a decodable stream
// ============================================================================

namespace {

void expectDestructorWritesTrailerWithoutFinish(Compression type)
{
  if (!compressionSupported(type)) {
    GTEST_SKIP() << compressionName(type) << " is not supported in this build";
  }

  // CompressingOStream owns its sink, so we cannot keep a raw pointer to an
  // owned ostringstream and read it after the stream is destroyed -- that
  // would be a use-after-free. Route through a real file instead: the point
  // of this test is that destruction *alone* (no explicit finish()) still
  // writes the trailer and leaves the file readable.
  std::string path = ::testing::TempDir() + "avogadro-compression-test-" +
                     compressionName(type) + ".bin";
  {
    auto sink =
      std::unique_ptr<std::ostream>(new std::ofstream(path, std::ios::binary));
    CompressingOStream cs(std::move(sink), type);
    cs << "hello world";
    // cs goes out of scope here without finish() being called explicitly.
  }

  std::string encoded = slurpFile(path);
  std::remove(path.c_str());

  std::string error;
  std::string decoded = decode(encoded, type, &error);
  EXPECT_TRUE(error.empty()) << error;
  EXPECT_EQ(decoded, "hello world");
}

} // namespace

TEST(CompressionTest, DestructorWithoutFinishGzip)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectDestructorWritesTrailerWithoutFinish(Compression::Gzip);
}

TEST(CompressionTest, DestructorWithoutFinishBzip2)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectDestructorWritesTrailerWithoutFinish(Compression::Bzip2);
}

TEST(CompressionTest, DestructorWithoutFinishXz)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectDestructorWritesTrailerWithoutFinish(Compression::Xz);
}

TEST(CompressionTest, DestructorWithoutFinishZstd)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectDestructorWritesTrailerWithoutFinish(Compression::Zstd);
}

// ============================================================================
// 14. File round trip
// ============================================================================

TEST(CompressionTest, FileRoundTrip)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  const std::string payload = slurpFile(kXyzDir + "methane.xyz");

  for (Compression type : { Compression::Gzip, Compression::Bzip2,
                            Compression::Xz, Compression::Zstd }) {
    SCOPED_TRACE(compressionName(type));
    if (!compressionSupported(type))
      continue;

    std::string path = ::testing::TempDir() +
                       "avogadro-compression-roundtrip-" +
                       compressionName(type) + "." + compressionExtension(type);
    {
      auto sink = std::unique_ptr<std::ostream>(
        new std::ofstream(path, std::ios::binary));
      CompressingOStream cs(std::move(sink), type);
      cs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
      ASSERT_TRUE(cs.finish());
    }

    std::string error;
    auto stream = openWrapped(path, &error);
    std::remove(path.c_str());
    ASSERT_NE(stream, nullptr) << error;
    EXPECT_EQ(slurpStream(*stream), payload);
  }
}

// ============================================================================
// 15. Command line interoperability
// ============================================================================

TEST(CompressionTest, GzipInteropWithSystemGzip)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!commandAvailable("gzip"))
    GTEST_SKIP() << "the gzip command line tool is not available";

  std::string path = ::testing::TempDir() + "avogadro-compression-interop.gz";
  std::string payload = compressiblePayload(1u << 16);
  {
    auto sink =
      std::unique_ptr<std::ostream>(new std::ofstream(path, std::ios::binary));
    CompressingOStream cs(std::move(sink), Compression::Gzip);
    cs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    ASSERT_TRUE(cs.finish());
  }
  int result = std::system(("gzip -t " + path).c_str());
  std::remove(path.c_str());
  EXPECT_EQ(result, 0) << "gzip -t rejected our own output";
}

TEST(CompressionTest, Bzip2InteropWithSystemBzip2)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!compressionSupported(Compression::Bzip2))
    GTEST_SKIP() << "bzip2 is not supported in this build";
  if (!commandAvailable("bzip2"))
    GTEST_SKIP() << "the bzip2 command line tool is not available";

  std::string path = ::testing::TempDir() + "avogadro-compression-interop.bz2";
  std::string payload = compressiblePayload(1u << 16);
  {
    auto sink =
      std::unique_ptr<std::ostream>(new std::ofstream(path, std::ios::binary));
    CompressingOStream cs(std::move(sink), Compression::Bzip2);
    cs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    ASSERT_TRUE(cs.finish());
  }
  int result = std::system(("bzip2 -t " + path).c_str());
  std::remove(path.c_str());
  EXPECT_EQ(result, 0) << "bzip2 -t rejected our own output";
}

TEST(CompressionTest, ZstdInteropWithSystemZstd)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!compressionSupported(Compression::Zstd))
    GTEST_SKIP() << "zstd is not supported in this build";
  if (!commandAvailable("zstd"))
    GTEST_SKIP() << "the zstd command line tool is not available";

  std::string path = ::testing::TempDir() + "avogadro-compression-interop.zst";
  std::string payload = compressiblePayload(1u << 16);
  {
    auto sink =
      std::unique_ptr<std::ostream>(new std::ofstream(path, std::ios::binary));
    CompressingOStream cs(std::move(sink), Compression::Zstd);
    cs.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    ASSERT_TRUE(cs.finish());
  }
  int result = std::system(("zstd -t " + path).c_str());
  std::remove(path.c_str());
  EXPECT_EQ(result, 0) << "zstd -t rejected our own output";
}

// ============================================================================
// 16. Unsupported codec: fail with a named error, never silently pass
//     compressed bytes through as if they were plain data.
// ============================================================================

TEST(CompressionTest, UnsupportedCodecFailsWithNamedError)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Compression unsupported = Compression::None;
  for (Compression type :
       { Compression::Bzip2, Compression::Xz, Compression::Zstd }) {
    if (!compressionSupported(type)) {
      unsupported = type;
      break;
    }
  }
  if (unsupported == Compression::None)
    GTEST_SKIP() << "every codec is supported in this build";

  std::string fixture =
    kCompressedDir + "methane.xyz." + compressionExtension(unsupported);
  std::string error;
  auto stream = openWrapped(fixture, &error);
  EXPECT_EQ(stream, nullptr)
    << "an unsupported codec must not silently hand back compressed bytes "
       "as data";
  EXPECT_NE(error.find(compressionName(unsupported)), std::string::npos)
    << "error should name the unsupported codec ("
    << compressionName(unsupported) << "): " << error;
}

// ============================================================================
// Supplementary: realistic non-xyz fixtures, one per codec, using the
// original reference files shipped alongside the compressed ones.
// ============================================================================

TEST(CompressionTest, DecodesPdbGzipFixture)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  std::string expected =
    slurpFile(std::string(AVOGADRO_DATA) + "/data/pdb/1CRN.pdb");
  std::string error;
  auto stream = openWrapped(kCompressedDir + "1crn.pdb.gz", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_EQ(slurpStream(*stream), expected);
}

TEST(CompressionTest, DecodesCjsonXzFixture)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!compressionSupported(Compression::Xz))
    GTEST_SKIP() << "xz is not supported in this build";

  std::string expected =
    slurpFile(std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson");
  std::string error;
  auto stream = openWrapped(kCompressedDir + "ethane.cjson.xz", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_EQ(slurpStream(*stream), expected);
}

TEST(CompressionTest, DecodesSdfZstdFixture)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!compressionSupported(Compression::Zstd))
    GTEST_SKIP() << "zstd is not supported in this build";

  std::string expected =
    slurpFile(std::string(AVOGADRO_DATA) + "/data/sdf/multi.sdf");
  std::string error;
  auto stream = openWrapped(kCompressedDir + "multi.sdf.zst", &error);
  ASSERT_NE(stream, nullptr) << error;
  EXPECT_EQ(slurpStream(*stream), expected);
}

// ============================================================================
// 17. FileFormat / FileFormatManager integration -- the actual wiring this
//     task adds. Everything above exercises compressedstream.h/compression.h
//     directly; everything below goes through FileFormat::open()/readMolecule
//     ()/readString()/writeString() and FileFormatManager, proving compressed
//     files and strings are handled transparently by ordinary chemical
//     formats that know nothing about compression.
// ============================================================================

TEST(CompressionTest, ManagerReadFileGzipNoExtension)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Molecule reference;
  ASSERT_TRUE(
    FileFormatManager::instance().readFile(reference, kXyzDir + "methane.xyz"));
  ASSERT_EQ(reference.atomCount(), 5);

  Molecule fromGzip;
  ASSERT_TRUE(FileFormatManager::instance().readFile(
    fromGzip, kCompressedDir + "methane.xyz.gz"));
  expectMoleculesMatch(fromGzip, reference);
}

TEST(CompressionTest, ManagerReadFileGzipExplicitExtension)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Molecule reference;
  ASSERT_TRUE(
    FileFormatManager::instance().readFile(reference, kXyzDir + "methane.xyz"));

  // An explicit chemical extension with no compression suffix must still
  // work: the codec is detected from content, not from this string.
  Molecule viaXyz;
  ASSERT_TRUE(FileFormatManager::instance().readFile(
    viaXyz, kCompressedDir + "methane.xyz.gz", "xyz"));
  expectMoleculesMatch(viaXyz, reference);

  // An explicit extension that includes the compression suffix must also
  // resolve to the XYZ format.
  Molecule viaXyzGz;
  ASSERT_TRUE(FileFormatManager::instance().readFile(
    viaXyzGz, kCompressedDir + "methane.xyz.gz", "xyz.gz"));
  expectMoleculesMatch(viaXyzGz, reference);
}

TEST(CompressionTest, ManagerReadFilePdbGzipNoExtension)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  // NOTE: this cannot use data/pdb/1CRN.pdb / data/compressed/1crn.pdb.gz as
  // originally planned. PdbFormat::read() has a pre-existing bug, unrelated
  // to compression: an ATOM record whose element cannot be resolved is
  // skipped with `continue` (pdbformat.cpp) without pushing a placeholder
  // onto rawToAtomId, which desynchronizes the CONECT serial-to-array-index
  // mapping for every CONECT record that follows. Compounding it, the two
  // `rawToAtomId[a]` / `rawToAtomId[b]` lookups are never bounds checked
  // against rawToAtomId.size() -- the only range test happens afterwards,
  // against mol.atomCount() -- so the desync becomes an out-of-bounds read
  // rather than a wrong bond. On 1CRN.pdb that crashes the process (verified
  // with plain, uncompressed 1CRN.pdb too -- it is not a compression
  // issue), and the indices come straight from the file, which for PDB data
  // means straight from the network. Fixing it
  // is out of scope here (pdbformat.cpp is chemistry-parsing code outside
  // this task's fileformat.cpp/fileformatmanager.cpp remit) and is reported
  // separately. data/pdb/cryst1.pdb has no CONECT records, is already read
  // successfully elsewhere (PdbTest.cryst1), and a gzip copy is made on the
  // fly here so this test still exercises exactly the thing it is meant to:
  // the manager decompressing a gzipped PDB file transparently.
  Molecule reference;
  ASSERT_TRUE(
    FileFormatManager::instance().readFile(reference, kPdbDir + "cryst1.pdb"));
  ASSERT_GT(reference.atomCount(), 0);

  std::string gzPath =
    ::testing::TempDir() + "avogadro-compression-cryst1.pdb.gz";
  std::remove(gzPath.c_str());
  {
    auto sink = std::make_unique<std::ofstream>(gzPath, std::ios::binary);
    CompressingOStream cs(std::move(sink), Compression::Gzip);
    std::string plain = slurpFile(kPdbDir + "cryst1.pdb");
    cs.write(plain.data(), static_cast<std::streamsize>(plain.size()));
    ASSERT_TRUE(cs.finish());
  }

  Molecule fromGzip;
  ASSERT_TRUE(FileFormatManager::instance().readFile(fromGzip, gzPath));
  std::remove(gzPath.c_str());
  EXPECT_EQ(fromGzip.atomCount(), reference.atomCount());
}

TEST(CompressionTest, ReadStringDetectsGzipContentFromPlainExtension)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Molecule reference;
  ASSERT_TRUE(
    FileFormatManager::instance().readFile(reference, kXyzDir + "methane.xyz"));

  // The bytes are gzip, but the caller only ever names the chemical format:
  // content sniffing inside FileFormat::readString() must still decode them.
  std::string raw = slurpFile(kCompressedDir + "methane.xyz.gz");
  Molecule fromString;
  ASSERT_TRUE(FileFormatManager::instance().readString(fromString, raw, "xyz"));
  expectMoleculesMatch(fromString, reference);
}

TEST(CompressionTest, MultiMoleculeSdfZstd)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  if (!compressionSupported(Compression::Zstd))
    GTEST_SKIP() << "zstd is not supported in this build";

  auto countMolecules = [](const std::string& path) {
    SdfFormat format;
    EXPECT_TRUE(format.open(path, FileFormat::Read | FileFormat::MultiMolecule))
      << format.error();
    int count = 0;
    Molecule molecule;
    while (format.readMolecule(molecule)) {
      ++count;
      molecule = Molecule();
    }
    // The final, failing readMolecule() call that signals "no more molecules"
    // leaves a generic "Error reading molecule name." in error() -- that is
    // MdlFormat's normal end-of-multi-molecule-stream signal (see
    // MdlTest.readMulti), not something specific to compressed input, so it
    // is not asserted on here. What matters is that decompression did not cut
    // the stream short: both the plain and compressed files must yield the
    // same molecule count.
    return count;
  };

  int expectedCount = countMolecules(kSdfDir + "multi.sdf");
  ASSERT_GT(expectedCount, 0);
  EXPECT_EQ(countMolecules(kCompressedDir + "multi.sdf.zst"), expectedCount);
}

namespace {

// Writes molecule through the manager to a temp path with the given
// compressed extension, checks the file's magic bytes, then reads it back
// through the manager and confirms the molecule round trips.
void expectManagerWriteRoundTrip(const std::string& extension,
                                 Compression expectedCodec)
{
  if (!compressionSupported(expectedCodec)) {
    GTEST_SKIP() << compressionName(expectedCodec)
                 << " is not supported in this build";
  }

  Molecule original;
  ASSERT_TRUE(FileFormatManager::instance().readFile(
    original, std::string(AVOGADRO_DATA) + "/data/xyz/methane.xyz"));

  std::string path = ::testing::TempDir() +
                     "avogadro-compression-manager-roundtrip." + extension;
  std::remove(path.c_str());

  ASSERT_TRUE(FileFormatManager::instance().writeFile(original, path))
    << "writeFile failed for " << path;
  EXPECT_EQ(fileMagic(path), expectedCodec)
    << path << " does not start with the " << compressionName(expectedCodec)
    << " magic bytes";

  Molecule roundTripped;
  ASSERT_TRUE(FileFormatManager::instance().readFile(roundTripped, path))
    << "readFile failed for " << path;
  std::remove(path.c_str());

  expectMoleculesMatch(roundTripped, original);
}

} // namespace

TEST(CompressionTest, ManagerWriteFileRoundTripGzipCjson)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectManagerWriteRoundTrip("cjson.gz", Compression::Gzip);
}

TEST(CompressionTest, ManagerWriteFileRoundTripBzip2Xyz)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectManagerWriteRoundTrip("xyz.bz2", Compression::Bzip2);
}

TEST(CompressionTest, ManagerWriteFileRoundTripZstdXyz)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";
  expectManagerWriteRoundTrip("xyz.zst", Compression::Zstd);
}

TEST(CompressionTest, WriteStringGzipRoundTrip)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Molecule original;
  ASSERT_TRUE(FileFormatManager::instance().readFile(
    original, std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson"));

  std::string compressed;
  ASSERT_TRUE(
    FileFormatManager::instance().writeString(original, compressed, "cjson.gz"))
    << FileFormatManager::instance().error();
  ASSERT_GE(compressed.size(), compressionMagicSize);
  EXPECT_EQ(detectCompression(compressed.data(), compressionMagicSize),
            Compression::Gzip);

  Molecule roundTripped;
  ASSERT_TRUE(FileFormatManager::instance().readString(roundTripped, compressed,
                                                       "cjson"));
  expectMoleculesMatch(roundTripped, original);
}

TEST(CompressionTest, ReadFileCorruptGzipFailsWithError)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  // A single flipped bit inside an otherwise well-formed gzip stream. If the
  // FileFormat layer let this through, the CRC failure would surface as an
  // ordinary short read and silently yield a truncated-but-"successful"
  // molecule -- exactly the bug this wiring exists to prevent.
  Molecule molecule;
  EXPECT_FALSE(FileFormatManager::instance().readFile(
    molecule, kCompressedDir + "corrupt.xyz.gz", "xyz"));

  XyzFormat format;
  Molecule direct;
  EXPECT_FALSE(format.readFile(kCompressedDir + "corrupt.xyz.gz", direct));
  EXPECT_FALSE(format.error().empty());
}

TEST(CompressionTest, ReadFileTruncatedGzipFailsWithError)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  XyzFormat format;
  Molecule molecule;
  EXPECT_FALSE(format.readFile(kCompressedDir + "truncated.xyz.gz", molecule));
  EXPECT_FALSE(format.error().empty());
}

TEST(CompressionTest, MaxDecompressedSizeOptionEnforced)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  // zeros-4mib.gz decodes to 4 MiB of NUL bytes containing no newline at all.
  // No chemical format parses that into a molecule, so this cannot assert on
  // readFile()'s return value or on a resulting atom count. PdbFormat::read()
  // is used because its `while (getline(in, buffer))` loop pulls the entire
  // decompressed stream into a single buffer before giving up, which reliably
  // drives the decoder past a small maxDecompressedSize -- unlike, say,
  // XyzFormat, whose very first `>>` extraction fails on the first NUL byte
  // without pulling enough data to ever approach the limit. So the assertion
  // is on the specific error text FileFormat::readMolecule() appends from the
  // decompressor, naming "maxDecompressedSize", exactly as the low-level
  // SizeCapStopsAtLimit test above checks it at the compressedstream layer.
  {
    PdbFormat format;
    format.setOptions(R"({"maxDecompressedSize": 65536})");
    Molecule molecule;
    format.readFile(kCompressedDir + "zeros-4mib.gz", molecule);
    EXPECT_FALSE(format.error().empty());
    EXPECT_NE(format.error().find("maxDecompressedSize"), std::string::npos)
      << format.error();
  }

  // With the limit lifted (0 == unlimited) the same read must not fail for
  // that reason, whatever else it may or may not make of 4 MiB of zeros.
  {
    PdbFormat format;
    format.setOptions(R"({"maxDecompressedSize": 0})");
    Molecule molecule;
    format.readFile(kCompressedDir + "zeros-4mib.gz", molecule);
    EXPECT_EQ(format.error().find("maxDecompressedSize"), std::string::npos)
      << format.error();
  }
}

TEST(CompressionTest, WritingUnsupportedCodecFailsAndCreatesNoFile)
{
  if (!compressionAvailable())
    GTEST_SKIP() << "compression is not supported in this build";

  Compression unsupported = Compression::None;
  for (Compression type :
       { Compression::Bzip2, Compression::Xz, Compression::Zstd }) {
    if (!compressionSupported(type)) {
      unsupported = type;
      break;
    }
  }
  if (unsupported == Compression::None)
    GTEST_SKIP() << "every codec is supported in this build";

  std::string path = ::testing::TempDir() +
                     "avogadro-compression-unsupported-write.xyz." +
                     compressionExtension(unsupported);
  std::remove(path.c_str());

  XyzFormat format;
  EXPECT_FALSE(format.open(path, FileFormat::Write));
  EXPECT_NE(format.error().find(compressionName(unsupported)),
            std::string::npos)
    << "error should name the unsupported codec ("
    << compressionName(unsupported) << "): " << format.error();

  std::ifstream probe(path);
  EXPECT_FALSE(probe.is_open())
    << "an unsupported codec must not leave a stray empty file behind: "
    << path;
  std::remove(path.c_str());
}
