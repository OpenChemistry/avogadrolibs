/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CHUNKWRITER_P_H
#define AVOGADRO_RENDERING_CHUNKWRITER_P_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <vector>

namespace Avogadro::Rendering {

/**
 * @class ChunkWriter chunkwriter_p.h
 * @brief Buffered binary output for the scene exporters (PLY, glTF).
 *
 * Values are collected in a fixed-size buffer and written to the stream in
 * large pieces. Every multi-byte value is stored least significant byte first
 * by explicit shifts, so the output is little-endian whatever the host byte
 * order (compilers turn this into a plain store on little-endian hosts).
 * Each call checks for room once, not per byte. The stream state is not
 * examined: check the stream after flush().
 */
class ChunkWriter
{
public:
  explicit ChunkWriter(std::ostream& out) : m_out(out), m_buffer(kSize) {}
  ~ChunkWriter() { flush(); }

  ChunkWriter(const ChunkWriter&) = delete;
  ChunkWriter& operator=(const ChunkWriter&) = delete;

  void byte(unsigned char value)
  {
    char* p = reserve(1);
    p[0] = static_cast<char>(value);
  }

  void u16(std::uint16_t value)
  {
    char* p = reserve(2);
    put16(p, value);
  }

  void u32(std::uint32_t value)
  {
    char* p = reserve(4);
    put32(p, value);
  }

  /** One IEEE-754 single, written as its bit pattern. */
  void f32(float value) { floats(&value, 1); }

  /** @p count consecutive floats. */
  void floats(const float* values, size_t count)
  {
    static_assert(sizeof(float) == 4, "the exporters need 32-bit floats");
    while (count > 0) {
      const size_t n = count < kMaxRun ? count : kMaxRun;
      char* p = reserve(n * 4);
      for (size_t i = 0; i < n; ++i) {
        std::uint32_t bits;
        std::memcpy(&bits, values + i, 4);
        put32(p + 4 * i, bits);
      }
      values += n;
      count -= n;
    }
  }

  void text(const std::string& s)
  {
    if (s.size() > kSize) {
      flush();
      m_out.write(s.data(), static_cast<std::streamsize>(s.size()));
      return;
    }
    char* p = reserve(s.size());
    std::memcpy(p, s.data(), s.size());
  }

  void pad(std::uint64_t count, unsigned char value = 0)
  {
    for (std::uint64_t i = 0; i < count; ++i)
      byte(value);
  }

  void flush()
  {
    if (m_used > 0) {
      m_out.write(m_buffer.data(), static_cast<std::streamsize>(m_used));
      m_used = 0;
    }
  }

private:
  static constexpr size_t kSize = 1 << 18;
  static constexpr size_t kMaxRun = 1024; // floats per reserve()

  // A pointer to @p n bytes of room (n <= kSize), which are counted as used.
  char* reserve(size_t n)
  {
    if (m_used + n > kSize)
      flush();
    char* p = m_buffer.data() + m_used;
    m_used += n;
    return p;
  }

  static void put16(char* p, std::uint16_t value)
  {
    p[0] = static_cast<char>(value & 0xff);
    p[1] = static_cast<char>((value >> 8) & 0xff);
  }

  static void put32(char* p, std::uint32_t value)
  {
    p[0] = static_cast<char>(value & 0xff);
    p[1] = static_cast<char>((value >> 8) & 0xff);
    p[2] = static_cast<char>((value >> 16) & 0xff);
    p[3] = static_cast<char>((value >> 24) & 0xff);
  }

  std::ostream& m_out;
  std::vector<char> m_buffer;
  size_t m_used = 0;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_CHUNKWRITER_P_H
