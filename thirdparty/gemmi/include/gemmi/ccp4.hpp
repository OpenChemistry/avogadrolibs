/// @file ccp4.hpp
/// @brief CCP4/MRC map file format (electron density maps and masks).
///
/// This header provides support for reading and writing CCP4 (Collaborative Computational
/// Project 4) and MRC (Medical Research Council) map file formats commonly used for
/// electron density maps and molecular masks in crystallography and cryo-EM.
/// The CCP4 map consists of a 1024-byte fixed header followed by data values (typically floats).
/// The header contains grid dimensions, unit cell parameters, space group, and data statistics.

// Copyright 2018 Global Phasing Ltd.
//
// CCP4 format for maps and masks.

#ifndef GEMMI_CCP4_HPP_
#define GEMMI_CCP4_HPP_

#include <cassert>
#include <cmath>     // for ceil, fabs, floor, round
#include <cstdint>   // for uint16_t, int32_t
#include <cstdio>    // for FILE
#include <cstring>   // for memcpy
#include <array>
#include <string>
#include <type_traits>  // for is_same
#include <vector>
#include "symmetry.hpp"
#include "fail.hpp"      // for fail
#include "fileutil.hpp"  // for file_open, is_little_endian, ...
#include "input.hpp"     // for AnyStream, FileStream
#include "grid.hpp"

#if __has_include(<stdfloat>)
# include <stdfloat>
#endif
#ifdef __STDCPP_FLOAT16_T__
using float16_type = std::float16_t;
#else
// Minimal IEEE 754 binary16 type for reading CCP4 mode-12 maps.
struct float16_type {
  std::uint16_t bits;
  operator float() const {
    std::uint32_t sign = (bits >> 15) & 1;
    std::uint32_t exp = (bits >> 10) & 0x1F;
    std::uint32_t mant = bits & 0x3FF;
    float result;
    if (exp == 0) {  // subnormal or zero
      result = std::ldexp(static_cast<float>(mant), -24);
    } else if (exp == 31) {  // inf or nan
      std::uint32_t f = (sign << 31) | 0x7F800000u | (mant << 13);
      std::memcpy(&result, &f, 4);
      return result;
    } else {
      result = std::ldexp(static_cast<float>(mant + 1024), static_cast<int>(exp) - 25);
    }
    return sign ? -result : result;
  }
  bool operator!=(float16_type o) const { return bits != o.bits; }
  bool operator==(float16_type o) const { return bits == o.bits; }
};
#endif

namespace gemmi {

using std::int32_t;

/// @brief Options for expanding/reordering CCP4 map data during setup.
///
/// CCP4 maps can store data in non-standard axis orderings and may cover only a portion
/// of the unit cell. The setup() method uses this enum to control transformation behavior.
enum class MapSetup {
  Full,         ///< Reorder axes to XYZ and expand with symmetry to the whole unit cell
  NoSymmetry,   ///< Reorder axes to XYZ and resize to the whole cell, but do not apply symmetry ops
  ReorderOnly   ///< Only reorder axes to X, Y, Z; keep the partial cell as-is
};

/// @brief Base class for CCP4 map headers and metadata.
///
/// Stores the raw CCP4 header (256 32-bit words plus optional extended symmetry records)
/// and provides methods to read/write individual header fields and manage map metadata.
/// The header defines the grid geometry, unit cell, space group, axis ordering, and statistics.
struct Ccp4Base {
  DataStats hstats;  ///< Data statistics (min, max, mean, RMS) read from/written to map header
  std::vector<int32_t> ccp4_header;  ///< Raw header words (256 required + symmetry records)
  bool same_byte_order = true;  ///< True if file byte order matches machine byte order

  /// @brief Get pointer to a header word (32-bit value).
  /// @param w Word number in CCP4 convention (1-indexed)
  /// @return Pointer to the word (cast to appropriate type as needed)
  void* header_word(int w) { return &ccp4_header.at(w - 1); }
  /// @brief Get const pointer to a header word.
  const void* header_word(int w) const { return &ccp4_header.at(w - 1); }

  /// @brief Read a 32-bit signed integer from header with byte-order correction.
  /// @param w Word number (1-indexed)
  /// @return The 32-bit value, byte-swapped if needed
  int32_t header_i32(int w) const {
    int32_t value = ccp4_header.at(w - 1);
    if (!same_byte_order)
      swap_four_bytes(&value);
    return value;
  }
  /// @brief Read three consecutive 32-bit integers from header.
  /// @param w Starting word number (1-indexed)
  /// @return Array of three consecutive 32-bit values
  std::array<int, 3> header_3i32(int w) const {
    return {{ header_i32(w), header_i32(w+1), header_i32(w+2) }};
  }
  /// @brief Read a 32-bit float from header with byte-order correction.
  /// @param w Word number (1-indexed)
  /// @return The floating-point value
  float header_float(int w) const {
    int32_t int_value = header_i32(w);
    float f;
    std::memcpy(&f, &int_value, 4);
    return f;
  }
  /// @brief Read a string field from header.
  /// @param w Starting word number (1-indexed)
  /// @param len Byte length to read (default 80 for standard CCP4 label)
  /// @return The extracted string (may include padding)
  std::string header_str(int w, size_t len=80) const {
    if (4 * ccp4_header.size() < 4 * (w - 1) + len)
      fail("invalid end of string");
    return std::string(reinterpret_cast<const char*>(header_word(w)), len);
  }
  /// @brief Write a 32-bit signed integer to header with byte-order correction.
  /// @param w Word number (1-indexed)
  /// @param value The value to write
  void set_header_i32(int w, int32_t value) {
    if (!same_byte_order)
      swap_four_bytes(&value);
    ccp4_header.at(w - 1) = value;
  }
  /// @brief Write three consecutive 32-bit integers to header.
  /// @param w Starting word number (1-indexed)
  /// @param x First value (word w)
  /// @param y Second value (word w+1)
  /// @param z Third value (word w+2)
  void set_header_3i32(int w, int32_t x, int32_t y, int32_t z) {
    set_header_i32(w, x);
    set_header_i32(w+1, y);
    set_header_i32(w+2, z);
  }
  /// @brief Write a 32-bit float to header with byte-order correction.
  /// @param w Word number (1-indexed)
  /// @param value The floating-point value to write
  void set_header_float(int w, float value) {
    int32_t int32_value;
    std::memcpy(&int32_value, &value, 4);
    set_header_i32(w, int32_value);
  }
  /// @brief Write a string to header field.
  /// @param w Starting word number (1-indexed)
  /// @param str The string to write (must fit in available space)
  void set_header_str(int w, const std::string& str) {
    std::memcpy(header_word(w), str.c_str(), str.size());
  }

  /// @brief Determine the actual axis ordering from header MAPC, MAPR, MAPS records.
  /// @return Array where pos[i] is the map column/row/section index for axis i (X/Y/Z)
  /// @throws If MAPC/MAPR/MAPS records are invalid or inconsistent
  std::array<int, 3> axis_positions() const {
    if (ccp4_header.empty())
      return {{0, 1, 2}}; // assuming it's X,Y,Z
    std::array<int, 3> pos{{-1, -1, -1}};
    for (int i = 0; i != 3; ++i) {
      int mapi = header_i32(17 + i);
      if (mapi <= 0 || mapi > 3 || pos[mapi - 1] != -1)
        fail("Incorrect MAPC/MAPR/MAPS records");
      pos[mapi - 1] = i;
    }
    return pos;
  }

  /// @brief Read a floating-point value from header, rounded to 5 decimal places.
  /// @param w Word number (1-indexed)
  /// @return The value rounded to avoid floating-point representation artifacts
  double header_rfloat(int w) const {
    return std::round(1e5 * header_float(w)) / 1e5;
  }

  /// @brief Get the extent of the map data in fractional coordinates.
  /// @return A box (min, max corners) in fractional coordinates covering the map data
  Box<Fractional> get_extent() const {
    Box<Fractional> box;
    // cf. setup()
    auto pos = axis_positions();
    std::array<int, 3> start = header_3i32(5);
    std::array<int, 3> size = header_3i32(1);
    std::array<int, 3> sampl = header_3i32(8);
    for (int i = 0; i < 3; ++i) {
      double scale = 1. / sampl[i];
      int p = pos[i];
      box.minimum.at(i) = scale * start[p] - 1e-9;
      box.maximum.at(i) = scale * (start[p] + size[p] - 1) + 1e-9;
    }
    return box;
  }

  /// @brief Check if the map has a skew transformation (non-orthogonal grid).
  /// @return True if LSKFLG (word 25) is non-zero, indicating skew is applied
  /// @note Skew transformation is CCP4-specific and rarely used; most software ignores it
  bool has_skew_transformation() const {
    return header_i32(25) != 0;
  }
  /// @brief Get the skew transformation matrix and translation vector.
  /// @return Transform struct with 3x3 matrix and translation for Xo(map) = S * (Xo(atoms) - t)
  /// @note Only meaningful if has_skew_transformation() is true
  Transform get_skew_transformation() const {
    return {
      // 26-34 SKWMAT
      { header_float(26), header_float(27), header_float(28),
        header_float(29), header_float(30), header_float(31),
        header_float(32), header_float(33), header_float(34) },
      // 35-37 SKWTRN
      { header_float(35), header_float(36), header_float(37) }
    };
  }

  /// @brief Get the origin offset (used in MRC format).
  /// @return Position vector from words 50-52 (usually zero in CCP4, non-zero in MRC)
  Position get_origin() const {
    return Position(header_float(50), header_float(51), header_float(52));
  }

  /// @brief Create a CCP4 header for the given grid (excludes MODE and data statistics).
  /// @param grid GridMeta with unit cell, space group, and dimensions to encode
  /// @note Assumes the grid covers the whole unit cell with no offset.
  /// The header includes symmetry operation records from the space group.
  void prepare_ccp4_header_except_mode_and_stats(GridMeta& grid) {
    GroupOps ops;
    if (grid.spacegroup)
      ops = grid.spacegroup->operations();
    ccp4_header.clear();
    ccp4_header.resize(256 + ops.order() * 20, 0);
    set_header_3i32(1, grid.nu, grid.nv, grid.nw); // NX, NY, NZ
    set_header_3i32(5, 0, 0, 0); // NXSTART, NYSTART, NZSTART
    if (grid.axis_order == AxisOrder::XYZ)
      set_header_3i32(8, grid.nu, grid.nv, grid.nw);  // MX, MY, MZ
    else // grid.axis_order == AxisOrder::ZYX
      set_header_3i32(8, grid.nw, grid.nv, grid.nu);
    set_header_float(11, (float) grid.unit_cell.a);
    set_header_float(12, (float) grid.unit_cell.b);
    set_header_float(13, (float) grid.unit_cell.c);
    set_header_float(14, (float) grid.unit_cell.alpha);
    set_header_float(15, (float) grid.unit_cell.beta);
    set_header_float(16, (float) grid.unit_cell.gamma);
    if (grid.axis_order == AxisOrder::XYZ)
      set_header_3i32(17, 1, 2, 3); // MAPC, MAPR, MAPS
    else // grid.axis_order == AxisOrder::ZYX
      set_header_3i32(17, 3, 2, 1);
    set_header_i32(23, grid.spacegroup ? grid.spacegroup->ccp4 : 1); // ISPG
    set_header_i32(24, ops.order() * 80);  // NSYMBT
    set_header_str(27, "CCP4"); // EXTTYP
    set_header_i32(28, 20140);  // NVERSION
    set_header_str(53, "MAP ");
    set_header_i32(54, is_little_endian() ? 0x00004144 : 0x11110000); // MACHST
    set_header_i32(56, 1); // labels
    std::memset(header_word(57), ' ', 800 + ops.order() * 80);
    set_header_str(57, "written by GEMMI");
    int n = 257;
    for (Op op : ops) {
      set_header_str(n, op.triplet());
      n += 20;
    }
  }

  /// @brief Update header MODE and data statistics fields.
  /// @param mode CCP4 mode (0=int8, 1=int16, 2=float, 6=uint16, 12=float16)
  void update_header_mode_and_stats(int mode) {
    set_header_i32(4, mode);
    set_header_float(20, (float) hstats.dmin);
    set_header_float(21, (float) hstats.dmax);
    set_header_float(22, (float) hstats.dmean);
    set_header_float(55, (float) hstats.rms);
  }

  /// @brief Check if the map data covers the entire unit cell.
  /// @param grid Grid metadata to check against header
  /// @return True if NXSTART=NYSTART=NZSTART=0 and MX=NX, MY=NY, MZ=NZ
  bool full_cell_(const GridMeta& grid) const {
    if (ccp4_header.empty())
      return true;
    return
      header_i32(5) == 0 && header_i32(6) == 0 && header_i32(7) == 0 &&
      header_i32(8) == grid.nu && header_i32(9) == grid.nv && header_i32(10) == grid.nw;
  }

  /// @brief Read CCP4 map header from stream, detecting byte order and extended records.
  /// @param grid GridMeta to populate with header info (may be null to skip grid setup)
  /// @param f Input stream positioned at start of file
  /// @param path File path for error reporting
  /// @throws If header is invalid, file is truncated, or contains unsupported features
  void read_ccp4_header_(GridMeta* grid, AnyStream& f, const std::string& path) {
    const size_t hsize = 256;
    ccp4_header.resize(hsize);
    if (!f.read(ccp4_header.data(), 4 * hsize))
      fail("Failed to read map header: " + path);
    if (header_str(53, 4) != "MAP ")
      fail("Not a CCP4 map: " + path);
    std::string machst = header_str(54, 4);
    if (machst[0] != 0x44 && machst[0] != 0x11)
      fail("Unsupported machine stamp (endianness) in the file?");
    same_byte_order = machst[0] == (is_little_endian() ? 0x44 : 0x11);
    size_t ext_w = header_i32(24) / 4;
    if (ext_w != 0) {
      if (ext_w > 1000000)
        fail("Unexpectedly long extended header: " + path);
      ccp4_header.resize(hsize + ext_w);
      if (!f.read(ccp4_header.data() + hsize, 4 * ext_w))
        fail("Failed to read extended header: " + path);
    }
    for (int i = 0; i < 3; ++i) {
      int axis = header_i32(17 + i);
      if (axis < 1 || axis > 3)
        fail("Unexpected axis value in word " + std::to_string(17 + i)
             + ": " + std::to_string(axis));
    }
    hstats.dmin = header_float(20);
    hstats.dmax = header_float(21);
    hstats.dmean = header_float(22);
    hstats.rms = header_float(55);
    if (grid) {
      grid->unit_cell.set(header_rfloat(11), header_rfloat(12), header_rfloat(13),
                          header_rfloat(14), header_rfloat(15), header_rfloat(16));
      grid->nu = header_i32(1);
      grid->nv = header_i32(2);
      grid->nw = header_i32(3);
      grid->spacegroup = find_spacegroup_by_number(header_i32(23));
      auto pos = axis_positions();
      grid->axis_order = AxisOrder::Unknown;
      if (pos[0] == 0 && pos[1] == 1 && pos[2] == 2 && full_cell_(*grid))
        grid->axis_order = AxisOrder::XYZ;
    }
  }
};

/// @brief CCP4 map file container with typed grid data.
/// @tparam T Data type for grid values (typically float, int8_t, int16_t, or uint16_t)
///
/// Extends Ccp4Base to hold both the raw CCP4 header and the grid data in memory.
/// The grid axes may not be in XYZ order when read; call setup() to reorder if needed.
template<typename T=float>
struct Ccp4 : public Ccp4Base {
  Grid<T> grid;  ///< The 3D grid of map values

  /// @brief Create or update the CCP4 header with mode and statistics.
  ///
  /// If the header is empty, creates it with full grid metadata.
  /// If the header exists, updates MODE word and optionally DMIN/DMAX/DMEAN/RMS.
  /// @param mode CCP4 data mode (-1 to auto-detect from T), or explicit mode value
  /// @param update_stats If true, compute and store min/max/mean/rms from grid data
  /// @throws If grid is empty, not setup, or mode cannot be determined
  void update_ccp4_header(int mode=-1, bool update_stats=true) {
    if (mode > 2 && mode != 6)
      fail("Only modes 0, 1, 2 and 6 are supported.");
    if (grid.point_count() == 0)
      fail("update_ccp4_header(): set the grid first (it has size 0)");
    if (grid.axis_order == AxisOrder::Unknown)
      fail("update_ccp4_header(): run setup() first");
    if (update_stats)
      hstats = calculate_data_statistics(grid.data);
    if (ccp4_header.empty())
      prepare_ccp4_header_except_mode_and_stats(grid);
    assert(ccp4_header.size() >= 256);
    if (mode < 0) {
      mode = mode_for_data();
      if (mode < 0)
        fail("update_ccp4_header: specify map mode explicitly (usually 2)");
    }
    update_header_mode_and_stats(mode);
  }

  /// @brief Detect CCP4 mode value for the data type T.
  /// @return CCP4 mode (0, 1, 2, 6) or -1 if type is not supported for mode
  static int mode_for_data() {
    if (std::is_same<T, std::int8_t>::value)
      return 0;
    if (std::is_same<T, std::int16_t>::value)
      return 1;
    if (std::is_same<T, float>::value)
      return 2;
    if (std::is_same<T, std::uint16_t>::value)
      return 6;
    return -1;
  }

  /// @brief Check if the map data covers the full unit cell.
  /// @return True if NXSTART, NYSTART, NZSTART are 0 and grid matches cell sampling
  bool full_cell() const { return full_cell_(grid); }

  /// @brief Read CCP4 header from stream and initialize grid metadata.
  /// @param f Input stream positioned at file start
  /// @param path File path for error reporting
  void read_ccp4_header(AnyStream& f, const std::string& path) {
    read_ccp4_header_(&grid, f, path);
    if (grid.axis_order != AxisOrder::Unknown)
      grid.calculate_spacing();
  }

  /// @brief Transform map axes and/or expand to full unit cell.
  /// @param default_value Value to use for grid points outside the map region
  /// @param mode Control what transformations to apply (Full, NoSymmetry, or ReorderOnly)
  /// @note Modifies grid dimensions, axis order, and data layout; call after reading header
  void setup(T default_value, MapSetup mode=MapSetup::Full);

  /// @brief Trim the map to a region specified in fractional coordinates.
  /// @param box Region bounds in fractional coordinates [0, 1]
  /// @note Only works after setup(); requires full_cell() == true and XYZ axis order
  void set_extent(const Box<Fractional>& box);

  /// @brief Read CCP4 map data and header from a stream.
  /// @param f Input stream positioned at file start
  /// @param path File path for error reporting
  /// @note Reads both header and data; grid data is resized and populated
  void read_ccp4_stream(AnyStream& f, const std::string& path);

  /// @brief Read CCP4 map from a file path.
  /// @param path Path to CCP4 map file
  void read_ccp4_file(const std::string& path) {
    FileStream stream(path.c_str(), "rb");
    read_ccp4_stream(stream, path);
  }

  /// @brief Read CCP4 map from memory buffer.
  /// @param data Pointer to file contents in memory
  /// @param size Size of buffer in bytes
  /// @param name Label for error messages
  void read_ccp4_from_memory(const char* data, size_t size, const std::string& name) {
    MemoryStream stream(data, size);
    read_ccp4_stream(stream, name);
  }

  /// @brief Read CCP4 map using a generic input adapter.
  /// @tparam Input Type with create_stream() and path() methods
  /// @param input Input adapter (e.g., MaybeGzipped for .map.gz files)
  template<typename Input>
  void read_ccp4(Input&& input) {
    std::unique_ptr<AnyStream> stream = input.create_stream();
    read_ccp4_stream(*stream, input.path());
  }

  /// @brief Write CCP4 map and data to file.
  /// @param path Output file path
  /// @note Header must be set (via update_ccp4_header) before writing
  void write_ccp4_map(const std::string& path) const;
};


namespace impl {

template<typename From, typename To>
To translate_map_point(From f) { return static_cast<To>(f); }
// We convert map 2 to 0 by translating non-zero values to 1.
template<> inline
std::int8_t translate_map_point<float,std::int8_t>(float f) { return f != 0; }
template<> inline
std::int8_t translate_map_point<float16_type,std::int8_t>(float16_type f) { return static_cast<float>(f) != 0; }

template<typename TFile, typename TMem>
void read_data(AnyStream& f, std::vector<TMem>& content) {
  if (std::is_same<TFile, TMem>::value) {
    size_t len = content.size();
    if (!f.read(content.data(), sizeof(TMem) * len))
      fail("Failed to read all the data from the map file.");
  } else {
    constexpr size_t chunk_size = 64 * 1024;
    std::vector<TFile> work(chunk_size);
    for (size_t i = 0; i < content.size(); i += chunk_size) {
      size_t len = std::min(chunk_size, content.size() - i);
      if (!f.read(work.data(), sizeof(TFile) * len))
        fail("Failed to read all the data from the map file.");
      for (size_t j = 0; j < len; ++j)
        content[i+j] = translate_map_point<TFile,TMem>(work[j]);
    }
  }
}

template<typename TFile, typename TMem>
void write_data(const std::vector<TMem>& content, FILE* f) {
  if (std::is_same<TMem, TFile>::value) {
    size_t len = content.size();
    if (std::fwrite(content.data(), sizeof(TFile), len, f) != len)
      sys_fail("Failed to write data to the map file");
  } else {
    constexpr size_t chunk_size = 64 * 1024;
    std::vector<TFile> work(chunk_size);
    for (size_t i = 0; i < content.size(); i += chunk_size) {
      size_t len = std::min(chunk_size, content.size() - i);
      for (size_t j = 0; j < len; ++j)
        work[j] = static_cast<TFile>(content[i+j]);
      if (std::fwrite(work.data(), sizeof(TFile), len, f) != len)
        sys_fail("Failed to write data to the map file");
    }
  }
}

} // namespace impl

// This function was tested only on little-endian machines,
// let us know if you need support for other architectures.
/// @brief Implementation of read_ccp4_stream for template specialization.
template<typename T>
void Ccp4<T>::read_ccp4_stream(AnyStream& f, const std::string& path) {
  read_ccp4_header(f, path);
  grid.data.resize(grid.point_count());
  int mode = header_i32(4);
  if (mode == 0)
    impl::read_data<std::int8_t>(f, grid.data);
  else if (mode == 1)
    impl::read_data<std::int16_t>(f, grid.data);
  else if (mode == 2)
    impl::read_data<float>(f, grid.data);
  else if (mode == 6)
    impl::read_data<std::uint16_t>(f, grid.data);
  else if (mode == 12)
    impl::read_data<float16_type>(f, grid.data);
  else
    fail("Mode " + std::to_string(mode) + " is not supported "
         "(only 0, 1, 2 and 6 are supported).");

  if (!same_byte_order) {
    if (sizeof(T) == 2)
      for (T& value : grid.data)
        swap_two_bytes(&value);
    else if (sizeof(T) == 4)
      for (T& value : grid.data)
        swap_four_bytes(&value);
  }
}

/// @brief Implementation of setup() for template specialization.
template<typename T>
void Ccp4<T>::setup(T default_value, MapSetup mode) {
  if (grid.axis_order == AxisOrder::XYZ || ccp4_header.empty())
    return;
  // cell sampling does not change
  const std::array<int, 3> sampl = header_3i32(8);
  // get old metadata
  const std::array<int, 3> pos = axis_positions();
  std::array<int, 3> start = header_3i32(5);
  int end[3] = { start[0] + grid.nu, start[1] + grid.nv, start[2] + grid.nw };
  // set new metadata
  if (mode == MapSetup::ReorderOnly) {
    set_header_3i32(5, start[pos[0]], start[pos[1]], start[pos[2]]);
    for (int i = 0; i < 3; ++i) {
      end[i] -= start[i];
      start[i] = 0;
    }
    int crs[3] = { grid.nu, grid.nv, grid.nw };
    grid.nu = crs[pos[0]];
    grid.nv = crs[pos[1]];
    grid.nw = crs[pos[2]];
  } else {
    grid.nu = sampl[0];
    grid.nv = sampl[1];
    grid.nw = sampl[2];
    set_header_3i32(5, 0, 0, 0);
  }
  set_header_3i32(1, grid.nu, grid.nv, grid.nw);
  set_header_3i32(17, 1, 2, 3);
  grid.axis_order = full_cell() ? AxisOrder::XYZ : AxisOrder::Unknown;
  if (grid.axis_order == AxisOrder::XYZ)
    grid.calculate_spacing();

  // now set the data
  {
    std::vector<T> full(grid.point_count(), default_value);
    int it[3];
    int idx = 0;
    for (it[2] = start[2]; it[2] < end[2]; it[2]++)
      for (it[1] = start[1]; it[1] < end[1]; it[1]++)
        for (it[0] = start[0]; it[0] < end[0]; it[0]++) {
          T val = grid.data[idx++];
          size_t new_index = grid.index_s(it[pos[0]], it[pos[1]], it[pos[2]]);
          full[new_index] = val;
        }
    grid.data = std::move(full);
  }

  if (mode == MapSetup::Full &&
      (end[pos[0]] - start[pos[0]] < sampl[0] ||
       end[pos[1]] - start[pos[1]] < sampl[1] ||
       end[pos[2]] - start[pos[2]] < sampl[2]))
    grid.symmetrize_nondefault(default_value);
}

/// @brief Implementation of set_extent() for template specialization.
template<typename T>
void Ccp4<T>::set_extent(const Box<Fractional>& box) {
  if (ccp4_header.empty())
    fail("set_extent(): no header in the map. Call update_ccp4_header() first");
  if (!full_cell())
    fail("Ccp4::set_extent() works only after setup()");
  if (grid.axis_order != AxisOrder::XYZ)
    fail("Ccp4::set_extent() works only with XYZ order");
  int u0 = (int)std::ceil(box.minimum.x * grid.nu);
  int v0 = (int)std::ceil(box.minimum.y * grid.nv);
  int w0 = (int)std::ceil(box.minimum.z * grid.nw);
  int nu = (int)std::floor(box.maximum.x * grid.nu) - u0 + 1;
  int nv = (int)std::floor(box.maximum.y * grid.nv) - v0 + 1;
  int nw = (int)std::floor(box.maximum.z * grid.nw) - w0 + 1;
  // set the data
  std::vector<T> new_data((size_t)nu * nv * nw);
  grid.get_subarray(new_data.data(), {u0, v0, w0}, {nu, nv, nw});
  grid.data.swap(new_data);
  // and metadata
  grid.nu = nu;
  grid.nv = nv;
  grid.nw = nw;
  set_header_3i32(1, grid.nu, grid.nv, grid.nw);
  set_header_3i32(5, u0, v0, w0);
  grid.axis_order = AxisOrder::Unknown;
}

/// @brief Implementation of write_ccp4_map() for template specialization.
template<typename T>
void Ccp4<T>::write_ccp4_map(const std::string& path) const {
  assert(ccp4_header.size() >= 256);
  fileptr_t f = file_open(path.c_str(), "wb");
  std::fwrite(ccp4_header.data(), 4, ccp4_header.size(), f.get());
  int mode = header_i32(4);
  if (mode == 0)
    impl::write_data<std::int8_t>(grid.data, f.get());
  else if (mode == 1)
    impl::write_data<std::int16_t>(grid.data, f.get());
  else if (mode == 2)
    impl::write_data<float>(grid.data, f.get());
  else if (mode == 6)
    impl::write_data<std::uint16_t>(grid.data, f.get());
}

/// @brief Convenience function to read a CCP4 electron density map.
/// @param path File path to .map or .map.gz file
/// @param setup If true, call setup(NAN) to expand and reorder to full cell
/// @return Ccp4 object with grid data and header
GEMMI_DLL Ccp4<float> read_ccp4_map(const std::string& path, bool setup);

/// @brief Convenience function to read a CCP4 binary mask.
/// @param path File path to .msk or mask file
/// @param setup If true, call setup(-1) to expand to full cell
/// @return Ccp4 object with int8_t grid data (0=false, non-zero=true)
GEMMI_DLL Ccp4<int8_t> read_ccp4_mask(const std::string& path, bool setup);

/// @brief Read only the CCP4 header without allocating grid data.
/// @param path File path to CCP4 map file
/// @return Ccp4Base with header and metadata (grid data not populated)
GEMMI_DLL Ccp4Base read_ccp4_header(const std::string& path);

} // namespace gemmi
#endif
