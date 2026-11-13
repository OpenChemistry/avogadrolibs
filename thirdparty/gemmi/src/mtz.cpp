// Copyright 2019-2023 Global Phasing Ltd.

#include <gemmi/mtz.hpp>
#include <cstring>            // for memcpy
#include <algorithm>          // for stable_sort
#include <gemmi/atof.hpp>     // for fast_atof
#include <gemmi/atox.hpp>     // for simple_atoi, read_word
#include <gemmi/gz.hpp>
#include <gemmi/sprintf.hpp>

namespace gemmi {

namespace {

double wrap_degrees(double phi) {
  if (phi >= 0 && phi < 360.)
    return phi;
  return phi - std::floor(phi / 360.) * 360.;
}

void shift_phase(float& phi, double shift, bool negate=false) {
  double phi_ = phi + deg(shift);
  phi = float(wrap_degrees(negate ? -phi_ : phi_));
}

// apply phase shift to Hendrickson–Lattman coefficients HLA, HLB, HLC and HLD
void shift_hl_coefficients(float& a, float& b, float& c, float& d,
                           double shift, bool negate=false) {
  double sinx = std::sin(shift);
  double cosx = std::cos(shift);
  double sin2x = 2 * sinx * cosx;
  double cos2x = sq(cosx)- sq(sinx);
  // a sin(x+y) + b cos(x+y) = a sin(x) cos(y) - b sin(x) sin(y)
  //                         + a cos(x) sin(y) + b cos(x) cos(y)
  float a_ = float(a * cosx - b * sinx);
  float b_ = float(a * sinx + b * cosx);
  float c_ = float(c * cos2x - d * sin2x);
  float d_ = float(c * sin2x + d * cos2x);
  a = a_;                 // cos(phi)
  b = negate ? -b_ : b_;  // sin(phi)
  c = c_;                 // cos(2 phi)
  d = negate ? -d_ : d_;  // sin(2 phi)
}

// this function is generic because it was used in other places in the past
template <typename T, typename FP=typename std::iterator_traits<T>::value_type>
std::array<FP,2> calculate_min_max_disregarding_nans(T begin, T end) {
  std::array<FP,2> minmax = {{NAN, NAN}};
  T i = begin;
  while (i != end && std::isnan(*i))
    ++i;
  if (i != end) {
    minmax[0] = minmax[1] = *i;
    while (++i != end) {
      if (*i < minmax[0])
        minmax[0] = *i;
      else if (*i > minmax[1])
        minmax[1] = *i;
    }
  }
  return minmax;
}

const char* skip_word_and_space(const char* line) {
  while (*line != '\0' && !std::isspace(*line))
    ++line;
  while (std::isspace(*line))
    ++line;
  return line;
}

UnitCell read_cell_parameters(const char* line) {
  double a = fast_atof(line, &line);
  double b = fast_atof(line, &line);
  double c = fast_atof(line, &line);
  double alpha = fast_atof(line, &line);
  double beta = fast_atof(line, &line);
  double gamma = fast_atof(line, &line);
  return UnitCell(a, b, c, alpha, beta, gamma);
}

} // anonymous namespace

UnitCellParameters Mtz::get_average_cell_from_batch_headers(double* rmsd) const {
  if (rmsd)
    for (int i = 0; i < 6; ++i)
      rmsd[i] = 0.;
  std::array<double, 6> avg = {0., 0., 0., 0., 0., 0.};
  for (const Batch& batch : batches)
    for (int i = 0; i < 6; ++i) {
      // if batch headers are not set correctly, return global cell
      if (batch.floats[i] <= 0)
        return cell;
      avg[i] += batch.floats[i];
    }
  if (avg[0] <= 0 || avg[1] <= 0 || avg[2] <= 0 ||
      avg[3] <= 0 || avg[4] <= 0 || avg[5] <= 0)
    return UnitCellParameters();
  size_t n = batches.size();
  for (int i = 0; i < 6; ++i)
    avg[i] /= n;
  if (rmsd) {
    for (const Batch& batch : batches)
      for (int i = 0; i < 6; ++i)
        rmsd[i] += sq(avg[i] - batch.floats[i]);
    for (int i = 0; i < 6; ++i)
      rmsd[i] = std::sqrt(rmsd[i] / n);
  }
  // If average parameters are almost equal to the global cell, use the latter
  // to avoid 32-bit precision artifacts (58.28 -> 58.279998).
  if (UnitCellParameters(avg).approx(cell, 1e-4))
    return cell;
  return UnitCellParameters(avg);
}

std::array<double,2> Mtz::calculate_min_max_1_d2() const {
  auto extend_min_max_1_d2 = [&](const UnitCell& uc, double& min, double& max) {
    for (size_t i = 0; i < data.size(); i += columns.size()) {
      double res = uc.calculate_1_d2_double(data[i+0], data[i+1], data[i+2]);
      if (res < min)
        min = res;
      if (res > max)
        max = res;
    }
  };
  if (!has_data() || columns.size() < 3)
    fail("No data.");
  double min_value = INFINITY;
  double max_value = 0.;
  if (cell.is_crystal() && cell.a > 0)
    extend_min_max_1_d2(cell, min_value, max_value);
  const UnitCell* prev_cell = nullptr;
  for (const Dataset& ds : datasets)
    if (ds.cell.is_crystal() && ds.cell.a > 0 && ds.cell != cell &&
        (!prev_cell || ds.cell != *prev_cell)) {
      extend_min_max_1_d2(ds.cell, min_value, max_value);
      prev_cell = &ds.cell;
    }
  if (min_value == INFINITY)
    min_value = 0;
  return {{min_value, max_value}};
}

void Mtz::read_first_bytes(AnyStream& stream) {
  char buf[20] = {0};

  if (!stream.read(buf, 20))
    fail("Could not read the MTZ file (is it empty?)");
  if (buf[0] != 'M' || buf[1] != 'T' || buf[2] != 'Z' || buf[3] != ' ')
    fail("Not an MTZ file - it does not start with 'MTZ '");

  // Bytes 9-12 have so-called machine stamp:
  // "The first 4 half-bytes represent the real, complex, integer and
  // character formats".
  // We don't try to handle all the combinations here, only the two most
  // common: big endian (for all types) and little endian (for all types).
  // BE is denoted by 1 and LE by 4.
  // If we get a value different than 1 and 4 we assume the native byte order.
  if ((buf[9] & 0xf0) == (is_little_endian() ? 0x10 : 0x40))
    toggle_endianness();

  std::int32_t tmp_header_offset;
  std::memcpy(&tmp_header_offset, buf + 4, 4);
  if (!same_byte_order)
    swap_four_bytes(&tmp_header_offset);

  if (tmp_header_offset == -1) {
    std::memcpy(&header_offset, buf + 12, 8);
    if (!same_byte_order) {
      swap_eight_bytes(&header_offset);
    }
  } else {
    header_offset = (int64_t) tmp_header_offset;
  }
  stream.skip(60);
}

void Mtz::read_main_headers(AnyStream& stream, std::vector<std::string>* save_headers) {
  char line[81] = {0};
  std::ptrdiff_t header_pos = 4 * std::ptrdiff_t(header_offset - 1);
  // temporary check
  long cur_pos = stream.tell();
  if (cur_pos != header_pos && cur_pos != -1)
    fail(cat("wrong pos ", int(header_pos), "  ", int(stream.tell())));
  int ncol = 0;
  bool has_batch = false;
  while (stream.read(line, 80)) {
    if (save_headers)
      save_headers->emplace_back(line, line+80);
    if (ialpha3_id(line) == ialpha3_id("END"))
      break;
    const char* args = skip_word_and_space(line);
    switch (ialpha4_id(line)) {
      case ialpha4_id("VERS"):
        version_stamp = rtrim_str(args);
        break;
      case ialpha4_id("TITL"):
        title = rtrim_str(args);
        break;
      case ialpha4_id("NCOL"): {
        ncol = simple_atoi(args, &args);
        nreflections = simple_atoi(args, &args);
        int nbatches = simple_atoi(args);
        if (nbatches < 0 || nbatches > 10000000)  // sanity check
          fail("Wrong NCOL header");
        batches.resize(nbatches);
        break;
      }
      case ialpha4_id("CELL"):
        cell = read_cell_parameters(args);
        break;
      case ialpha4_id("SORT"):
        for (int& n : sort_order)
          n = simple_atoi(args, &args);
        break;
      case ialpha4_id("SYMI"): {
        nsymop = simple_atoi(args, &args);
        symops.reserve(nsymop);
        simple_atoi(args, &args); // ignore number of primitive operations
        args = skip_word_and_space(skip_blank(args)); // ignore lattice type
        spacegroup_number = simple_atoi(args, &args);
        args = skip_blank(args);
        if (*args != '\'')
          spacegroup_name = read_word(args);
        else if (const char* end = std::strchr(++args, '\''))
          spacegroup_name.assign(args, end);
        // ignore point group which is at the end of args
        break;
      }
      case ialpha4_id("SYMM"):
        symops.push_back(parse_triplet(args));
        break;
      case ialpha4_id("RESO"):
        min_1_d2 = fast_atof(args, &args);
        max_1_d2 = fast_atof(args, &args);
        break;
      case ialpha4_id("VALM"):
        if (*args != 'N') {
          const char* endptr;
          float v = (float) fast_atof(args, &endptr);
          if (*endptr == '\0' || is_space(*endptr))
            valm = v;
          else
            logger.note("Unexpected VALM value: " + rtrim_str(args));
        }
        break;
      case ialpha4_id("COLU"): {
        columns.emplace_back();
        Column& col = columns.back();
        col.label = read_word(args, &args);
        col.type = read_word(args, &args)[0];
        col.min_value = (float) fast_atof(args, &args);
        col.max_value = (float) fast_atof(args, &args);
        col.dataset_id = simple_atoi(args);
        col.parent = this;
        col.idx = columns.size() - 1;
        break;
      }
      case ialpha4_id("COLS"):
        // COLSRC is undocumented. CMTZ (libccp4) adds it after COLUMN:
        // COLUMN IMEAN                          J       -300.600006              4619    1
        // COLSRC IMEAN                          CREATED_07/08/2019_11:00:23              1
        if (!columns.empty() && columns.back().label == read_word(args, &args))
          columns.back().source = read_word(args);
        else
          logger.note("MTZ: COLSRC is not after matching COLUMN");
        break;
      case ialpha4_id("COLG"):
        // Column group - not used.
        break;
      case ialpha4_id("NDIF"):
        datasets.reserve(simple_atoi(args));
        break;
      case ialpha4_id("PROJ"):
        datasets.emplace_back();
        datasets.back().id = simple_atoi(args, &args);
        datasets.back().project_name = read_word(skip_word_and_space(args));
        datasets.back().wavelength = 0.0;
        break;
      case ialpha4_id("CRYS"):
        if (simple_atoi(args, &args) == last_dataset().id)
          datasets.back().crystal_name = read_word(args);
        else
          logger.note("MTZ CRYSTAL line: unusual numbering.");
        break;
      case ialpha4_id("DATA"):
        if (simple_atoi(args, &args) == last_dataset().id)
          datasets.back().dataset_name = read_word(args);
        else
          logger.note("MTZ DATASET line: unusual numbering.");
        break;
      case ialpha4_id("DCEL"):
        if (simple_atoi(args, &args) == last_dataset().id)
          datasets.back().cell = read_cell_parameters(args);
        else
          logger.note("MTZ DCELL line: unusual numbering.");
        break;
      // case("DRES"): not in use yet
      case ialpha4_id("DWAV"):
        if (simple_atoi(args, &args) == last_dataset().id)
          datasets.back().wavelength = fast_atof(args);
        else
          logger.note("MTZ DWAV line: unusual numbering.");
        break;
      case ialpha4_id("BATCH"):
        // We take number of batches from the NCOL record and serial numbers
        // from BH. This header could be used only to check consistency.
        has_batch = true;
        break;
      default:
        logger.note("Unknown header: " + rtrim_str(line));
    }
  }
  if (ncol != (int) columns.size())
    fail("Number of COLU records inconsistent with NCOL record.");
  if (has_batch != !batches.empty())
    fail("BATCH header inconsistent with NCOL record.");
  // adjust data size, if necessary
  if (!data.empty()) {
    size_t expected_size = columns.size() * nreflections;
    if (data.size() > expected_size)
      data.resize(expected_size);
    else if (data.size() < expected_size)
      fail("internal error, wrong data size");
  }
}

void Mtz::read_history_and_batch_headers(AnyStream& stream) {
  char buf[81] = {0};
  int n_headers = 0;
  while (stream.read(buf, 80) && ialpha4_id(buf) != ialpha4_id("MTZE")) {
    if (n_headers != 0) {
      const char* start = skip_blank(buf);
      const char* end = rtrim_cstr(start, start+80);
      history.emplace_back(start, end);
      --n_headers;
    } else if (ialpha4_id(buf) == ialpha4_id("MTZH")) {
      n_headers = simple_atoi(skip_word_and_space(buf+4));
      if (n_headers < 0 || n_headers > 30) {
        logger.note("Wrong MTZ: number of headers should be between 0 and 30");
        return;
      }
      history.reserve(n_headers);
    } else if (ialpha4_id(buf) == ialpha4_id("MTZB")) {
      for (Batch& batch : batches) {
        stream.read(buf, 80);
        if (ialpha3_id(buf) != ialpha3_id("BH "))
          fail("Missing BH header");
        const char* args = skip_blank(buf + 2);
        batch.number = simple_atoi(args, &args);
        int total_words = simple_atoi(args, &args);
        int int_words = simple_atoi(args, &args);
        int float_words = simple_atoi(args);
        if (total_words != int_words + float_words || total_words > 1000)
          fail("Wrong BH header");
        stream.read(buf, 80); // TITLE
        const char* end = rtrim_cstr(buf + 6, buf+76);
        batch.title.assign(buf, end - buf);
        batch.ints.resize(int_words);
        stream.read(batch.ints.data(), int_words * 4);
        batch.floats.resize(float_words);
        stream.read(batch.floats.data(), float_words * 4);
        stream.read(buf, 80);
        if (ialpha4_id(buf) != ialpha4_id("BHCH"))
          fail("Missing BHCH header");
        split_str_into_multi(buf + 5, " \t", batch.axes);
      }
    }
  }
  appended_text = stream.read_rest();
}

void Mtz::setup_spacegroup() {
  spacegroup = find_spacegroup_by_name(spacegroup_name, cell.alpha, cell.gamma);
  if (!spacegroup) {
    logger.note("MTZ: unrecognized spacegroup name: " + spacegroup_name);
    return;
  }
  if (spacegroup->ccp4 != spacegroup_number)
    logger.note("MTZ: inconsistent spacegroup name and number");
  cell.set_cell_images_from_spacegroup(spacegroup);
  for (Dataset& d : datasets)
    d.cell.set_cell_images_from_spacegroup(spacegroup);
}

// we should be at byte 80
void Mtz::read_raw_data(AnyStream& stream, bool do_read) {
  size_t n = size_t(header_offset - 1 - 20);
  if (!do_read) {
    if (!stream.skip(4 * n))
      fail("ignoring mtz data segment failed");
    return;
  }
  data.resize(n);
  if (!stream.read(data.data(), 4 * n))
    fail("Error when reading MTZ data");
  if (!same_byte_order)
    for (float& f : data)
      swap_four_bytes(&f);
}

void Mtz::read_stream(AnyStream& stream, bool with_data) {
  read_first_bytes(stream);
  // The older implementation of MTZ reading first read the headers,
  // then the data. This required jumping to the headers at the end,
  // then back to the beginning of the data (byte 80).
  // The current implementation avoids calling seek(), allowing
  // incremental reading of streams (stdin, gzipped files, etc).
  read_raw_data(stream, with_data);
  read_main_headers(stream, nullptr);
  read_history_and_batch_headers(stream);
  setup_spacegroup();
  if (datasets.empty())
    datasets.push_back({0, "HKL_base", "HKL_base", "HKL_base", cell, 0.});
}

// for probing/testing individual reflections, no need to optimize it
size_t Mtz::find_offset_of_hkl(const Miller& hkl, size_t start) const {
  if (!has_data() || columns.size() < 3)
    fail("No data.");
  if (start != 0)
    start -= (start % columns.size());
  for (size_t n = start; n + 2 < data.size(); n += columns.size())
    if (get_hkl(n) == hkl)
      return n;
  return (size_t)-1;
}

void Mtz::ensure_asu(bool tnt_asu) {
  if (!is_merged())
    fail("Mtz::ensure_asu() is for merged MTZ only");
  if (!spacegroup)
    return;
  GroupOps gops = spacegroup->operations();
  ReciprocalAsu asu(spacegroup, tnt_asu);
  std::vector<int> phase_columns = positions_of_columns_with_type('P');
  std::vector<int> abcd_columns = positions_of_columns_with_type('A');
  std::vector<int> dano_columns = positions_of_columns_with_type('D');
  std::vector<std::pair<int,int>> plus_minus_columns = positions_of_plus_minus_columns();
  bool no_special_columns = phase_columns.empty() && abcd_columns.empty() &&
                            plus_minus_columns.empty() && dano_columns.empty();
  bool centric = no_special_columns || gops.is_centrosymmetric();
  for (size_t n = 0; n < data.size(); n += columns.size()) {
    Miller hkl = get_hkl(n);
    if (asu.is_in(hkl))
      continue;
    auto result = asu.to_asu(hkl, gops);
    // cf. impl::move_to_asu() in asudata.hpp
    set_hkl(n, result.first);
    if (no_special_columns)
      continue;
    int isym = result.second;
    if (!phase_columns.empty() || !abcd_columns.empty()) {
      const Op& op = gops.sym_ops[(isym - 1) / 2];
      double shift = op.phase_shift(hkl);
      bool negate = (isym % 2 == 0);
      for (int col : phase_columns)
        shift_phase(data[n + col], shift, negate);
      for (auto i = abcd_columns.begin(); i+3 < abcd_columns.end(); i += 4)
        // we expect coefficients HLA, HLB, HLC and HLD - in this order
        shift_hl_coefficients(data[n + *(i+0)], data[n + *(i+1)],
                              data[n + *(i+2)], data[n + *(i+3)],
                              shift, negate);
    }
    if (isym % 2 == 0 && !centric &&
        // usually, centric reflections have empty F(-), so avoid swapping it
        !gops.is_reflection_centric(hkl)) {
      for (std::pair<int,int> cols : plus_minus_columns)
        std::swap(data[n + cols.first], data[n + cols.second]);
      for (int col : dano_columns)
        data[n + col] = -data[n + col];
    }
  }
}

void Mtz::reindex(const Op& op) {
  if (op.tran != Op::Tran{0, 0, 0})
    gemmi::fail("reindexing operator must not have a translation");
  if (op.det_rot() < 0)
    gemmi::fail("reindexing operator must preserve the hand of the axes");
  switch_to_original_hkl();  // changes hkl for unmerged data only
  Op xyz_op = op.as_xyz();
  logger.mesg("Real space transformation: ", op.as_xyz().triplet());
  bool row_removal = false;
  // change Miller indices
  for (size_t n = 0; n < data.size(); n += columns.size()) {
    Miller hkl_den = op.apply_to_hkl_without_division(get_hkl(n));
    Miller hkl = Op::divide_hkl_by_DEN(hkl_den);
    if (hkl[0] * Op::DEN == hkl_den[0] &&
        hkl[1] * Op::DEN == hkl_den[1] &&
        hkl[2] * Op::DEN == hkl_den[2]) {
      set_hkl(n, hkl);
    } else {  // fractional hkl - remove
      row_removal = true;
      data[n] = NAN;  // mark for removal
    }
  }

  // remove reflections marked for removal
  if (row_removal) {
    int n_before = nreflections;
    remove_rows_if([](const float* h) { return std::isnan(*h); });
    logger.mesg("Reflections removed (because of fractional indices): ", n_before - nreflections);
  }

  switch_to_asu_hkl();  // revert switch_to_original_hkl() for unmerged data

  // change space group
  if (spacegroup) {
    GroupOps gops = spacegroup->operations();
    gops.change_basis_backward(xyz_op);
    const SpaceGroup* new_sg = find_spacegroup_by_ops(gops);
    if (!new_sg)
      fail("reindexing: failed to determine new space group name");
    if (new_sg != spacegroup) {
      logger.mesg("Space group changed from ", spacegroup->xhm(), " to ", new_sg->xhm(), '.');
      set_spacegroup(new_sg);
    } else {
      logger.mesg("Space group stays the same:", spacegroup->xhm(), '.');
    }
  }

  // change unit cell parameters
  cell = cell.changed_basis_backward(xyz_op, false);
  for (Mtz::Dataset& ds : datasets)
    ds.cell = ds.cell.changed_basis_backward(xyz_op, false);
  for (Mtz::Batch& batch : batches)
    batch.set_cell(batch.get_cell().changed_basis_backward(xyz_op, false));
}

void Mtz::expand_to_p1() {
  if (!spacegroup || !has_data())
    return;
  std::vector<int> phase_columns = positions_of_columns_with_type('P');
  std::vector<int> abcd_columns = positions_of_columns_with_type('A');
  bool has_phases = (!phase_columns.empty() || !abcd_columns.empty());
  GroupOps gops = spacegroup->operations();
  data.reserve(gops.sym_ops.size() * data.size());
  size_t orig_size = data.size();
  std::vector<Miller> hkl_copies;
  for (size_t n = 0; n < orig_size; n += columns.size()) {
    hkl_copies.clear();
    Miller hkl = get_hkl(n);
    // no reallocations because of reserve() above
    auto orig_iter = data.begin() + n;
    for (auto op = gops.sym_ops.begin() + 1; op < gops.sym_ops.end(); ++op) {
      Miller new_hkl = op->apply_to_hkl(hkl);
      Op::Miller negated{{-new_hkl[0], -new_hkl[1], -new_hkl[2]}};
      if (new_hkl != hkl && !in_vector(new_hkl, hkl_copies) &&
          negated != hkl && !in_vector(negated, hkl_copies)) {
        hkl_copies.push_back(new_hkl);
        size_t offset = data.size();
        data.insert(data.end(), orig_iter, orig_iter + columns.size());
        set_hkl(offset, new_hkl);
        if (has_phases) {
          double shift = op->phase_shift(hkl);
          if (shift != 0) {
            for (int col : phase_columns)
              shift_phase(data[offset + col], shift);
            for (auto i = abcd_columns.begin(); i+3 < abcd_columns.end(); i += 4)
              // we expect coefficients HLA, HLB, HLC and HLD - in this order
              shift_hl_coefficients(data[offset + *(i+0)], data[offset + *(i+1)],
                                    data[offset + *(i+2)], data[offset + *(i+3)], shift);
          }
        }
      }
    }
  }
  nreflections = int(data.size() / columns.size());
  sort_order = {{0, 0, 0, 0, 0}};
  set_spacegroup(&get_spacegroup_p1());
}

bool Mtz::switch_to_original_hkl() {
  if (indices_switched_to_original)
    return false;
  if (!has_data())
    fail("switch_to_original_hkl(): data not read yet");
  if (nreflections == 0) {
    // This function can be called before the data is populated
    // to set indices_switched_to_original, which is not exposed in Python.
    indices_switched_to_original = true;
    return true;
  }
  const Column* col = column_with_label("M/ISYM");
  if (col == nullptr || col->type != 'Y' || col->idx < 3)
    return false;
  std::vector<Op> inv_symops;
  inv_symops.reserve(symops.size());
  for (const Op& op : symops)
    inv_symops.push_back(op.inverse());
  for (size_t n = 0; n + col->idx < data.size(); n += columns.size()) {
    int isym = static_cast<int>(data[n + col->idx]) & 0xFF;
    const Op& op = inv_symops.at((isym - 1) / 2);
    Miller hkl = op.apply_to_hkl(get_hkl(n));
    int sign = (isym & 1) ? 1 : -1;
    for (int i = 0; i < 3; ++i)
      data[n+i] = static_cast<float>(sign * hkl[i]);
  }
  indices_switched_to_original = true;
  return true;
}

bool Mtz::switch_to_asu_hkl() {
  if (!indices_switched_to_original)
    return false;
  if (!has_data())
    fail("switch_to_asu_hkl(): data not read yet");
  const Column* col = column_with_label("M/ISYM");
  if (col == nullptr || col->type != 'Y' || col->idx < 3 || !spacegroup)
    return false;
  size_t misym_idx = col->idx;
  UnmergedHklMover hkl_mover(spacegroup);
  for (size_t n = 0; n + col->idx < data.size(); n += columns.size()) {
    Miller hkl = get_hkl(n);
    int isym = hkl_mover.move_to_asu(hkl);  // modifies hkl
    set_hkl(n, hkl);
    float& misym = data[n + misym_idx];
    misym = float(((int)misym & ~0xff) | isym);
  }
  indices_switched_to_original = false;
  return true;
}

void Mtz::read_file_gz(const std::string& path, bool with_data) {
  try {
    read_input(MaybeGzipped(path), with_data);
  } catch (std::runtime_error& e) {
    // append path to the error like in read_file(), but shouldn't the path go first?
    fail(std::string(e.what()) + ": " + path);
  }
}

std::vector<int> Mtz::sorted_row_indices(int use_first) const {
  if (!has_data())
    fail("No data.");
  if (use_first <= 0 || use_first >= (int) columns.size())
    fail("Wrong use_first arg in Mtz::sort.");
  std::vector<int> indices(nreflections);
  for (int i = 0; i != nreflections; ++i)
    indices[i] = i;
  std::stable_sort(indices.begin(), indices.end(), [&](int i, int j) {
    int a = i * (int) columns.size();
    int b = j * (int) columns.size();
    for (int n = 0; n < use_first; ++n)
      if (data[a+n] != data[b+n])
        return data[a+n] < data[b+n];
    return false;
  });
  return indices;
}

bool Mtz::sort(int use_first) {
  std::vector<int> indices = sorted_row_indices(use_first);
  sort_order = {{0, 0, 0, 0, 0}};
  for (int i = 0; i < use_first; ++i)
    sort_order[i] = i + 1;
  if (std::is_sorted(indices.begin(), indices.end()))
    return false;
  std::vector<float> new_data(data.size());
  size_t w = columns.size();
  for (size_t i = 0; i != indices.size(); ++i)
    std::memcpy(&new_data[i * w], &data[indices[i] * w], w * sizeof(float));
  data.swap(new_data);
  return true;
}

Mtz::Column& Mtz::add_column(const std::string& label, char type,
                             int dataset_id, int pos, bool expand_data) {
  if (datasets.empty())
    fail("No datasets.");
  if (dataset_id < 0)
    dataset_id = datasets.back().id;
  else
    dataset(dataset_id); // check if such dataset exist
  if (pos > (int) columns.size())
    fail("Requested column position after the end.");
  if (pos < 0)
    pos = (int) columns.size();
  auto col = columns.emplace(columns.begin() + pos);
  for (auto i = col + 1; i != columns.end(); ++i)
    i->idx++;
  col->dataset_id = dataset_id;
  col->type = type;
  col->label = label;
  col->parent = this;
  col->idx = pos;
  if (expand_data)
    expand_data_rows(1, pos);
  return *col;
}


namespace {  // helper functions for copying, replacing and removing columns

void check_column(const Mtz& mtz, size_t idx, const char* msg) {
  if (!mtz.has_data())
    fail(msg, ": data not read yet");
  if (idx >= mtz.columns.size())
    fail(msg, ": no column with 0-based index ", std::to_string(idx));
}

void check_trailing_cols(const Mtz& mtz, const Mtz::Column& src_col,
                         const std::vector<std::string>& trailing_cols) {
  assert(src_col.parent == &mtz);
  if (!mtz.has_data())
    fail("data in source mtz not read yet");
  if (src_col.idx + trailing_cols.size() >= mtz.columns.size())
    fail("Not enough columns after " + src_col.label);
  for (size_t i = 0; i < trailing_cols.size(); ++i)
    if (!trailing_cols[i].empty() &&
        trailing_cols[i] != mtz.columns[src_col.idx + i + 1].label)
      fail("expected trailing column ", trailing_cols[i], ", found ", src_col.label);
}

void do_replace_column(Mtz& mtz, size_t dest_idx, const Mtz::Column& src_col,
                       const std::vector<std::string>& trailing_cols) {
  const Mtz* src_mtz = src_col.parent;
  for (size_t i = 0; i <= trailing_cols.size(); ++i) {
    Mtz::Column& dst = mtz.columns[dest_idx + i];
    const Mtz::Column& src = src_mtz->columns[src_col.idx + i];
    dst.type = src.type;
    dst.label = src.label;
    dst.min_value = src.min_value;
    dst.max_value = src.max_value;
    dst.source = src.source;
    dst.dataset_id = src.dataset_id;
  }
  if (src_mtz == &mtz) {
    // internal copying
    for (size_t n = 0; n < mtz.data.size(); n += mtz.columns.size())
      for (size_t i = 0; i <= trailing_cols.size(); ++i)
        mtz.data[n + dest_idx + i] = mtz.data[n + src_col.idx + i];
  } else {
    // external copying - need to match indices
    std::vector<int> dst_indices = mtz.sorted_row_indices();
    std::vector<int> src_indices = src_mtz->sorted_row_indices();
    // cf. for_matching_reflections()
    size_t dst_stride = mtz.columns.size();
    size_t src_stride = src_mtz->columns.size();
    auto dst = dst_indices.begin();
    auto src = src_indices.begin();
    while (dst != dst_indices.end() && src != src_indices.end()) {
      Miller dst_hkl = mtz.get_hkl(*dst * dst_stride);
      Miller src_hkl = src_mtz->get_hkl(*src * src_stride);
      if (dst_hkl == src_hkl) {
        // copy values
        for (size_t i = 0; i <= trailing_cols.size(); ++i)
          mtz.data[*dst * dst_stride + dest_idx + i] =
            src_mtz->data[*src * src_stride + src_col.idx + i];
        ++dst;
        ++src;
      } else if (dst_hkl < src_hkl) {
        ++dst;
      } else {
        ++src;
      }
    }
  }
}

} // anonymous namespace

Mtz::Column& Mtz::replace_column(size_t dest_idx, const Mtz::Column& src_col,
                                 const std::vector<std::string>& trailing_cols) {
  check_trailing_cols(*src_col.parent, src_col, trailing_cols);
  check_column(*this, dest_idx + trailing_cols.size(), "replace_column()");
  do_replace_column(*this, dest_idx, src_col, trailing_cols);
  return columns[dest_idx];
}

Mtz::Column& Mtz::copy_column(int dest_idx, const Mtz::Column& src_col,
                              const std::vector<std::string>& trailing_cols) {
  // check input consistency
  if (!has_data())
    fail("copy_column(): data not read yet");
  check_trailing_cols(*src_col.parent, src_col, trailing_cols);
  // add new columns
  if (dest_idx < 0)
    dest_idx = (int) columns.size();
  // if src_col is from this Mtz it may get invalidated when adding columns
  int col_idx = -1;
  if (src_col.parent == this) {
    col_idx = (int) src_col.idx;
    if (col_idx >= dest_idx)
      col_idx += 1 + (int)trailing_cols.size();
  }
  for (int i = 0; i <= (int) trailing_cols.size(); ++i)
    add_column("", ' ', -1, dest_idx + i, false);
  expand_data_rows(1 + trailing_cols.size(), dest_idx);
  // copy the data
  const Column& src_col_now = col_idx < 0 ? src_col : columns[col_idx];
  // most of the work (hkl-based row matching and data copying) is done here:
  do_replace_column(*this, dest_idx, src_col_now, trailing_cols);
  return columns[dest_idx];
}

void Mtz::remove_column(size_t idx) {
  check_column(*this, idx, "remove_column()");
  columns.erase(columns.begin() + idx);
  for (size_t i = idx; i < columns.size(); ++i)
    --columns[i].idx;
  vector_remove_column(data, columns.size(), idx);
  assert(columns.size() * nreflections == data.size());
}


#define WRITE(...) do { \
    int len = snprintf_z(buf, 81, __VA_ARGS__); \
    if (len < 80) \
      std::memset(buf + len, ' ', 80 - len); \
    if (write(buf, 80, 1) != 1) \
      sys_fail("Writing MTZ file failed"); \
  } while(0)

template<typename Write>
void Mtz::write_to_stream(Write write) const {
  // uses: data, spacegroup, nreflections, batches, cell, sort_order,
  //       valm, columns, datasets, history
  if (!has_data())
    fail("Cannot write Mtz which has no data");
  if (!spacegroup)
    fail("Cannot write Mtz which has no space group");
  char buf[81] = {'M', 'T', 'Z', ' ', '\0'};
  std::int64_t real_header_start = (int64_t) columns.size() * nreflections + 21;
  std::int32_t header_start = (int32_t) real_header_start;
  if (real_header_start > std::numeric_limits<int32_t>::max()) {
    header_start = -1;
  } else {
    real_header_start = 0;
  }
  std::memcpy(buf + 4, &header_start, 4);
  std::int32_t machst = is_little_endian() ? 0x00004144 : 0x11110000;
  std::memcpy(buf + 8, &machst, 4);
  std::memcpy(buf + 12, &real_header_start, 8);
  if (write(buf, 80, 1) != 1 ||
      write(data.data(), 4, data.size()) != data.size())
    fail("Writing MTZ file failed");
  WRITE("VERS MTZ:V1.1");
  WRITE("TITLE %s", title.c_str());
  WRITE("NCOL %8zu %12d %8zu", columns.size(), nreflections, batches.size());
  if (cell.is_crystal())
    WRITE("CELL  %9.4f %9.4f %9.4f %9.4f %9.4f %9.4f",
          cell.a, cell.b, cell.c, cell.alpha, cell.beta, cell.gamma);
  WRITE("SORT  %3d %3d %3d %3d %3d", sort_order[0], sort_order[1],
        sort_order[2], sort_order[3], sort_order[4]);
  GroupOps ops = spacegroup->operations();
  char lat_type = spacegroup->ccp4_lattice_type();
  WRITE("SYMINF %3d %2d %c %5d %*s'%c%s' PG%s",
        ops.order(),               // number of symmetry operations
        (int) ops.sym_ops.size(),  // number of primitive operations
        lat_type,                  // lattice type
        spacegroup->ccp4,          // space group number
        20 - (int) std::strlen(spacegroup->hm), "",
        lat_type,                  // space group name (first letter)
        spacegroup->hm + 1,        // space group name (the rest)
        spacegroup->point_group_hm()); // point group name
  // If we have symops that are the same as spacegroup->operations(),
  // write symops to preserve the order of SYMM records.
  if (!symops.empty() && ops.is_same_as(split_centering_vectors(symops)))
    for (Op op : symops)
      WRITE("SYMM %s", to_upper(op.triplet()).c_str());
  else
    for (Op op : ops)
      WRITE("SYMM %s", to_upper(op.triplet()).c_str());
  auto reso = calculate_min_max_1_d2();
  WRITE("RESO %-20.12f %-20.12f", reso[0], reso[1]);
  if (std::isnan(valm))
    WRITE("VALM NAN");
  else
    WRITE("VALM %f", valm);
  auto format17 = [](float f) {
    char buffer[18];
    int len = snprintf_z(buffer, 18, "%.9f", f);
    return std::string(buffer, len > 0 ? std::min(len, 17) : 0);
  };
  for (const Column& col : columns) {
    auto minmax = calculate_min_max_disregarding_nans(col.begin(), col.end());
    const char* label = !col.label.empty() ? col.label.c_str() : "_";
    WRITE("COLUMN %-30s %c %17s %17s %4d",
          label, col.type,
          format17(minmax[0]).c_str(), format17(minmax[1]).c_str(),
          col.dataset_id);
    if (!col.source.empty())
      WRITE("COLSRC %-30s %-36s  %4d", label, col.source.c_str(), col.dataset_id);
  }
  WRITE("NDIF %8zu", datasets.size());
  for (const Dataset& ds : datasets) {
    WRITE("PROJECT %7d %s", ds.id, ds.project_name.c_str());
    WRITE("CRYSTAL %7d %s", ds.id, ds.crystal_name.c_str());
    WRITE("DATASET %7d %s", ds.id, ds.dataset_name.c_str());
    const UnitCell& uc = (ds.cell.is_crystal() && ds.cell.a > 0 ? ds.cell : cell);
    WRITE("DCELL %9d %10.4f%10.4f%10.4f%10.4f%10.4f%10.4f",
          ds.id, uc.a, uc.b, uc.c, uc.alpha, uc.beta, uc.gamma);
    WRITE("DWAVEL %8d %10.5f", ds.id, ds.wavelength);
  }
  int pos = 0;
  for (const Batch& batch : batches) {
    if (pos == 0) {
      std::memcpy(buf, "BATCH ", 6);  // NOLINT(bugprone-not-null-terminated-result)
      pos = 6;
    }
    snprintf_z(buf + pos, 7, "%6d", batch.number);
    pos += 6;
    if (pos + 6 > 80 || &batch == &batches.back()) {
      std::memset(buf + pos, ' ', 80 - pos);
      if (write(buf, 80, 1) != 1)
        fail("Writing MTZ file failed");
      pos = 0;
    }
  }
  WRITE("END");
  if (!history.empty()) {
    // According to mtzformat.html the file can have only up to 30 history
    // lines, but we don't enforce it here.
    WRITE("MTZHIST %3zu", history.size());
    for (const std::string& line : history)
      WRITE("%s", line.c_str());
  }
  if (!batches.empty()) {
    WRITE("MTZBATS");
    for (const Batch& batch : batches) {
      // keep the numbers the same as in files written by libccp4
      WRITE("BH %8d %7zu %7zu %7zu",
            batch.number, batch.ints.size() + batch.floats.size(),
            batch.ints.size(), batch.floats.size());
      WRITE("TITLE %.70s", batch.title.c_str());
      if (batch.ints.size() != 29 || batch.floats.size() != 156)
        fail("wrong size of binaries batch headers");
      write(batch.ints.data(), 4, batch.ints.size());
      write(batch.floats.data(), 4, batch.floats.size());
      WRITE("BHCH  %7.7s %7.7s %7.7s",
            batch.axes.size() > 0 ? batch.axes[0].c_str() : "",
            batch.axes.size() > 1 ? batch.axes[1].c_str() : "",
            batch.axes.size() > 2 ? batch.axes[2].c_str() : "");
    }
  }
  WRITE("MTZENDOFHEADERS");
  if (!appended_text.empty()) {
    if (write(appended_text.data(), appended_text.size(), 1) != 1)
      fail("Writing MTZ file failed");
  }
}

#undef WRITE

void Mtz::write_to_cstream(std::FILE* stream) const {
  write_to_stream([&](const void *ptr, size_t size, size_t nmemb) {
      return std::fwrite(ptr, size, nmemb, stream);
  });
}

void Mtz::write_to_string(std::string& str) const {
  // Calculate the size beforehand to avoid memory re-allocations
  // and minimize memory usage. It hasn't been benchmarked against
  // a single-pass writing.
  size_t nbytes = size_to_write();
  str.resize(nbytes);
  write_to_buffer(&str[0], nbytes);
}

void Mtz::write_to_file(const std::string& path) const {
  fileptr_t f = file_open(path.c_str(), "wb");
  try {
    write_to_cstream(f.get());
  } catch (std::runtime_error& e) {
    fail(std::string(e.what()) + ": " + path);
  }
}

size_t Mtz::size_to_write() const {
  size_t nbytes = 0;
  write_to_stream([&](const void *, size_t size, size_t nmemb) {
      nbytes += size * nmemb;
      return nmemb;
  });
  return nbytes;
}

size_t Mtz::write_to_buffer(char* buf, size_t maxlen) const {
  size_t len = 0;
  write_to_stream([&](const void *ptr, size_t size, size_t nmemb) {
      len += size * nmemb;
      if (len > maxlen)
        fail("Mtz::write_to_buffer: size too small");
      memcpy(buf, ptr, size * nmemb);
      buf += size * nmemb;
      return nmemb;
  });
  return len;
}

} // namespace gemmi
