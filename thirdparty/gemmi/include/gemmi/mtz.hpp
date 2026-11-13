/// @file
/// @brief MTZ reflection file format (X-ray crystallography).

// Copyright 2019 Global Phasing Ltd.
//
// MTZ reflection file format.

#ifndef GEMMI_MTZ_HPP_
#define GEMMI_MTZ_HPP_

#include <cassert>
#include <cmath>         // for isnan
#include <cstdint>       // for int32_t
#include <algorithm>     // for copy
#include <array>
#include <initializer_list>
#include <string>
#include <vector>
#include "fail.hpp"      // for fail
#include "input.hpp"     // for AnyStream, FileStream, CharArray
#include "iterator.hpp"  // for StrideIter
#include "logger.hpp"    // for Logger
#include "math.hpp"      // for rad, Mat33
#include "symmetry.hpp"  // for find_spacegroup_by_name, SpaceGroup
#include "unitcell.hpp"  // for UnitCell
#include "util.hpp"      // for ialpha4_id, rtrim_str, ialpha3_id, ...

namespace gemmi {

/// Helper for writing unmerged MTZ files with correct M/ISYM column values.
/// Converts Miller indices to ASU-equivalent and encodes the symmetry operation.
struct UnmergedHklMover {
  /// Initialize with spacegroup information.
  /// @param spacegroup The space group (may be null).
  UnmergedHklMover(const SpaceGroup* spacegroup) : asu_(spacegroup) {
    if (spacegroup)
      group_ops_ = spacegroup->operations();
  }

  /// Move HKL indices to ASU and return the encoded ISYM value.
  /// @param hkl [in,out] Miller indices; modified to ASU-equivalent values.
  /// @return ISYM value for the M/ISYM column (encodes symmetry operation).
  int move_to_asu(std::array<int, 3>& hkl) {
    std::pair<Miller, int> hkl_isym = asu_.to_asu(hkl, group_ops_);
    hkl = hkl_isym.first;
    return hkl_isym.second;
  }

private:
  ReciprocalAsu asu_;
  GroupOps group_ops_;
};

/// MTZ file metadata: crystallographic parameters, symmetry, and file structure.
struct MtzMetadata {
  /// Input file path (if known).
  std::string source_path;
  /// True if the file's byte order matches the system (not swapped).
  bool same_byte_order = true;
  /// For unmerged MTZ: true if HKL indices have been switched to original (non-ASU) values.
  bool indices_switched_to_original = false;
  /// Offset (in 32-bit words) to the start of the header block.
  std::int64_t header_offset = 0;
  /// Version stamp from VERS header line (e.g., "MTZ:V1.1").
  std::string version_stamp;
  /// Title from TITLE header line.
  std::string title;
  /// Number of reflections in the data array.
  int nreflections = 0;
  /// Sort order: columns used to sort reflections (0 = not used).
  std::array<int, 5> sort_order = {};
  /// Minimum 1/d² value in the file (d = 1/sqrt(1/d²)).
  double min_1_d2 = NAN;
  /// Maximum 1/d² value in the file.
  double max_1_d2 = NAN;
  /// VALM value: typically unused (for future use in CCP4).
  float valm = NAN;
  /// Number of symmetry operations (redundant with symops.size()).
  int nsymop = 0;
  /// Global unit cell parameters.
  UnitCell cell;
  /// CCP4 space group number.
  int spacegroup_number = 0;
  /// Space group name (Hermann-Mauguin, e.g., "P 21 21 21").
  std::string spacegroup_name;
  /// Symmetry operations read from SYMM header lines.
  std::vector<Op> symops;
  /// Pointer to the SpaceGroup object (from symmetry database).
  const SpaceGroup* spacegroup = nullptr;
  /// Historical processing steps (MTZHIST records).
  std::vector<std::string> history;
  /// Text appended after MTZENDOFHEADERS (non-standard).
  std::string appended_text;
  /// Logger for non-critical problems during file reading.
  Logger logger;
};

/// Representation of an MTZ reflection file.
/// Contains reflection data, column definitions, batch headers (for unmerged files),
/// and crystallographic metadata (cell, space group, symmetry operations).
struct GEMMI_DLL Mtz : public MtzMetadata {
  /// A dataset in the MTZ file hierarchy: project → crystal → dataset → columns.
  struct Dataset {
    /// Unique dataset ID (positive integer, typically starting at 1).
    int id;
    /// Project name (e.g., dataset owner or beamline).
    std::string project_name;
    /// Crystal name (e.g., sample identifier).
    std::string crystal_name;
    /// Dataset name (e.g., experiment or scan identifier).
    std::string dataset_name;
    /// Unit cell parameters for this dataset (overrides global cell if set).
    UnitCell cell;
    /// X-ray wavelength in Angstroms (0 = not set).
    double wavelength;
  };

  /// A column in the reflection data array.
  /// Stores one field per reflection (e.g., amplitude, phase, flag).
  struct Column {
    /// Dataset ID this column belongs to.
    int dataset_id;
    /// Column type code: 'H'=Miller index (H, K, or L), 'F'=amplitude,
    /// 'Q'=standard deviation, 'J'=intensity, 'M/ISYM'=symmetry flag (unmerged),
    /// 'D'=anomalous difference, 'P'=phase (degrees), 'W'=weight, 'A'=phase prob.,
    /// 'B'=batch number, 'Y'=M/ISYM, 'I'=integer, 'R'=R-factor, 'G'=F(+)/F(-),
    /// 'K'=I(+)/I(-), 'L'=string.
    char type;
    /// Column label (e.g., "FP", "SIGFP", "FWT", "PHWT").
    std::string label;
    /// Minimum value in this column (NAN if not computed).
    float min_value = NAN;
    /// Maximum value in this column (NAN if not computed).
    float max_value = NAN;
    /// Source of the data (from COLSRC header; e.g., derivation formula).
    std::string source;
    /// Pointer to parent Mtz object (for data access).
    Mtz* parent;
    /// Index of this column in parent->columns (used to access data array).
    std::size_t idx;

    /// Get the Dataset this column belongs to.
    Dataset& dataset() { return parent->dataset(dataset_id); }
    /// Get the Dataset this column belongs to (const).
    const Dataset& dataset() const { return parent->dataset(dataset_id); }
    /// True if parent Mtz has data loaded.
    bool has_data() const { return parent->has_data(); }
    /// Number of values in this column (0 if no data loaded).
    int size() const { return has_data() ? parent->nreflections : 0; }
    /// Stride between consecutive values in the data array (= number of columns).
    size_t stride() const { return parent->columns.size(); }
    /// Access column value for reflection n.
    /// @param n Reflection index (0 to nreflections-1).
    float& operator[](std::size_t n) { return parent->data[idx + n * stride()]; }
    /// Access column value for reflection n (const).
    float operator[](std::size_t n) const { return parent->data[idx + n * stride()]; }
    /// Access column value for reflection n with bounds checking.
    /// @param n Reflection index.
    /// @return Reference to the data value.
    /// @throws std::out_of_range if n is out of bounds.
    float& at(std::size_t n) { return parent->data.at(idx + n * stride()); }
    /// Access column value for reflection n with bounds checking (const).
    float at(std::size_t n) const { return parent->data.at(idx + n * stride()); }
    /// True if this column type represents an integer value.
    /// Returns true for types H, B, Y, I (indices, batch, ISYM, integers).
    bool is_integer() const {
      return type == 'H' || type == 'B' || type == 'Y' || type == 'I';
    }

    /// Find the next column in the same dataset with a specific type.
    /// @param next_type The column type to search for.
    /// @return Pointer to the next matching column, or nullptr.
    const Column* get_next_column_if_type(char next_type) const {
      if (idx + 1 < parent->columns.size()) {
        const Column& next_col = parent->columns[idx + 1];
        if (next_col.dataset_id == dataset_id && next_col.type == next_type)
          return &next_col;
      }
      return nullptr;
    }

    /// Iterator over this column's values.
    using iterator = StrideIter<float>;
    /// Begin iterator over all values in this column.
    iterator begin() {
      assert(parent);
      assert(&parent->columns[idx] == this);
      return iterator({parent->data.data(), idx, stride()});
    }
    /// End iterator for this column.
    iterator end() {
      return iterator({parent->data.data() + parent->data.size(), idx,
                       stride()});
    }
    /// Const iterator over this column's values.
    using const_iterator = StrideIter<const float>;
    /// Begin const iterator.
    const_iterator begin() const { return const_cast<Column*>(this)->begin(); }
    /// End const iterator.
    const_iterator end() const { return const_cast<Column*>(this)->end(); }
  };

  /// Batch header for unmerged MTZ files (one per diffraction image/sweep).
  /// Contains crystallographic and experimental metadata in fixed positions.
  struct Batch {
    /// Initialize a batch with default values (matching CCP4 COMBAT/Pointless).
    Batch() {
      ints.resize(29, 0);
      floats.resize(156, 0.);
      // write the same values that are written by CCP4 progs such as COMBAT
      ints[0] = 29 + 156;
      ints[1] = 29;
      ints[2] = 156;
      // COMBAT sets BSCALE=1, but Pointless sets it to 0.
      //floats[43] = 1.f; // batch scale
    }
    /// Batch number (usually 1-based).
    int number = 0;
    /// Title or description of the batch.
    std::string title;
    /// Integer values: ints[20] = dataset_id, ints[0,1,2] = sizes (fixed).
    std::vector<int> ints;
    /// Float values: floats[0-5] = cell, floats[6-14] = U matrix, floats[36-37] = phi range,
    /// floats[86] = wavelength.
    std::vector<float> floats;
    /// Axis names (e.g., "OMEGA", "KAPPA", "PHI").
    std::vector<std::string> axes;

    /// Extract unit cell parameters from batch header.
    /// @return Unit cell (a, b, c, alpha, beta, gamma).
    UnitCell get_cell() const {
      return UnitCell(floats[0], floats[1], floats[2],
                      floats[3], floats[4], floats[5]);
    }
    /// Set unit cell parameters in batch header.
    /// @param uc The unit cell to store.
    void set_cell(const UnitCell& uc) {
      floats[0] = (float) uc.a;
      floats[1] = (float) uc.b;
      floats[2] = (float) uc.c;
      floats[3] = (float) uc.alpha;
      floats[4] = (float) uc.beta;
      floats[5] = (float) uc.gamma;
    }

    /// Get the dataset ID from batch header.
    /// @return Dataset ID (from ints[20]).
    int dataset_id() const { return ints[20]; }
    /// Set the dataset ID in batch header.
    /// @param id Dataset ID to store in ints[20].
    void set_dataset_id(int id) { ints[20] = id; }
    /// Get the X-ray wavelength.
    /// @return Wavelength in Angstroms (from floats[86]).
    float wavelength() const { return floats[86]; }
    /// Set the X-ray wavelength.
    /// @param lambda Wavelength in Angstroms.
    void set_wavelength(float lambda) { floats[86] = lambda; }
    /// Get the phi rotation start angle.
    /// @return Start angle in degrees (from floats[36]).
    float phi_start() const { return floats[36]; }
    /// Get the phi rotation end angle.
    /// @return End angle in degrees (from floats[37]).
    float phi_end() const { return floats[37]; }
    /// Get the crystal orientation matrix U (3×3).
    /// @return U matrix from floats[6-14].
    Mat33 matrix_U() const {
      return Mat33(floats[6], floats[9],  floats[12],
                   floats[7], floats[10], floats[13],
                   floats[8], floats[11], floats[14]);
    }
  };

  /// All datasets in the file.
  std::vector<Dataset> datasets;
  /// All columns in the file (ordered by position in the data array).
  std::vector<Column> columns;
  /// Batch headers (empty for merged MTZ files).
  std::vector<Batch> batches;
  /// Reflection data: laid out as [col0_refl0, col1_refl0, ..., col0_refl1, col1_refl1, ...].
  /// Size = columns.size() * nreflections. Access via Column's operator[].
  std::vector<float> data;

  /// Create an empty MTZ object.
  /// @param with_base If true, initialize with a default HKL_base dataset and H, K, L columns.
  explicit Mtz(bool with_base=false) {
    if (with_base)
      add_base();
  }
  /// Move constructor.
  Mtz(Mtz&& o) noexcept { *this = std::move(o); }
  /// Move assignment. Updates parent pointers in all columns.
  Mtz& operator=(Mtz&& o) noexcept {
    MtzMetadata::operator=(std::move(o));
    datasets = std::move(o.datasets);
    columns = std::move(o.columns);
    batches = std::move(o.batches);
    data = std::move(o.data);
    for (Mtz::Column& col : columns)
      col.parent = this;
    return *this;
  }

  /// Copy constructor. Explicit to prevent accidental copies. Updates parent pointers.
  explicit Mtz(const Mtz& o) : MtzMetadata(o) {
    datasets = o.datasets;
    columns = o.columns;
    batches = o.batches;
    data = o.data;
    for (Mtz::Column& col : columns)
      col.parent = this;
  }

  /// Copy assignment is deleted (explicit copy constructor forces intentionality).
  Mtz& operator=(Mtz const&) = delete;

  /// Initialize with default HKL_base dataset and H, K, L columns.
  void add_base() {
    datasets.push_back({0, "HKL_base", "HKL_base", "HKL_base", cell, 0.});
    for (int i = 0; i != 3; ++i)
      add_column(std::string(1, "HKL"[i]), 'H', 0, i, false);
  }

  /// @name Crystallographic properties (after reading headers/data)
  /// @{

  /// Get the highest resolution in Angstroms.
  /// @return d_min = 1/sqrt(max_1_d2); resolution is high when d is small.
  double resolution_high() const { return std::sqrt(1.0 / max_1_d2); }
  /// Get the lowest resolution in Angstroms.
  /// @return d_max = 1/sqrt(min_1_d2); resolution is low when d is large.
  double resolution_low() const  { return std::sqrt(1.0 / min_1_d2); }

  /// Get the unit cell for a specific dataset or the global cell.
  /// @param dataset Dataset ID (default -1 = global cell, but searches datasets first).
  /// @return Reference to the unit cell.
  UnitCell& get_cell(int dataset=-1) {
    for (Dataset& ds : datasets)
      if (ds.id == dataset && ds.cell.is_crystal() && ds.cell.a > 0)
        return ds.cell;
    return cell;
  }

  /// Get the unit cell (const).
  const UnitCell& get_cell(int dataset=-1) const {
    return const_cast<Mtz*>(this)->get_cell(dataset);
  }

  /// Set the global and all per-dataset unit cells to the same value.
  /// @param new_cell The new unit cell parameters.
  void set_cell_for_all(const UnitCell& new_cell) {
    cell = new_cell;
    cell.set_cell_images_from_spacegroup(spacegroup);  // probably not needed
    for (Dataset& ds : datasets)
      ds.cell = cell;
  }

  /// Calculate average unit cell from all batch headers, optionally with RMSD.
  /// @param rmsd [out] Pointer to array of 6 doubles (a, b, c, alpha, beta, gamma RMSD),
  ///                   or nullptr to skip.
  /// @return Average cell from all batches, or global cell if batches are invalid.
  UnitCellParameters get_average_cell_from_batch_headers(double* rmsd) const;

  /// Set the space group and update related fields.
  /// @param new_sg Pointer to SpaceGroup (may be null).
  void set_spacegroup(const SpaceGroup* new_sg) {
    spacegroup = new_sg;
    spacegroup_number = new_sg ? spacegroup->ccp4 : 0;
    spacegroup_name = new_sg ? spacegroup->hm : "";
  }

  /// @}
  /// @name Dataset access
  /// @{

  /// Get the last (most recently added) dataset.
  /// @return Reference to the last dataset.
  /// @throws std::runtime_error if no datasets exist.
  Dataset& last_dataset() {
    if (datasets.empty())
      fail("MTZ dataset not found (missing DATASET header line?).");
    return datasets.back();
  }

  /// Get dataset by ID.
  /// @param id Dataset ID to look up.
  /// @return Reference to the dataset.
  /// @throws std::runtime_error if ID not found.
  Dataset& dataset(int id) {
    if ((size_t)id < datasets.size() && datasets[id].id == id)
      return datasets[id];
    for (Dataset& d : datasets)
      if (d.id == id)
        return d;
    fail("MTZ file has no dataset with ID " + std::to_string(id));
  }
  /// Get dataset by ID (const).
  const Dataset& dataset(int id) const {
    return const_cast<Mtz*>(this)->dataset(id);
  }

  /// Find a dataset by name.
  /// @param name Dataset name to search for.
  /// @return Pointer to the dataset, or nullptr if not found.
  Dataset* dataset_with_name(const std::string& name) {
    for (Dataset& d : datasets)
      if (d.dataset_name == name)
        return &d;
    return nullptr;
  }
  /// Find a dataset by name (const).
  const Dataset* dataset_with_name(const std::string& label) const {
    return const_cast<Mtz*>(this)->dataset_with_name(label);
  }

  /// @}
  /// @name Column access and queries
  /// @{

  /// Count columns with a specific label (may be > 1 if duplicates exist).
  /// @param label Column label to count.
  /// @return Number of columns with this label.
  int count(const std::string& label) const {
    int n = 0;
    for (const Column& col : columns)
      if (col.label == label)
        ++n;
    return n;
  }

  /// Count columns of a specific type.
  /// @param type Column type code (e.g., 'F', 'P', 'Q').
  /// @return Number of columns with this type.
  int count_type(char type) const {
    int n = 0;
    for (const Column& col : columns)
      if (col.type == type)
        ++n;
    return n;
  }

  /// Find the first column with a given label, optionally filtered by dataset and type.
  /// @param label Column label.
  /// @param ds [optional] Restrict search to this dataset (nullptr = any).
  /// @param type [optional] Restrict search to this type ('*' = any).
  /// @return Pointer to the column, or nullptr if not found.
  Column* column_with_label(const std::string& label, const Dataset* ds=nullptr, char type='*') {
    for (Column& col : columns)
      if (col.label == label && (!ds || ds->id == col.dataset_id)
                             && (type == '*' || type == col.type))
        return &col;
    return nullptr;
  }
  /// Find the first column with a given label (const).
  const Column* column_with_label(const std::string& label, const Dataset* ds=nullptr,
                                  char type='*') const {
    return const_cast<Mtz*>(this)->column_with_label(label, ds, type);
  }

  /// Get a column by label, raising an error if not found.
  /// @param label Column label.
  /// @param ds [optional] Restrict search to this dataset.
  /// @return Reference to the column.
  /// @throws std::runtime_error if column not found.
  const Column& get_column_with_label(const std::string& label, const Dataset* ds=nullptr) const {
    if (const Column* col = column_with_label(label, ds))
      return *col;
    fail("Column label not found: " + label);
  }

  /// Get all columns of a specific type.
  /// @param type Column type code.
  /// @return Vector of pointers to matching columns.
  std::vector<const Column*> columns_with_type(char type) const {
    std::vector<const Column*> cols;
    for (const Column& col : columns)
      if (col.type == type)
        cols.push_back(&col);
    return cols;
  }

  /// Get positions (indices) of all columns with a specific type.
  /// @param col_type Column type code.
  /// @return Vector of column indices.
  std::vector<int> positions_of_columns_with_type(char col_type) const {
    std::vector<int> cols;
    for (int i = 0; i < (int) columns.size(); ++i)
      if (columns[i].type == col_type)
        cols.push_back(i);
    return cols;
  }

  /// Find anomalous (±) column pairs by label pattern matching.
  /// Looks for labels with "(+)" and matches corresponding "(-)" columns.
  /// Note: F(+)/(-) pairs use type G, I(+)/(-) use type K, but E(+)/(-)
  /// have no dedicated type, so label matching is used.
  /// @return Vector of (index_plus, index_minus) pairs.
  std::vector<std::pair<int,int>> positions_of_plus_minus_columns() const {
    std::vector<std::pair<int,int>> r;
    for (int i = 0; i < (int) columns.size(); ++i) {
      const Column& col = columns[i];
      size_t sign_pos = col.label.find("(+)");
      if (sign_pos != std::string::npos) {
        std::string minus_label = columns[i].label;
        minus_label[sign_pos+1] = '-';
        for (int j = 0; j < (int) columns.size(); ++j)
          if (columns[j].label == minus_label &&
              columns[j].type == col.type &&
              columns[j].dataset_id == col.dataset_id) {
            r.emplace_back(i, j);
            break;
          }
      }
    }
    return r;
  }

  /// Find the first column matching any label in a prioritized list.
  /// @param labels List of labels to try in order.
  /// @param type [optional] Column type to match ('*' = any).
  /// @return Pointer to the first matching column, or nullptr.
  /// @note Order of labels matters; returns the first match.
  const Column* column_with_one_of_labels(std::initializer_list<const char*> labels,
                                          char type='*') const {
    for (const char* label : labels)
      if (const Column* col = column_with_label(label, nullptr, type))
        return col;
    return nullptr;
  }

  /// Find a column matching a type and any of several labels.
  /// @param type Column type to match.
  /// @param labels List of labels to search for.
  /// @return Pointer to the first matching column, or nullptr.
  /// @note Order of labels does not matter.
  Column* column_with_type_and_any_of_labels(char type, std::initializer_list<const char*> labels) {
    for (Column& col : columns)
      if (col.type == type) {
        for (const char* label : labels)
          if (col.label == label)
            return &col;
      }
    return nullptr;
  }

  /// Find the R-free flag column (common labels: FREE, RFREE, R_FREE_FLAGS, etc.).
  /// @return Pointer to R-free column (type 'I'), or nullptr.
  Column* rfree_column() {
    // cf. MtzToCif::default_spec in mtz2cif.hpp
    return column_with_type_and_any_of_labels('I',
        {"FREE", "RFREE", "FREER", "FreeR_flag", "R-free-flags", "FreeRflag", "R_FREE_FLAGS"});
  }
  /// Find the R-free flag column (const).
  const Column* rfree_column() const {
    return const_cast<Mtz*>(this)->rfree_column();
  }

  /// Find the mean intensity column (common labels: IMEAN, I, IOBS, I-obs).
  /// @return Pointer to intensity column (type 'J'), or nullptr.
  Column* imean_column() {
    return column_with_type_and_any_of_labels('J', {"IMEAN", "I", "IOBS", "I-obs"});
  }
  /// Find the mean intensity column (const).
  const Column* imean_column() const {
    return const_cast<Mtz*>(this)->imean_column();
  }

  /// Find the I(+) anomalous intensity column (common labels: I(+), IOBS(+), Iplus).
  /// @return Pointer to I(+) column (type 'K'), or nullptr.
  Column* iplus_column() {
    return column_with_type_and_any_of_labels('K', {"I(+)", "IOBS(+)", "I-obs(+)", "Iplus"});
  }
  /// Find the I(+) column (const).
  const Column* iplus_column() const {
    return const_cast<Mtz*>(this)->iplus_column();
  }

  /// Find the I(-) anomalous intensity column.
  /// @return Pointer to I(-) column (type 'K'), or nullptr.
  Column* iminus_column() {
    return column_with_type_and_any_of_labels('K', {"I(-)", "IOBS(-)", "I-obs(-)", "Iminus"});
  }
  /// Find the I(-) column (const).
  const Column* iminus_column() const {
    return const_cast<Mtz*>(this)->iminus_column();
  }

  /// @}
  /// @name Data status
  /// @{

  /// Check if reflection data has been loaded.
  /// @return True if data.size() == columns.size() * nreflections.
  bool has_data() const {
    return data.size() == columns.size() * nreflections;
  }

  /// Check if this is a merged MTZ file (no batch headers).
  /// @return True if batches.empty().
  bool is_merged() const { return batches.empty(); }

  /// Calculate min/max 1/d² from all reflections and unit cells.
  /// Considers both global cell and per-dataset DCELLs.
  /// @return [min_1_d2, max_1_d2].
  std::array<double,2> calculate_min_max_1_d2() const;

  /// Recalculate and update min_1_d2 and max_1_d2 from reflection data.
  void update_reso() {
    std::array<double,2> reso = calculate_min_max_1_d2();
    min_1_d2 = reso[0];
    max_1_d2 = reso[1];
  }

  /// @}
  /// @name File I/O
  /// @{

  /// Toggle the assumed byte order and swap header_offset accordingly.
  void toggle_endianness() {
    same_byte_order = !same_byte_order;
    swap_eight_bytes(&header_offset);
  }

  /// Read and verify the first 80 bytes (MTZ magic and machine stamp).
  /// @param stream Input stream positioned at file start.
  void read_first_bytes(AnyStream& stream);

  /// Read header records from VERS until END.
  /// @param stream Input stream positioned at the header block.
  /// @param save_headers [optional] Pointer to string vector to save header lines.
  void read_main_headers(AnyStream& stream, std::vector<std::string>* save_headers);

  /// Read history (MTZHIST) and batch (MTZBATS) records after the END header.
  /// @param stream Input stream positioned after END.
  void read_history_and_batch_headers(AnyStream& stream);

  /// Set up spacegroup pointer from spacegroup_number or spacegroup_name.
  void setup_spacegroup();

  /// Read raw reflection data from stream (float32 binary).
  /// @param stream Input stream.
  /// @param do_read If false, skip reading (compute space only).
  void read_raw_data(AnyStream& stream, bool do_read=true);

  /// Read all header records (convenience wrapper).
  /// @param stream Input stream.
  void read_all_headers(AnyStream& stream);

  /// Read MTZ from a stream, including headers and optionally data.
  /// Expects stream positioned at file start; reads in order: raw data, main headers, batch headers.
  /// @param stream Input stream.
  /// @param with_data If true, read reflection data; if false, skip it.
  void read_stream(AnyStream& stream, bool with_data);

  /// Read MTZ from a file path.
  /// @param path File path.
  /// @throws std::system_error or std::runtime_error on failure.
  void read_file(const std::string& path) {
    try {
      source_path = path;
      FileStream stream(path.c_str(), "rb");
      read_stream(stream, true);
    } catch (std::system_error&) {
      throw;  // system_error::what() includes path, don't add anything
    } catch (std::runtime_error& e) {
      fail(std::string(e.what()) + ": " + path);
    }
  }

  /// Read MTZ from an input object (e.g., MaybeGzipped for .mtz or .mtz.gz).
  /// @tparam Input Type with path() and create_stream() methods.
  /// @param input Input object.
  /// @param with_data If true, read reflection data.
  template<typename Input>
  void read_input(Input&& input, bool with_data) {
    source_path = input.path();
    read_stream(*input.create_stream(), with_data);
  }

  /// Read MTZ from a file, handling .gz compression automatically.
  /// @param path File path (.mtz or .mtz.gz).
  /// @param with_data If true, read reflection data (default true).
  void read_file_gz(const std::string& path, bool with_data=true);

  /// @}
  /// @name Data manipulation (reflection rows)
  /// @{

  /// Get sorted row indices based on the first N columns (HKL by default).
  /// @param use_first Number of columns to use for sorting (default 3 = h, k, l).
  /// @return Vector of indices [0..nreflections-1] sorted by the first N columns.
  std::vector<int> sorted_row_indices(int use_first=3) const;

  /// Sort reflections in-place using the first N columns.
  /// @param use_first Number of columns to use for sorting (default 3).
  /// @return True if any sorting was done; false if already sorted.
  bool sort(int use_first=3);

  /// Extract Miller indices from a reflection at a given offset in the data array.
  /// @param offset Offset to the first element of the reflection (H, K, L at offsets 0, 1, 2).
  /// @return Miller indices.
  Miller get_hkl(size_t offset) const {
    return {{(int)data[offset], (int)data[offset+1], (int)data[offset+2]}};
  }

  /// Set Miller indices at a given offset.
  /// @param offset Offset to the H element.
  /// @param hkl Miller indices to store.
  void set_hkl(size_t offset, const Miller& hkl) {
    for (int i = 0; i != 3; ++i)
      data[offset + i] = static_cast<float>(hkl[i]);
  }

  /// Find the data offset of the first reflection with specific Miller indices.
  /// @param hkl Miller indices to search for.
  /// @param start Starting offset (optional, default 0).
  /// @return Offset to the reflection, or (size_t)-1 if not found.
  /// @note This is a linear search; can be slow for large files.
  size_t find_offset_of_hkl(const Miller& hkl, size_t start=0) const;

  /// Move all reflections to ASU and adjust phases/anomalous data accordingly.
  /// For merged MTZ only. Transforms F(+), F(-), phases, and Hendrickson-Lattman coefficients.
  /// @param tnt_asu If true, use TNT ASU setting; if false, use default ASU.
  void ensure_asu(bool tnt_asu=false);

  /// Reindex reflections using a new basis and update space group accordingly.
  /// Applies symmetry operation to HKL, removes fractional indices, adjusts cell and space group.
  /// Outputs messages to logger.
  /// @param op Reindexing operation (must have no translation and determinant > 0).
  void reindex(const Op& op);

  /// Expand reflections to P1 using all symmetry operations.
  /// Duplicate reflections under symmetry, adjust phases if present.
  /// Similar to SFTOOLS EXPAND command.
  /// @note Does not re-sort; sort afterwards if needed.
  void expand_to_p1();

  /// For unmerged MTZ: convert HKL from ASU to original (observer) indices.
  /// Reads M/ISYM column and applies inverse symmetry operations.
  /// @return True if M/ISYM column was found and data was modified.
  bool switch_to_original_hkl();

  /// For unmerged MTZ: convert HKL to ASU and set M/ISYM column accordingly.
  /// @return True if M/ISYM column was found and data was modified.
  bool switch_to_asu_hkl();

  /// @}
  /// @name Data construction
  /// @{

  /// Create a new dataset with auto-assigned ID and add to the file.
  /// @param name Name to use for project, crystal, and dataset.
  /// @return Reference to the newly added dataset.
  Dataset& add_dataset(const std::string& name) {
    int id = 0;
    for (const Dataset& d : datasets)
      if (d.id >= id)
        id = d.id + 1;
    datasets.push_back({id, name, name, name, cell, 0.0});
    return datasets.back();
  }

  /// Add a column to the file and optionally expand the data array.
  /// @param label Column label.
  /// @param type Column type code.
  /// @param dataset_id Dataset ID for this column (-1 = last dataset).
  /// @param pos Position in column list (-1 = append).
  /// @param expand_data If true, insert empty rows (NAN) in the data array.
  /// @return Reference to the newly added column.
  Column& add_column(const std::string& label, char type,
                     int dataset_id, int pos, bool expand_data);

  /// Replace a column with data from another column (including trailing columns).
  /// @param dest_idx Destination column index.
  /// @param src_col Source column to copy from.
  /// @param trailing_cols [optional] Labels of columns immediately after src_col to also copy.
  /// @return Reference to the destination column.
  Column& replace_column(size_t dest_idx, const Column& src_col,
                         const std::vector<std::string>& trailing_cols={});

  /// Copy a column to a destination, or append if dest_idx < 0.
  /// @param dest_idx Destination index (-1 = append).
  /// @param src_col Source column.
  /// @param trailing_cols [optional] Labels of subsequent columns to also copy.
  /// @return Reference to the destination column.
  Column& copy_column(int dest_idx, const Column& src_col,
                      const std::vector<std::string>& trailing_cols={});

  /// Remove a column from the file and data array.
  /// @param idx Column index to remove.
  void remove_column(size_t idx);

  /// Remove reflection rows matching a condition.
  /// @tparam Func Callable that takes pointer to row data and returns true to remove.
  /// @param condition Predicate function.
  template <typename Func>
  void remove_rows_if(Func condition) {
    if (!has_data())
      fail("No data.");
    auto out = data.begin();
    size_t width = columns.size();
    for (auto r = data.begin(); r < data.end(); r += width)
      if (!condition(&*r)) {
        if (r != out)
          std::copy(r, r + width, out);
        out += width;
      }
    data.erase(out, data.end());
    nreflections = int(data.size() / width);
  }

  /// Insert new empty columns in the data array.
  /// @param added Number of columns to insert.
  /// @param pos_ Position to insert at (-1 = at the end).
  void expand_data_rows(size_t added, int pos_=-1) {
    size_t old_row_size = columns.size() - added;
    if (data.size() != old_row_size * nreflections)
      fail("Internal error");
    size_t pos = pos_ == -1 ? old_row_size : (size_t) pos_;
    if (pos > old_row_size)
      fail("expand_data_rows(): pos out of range");
    vector_insert_columns(data, old_row_size, (size_t)nreflections, added, pos, NAN);
  }

  /// Replace the reflection data array with new data.
  /// @param new_data Pointer to float array.
  /// @param n Total number of floats (must be divisible by columns.size()).
  /// @throws std::runtime_error if n is not a multiple of columns.size().
  void set_data(const float* new_data, size_t n) {
    size_t ncols = columns.size();
    if (n % ncols != 0)
      fail("Mtz.set_data(): expected " + std::to_string(ncols) + " columns.");
    nreflections = int(n / ncols);
    data.assign(new_data, new_data + n);
  }

  /// @}
  /// @name File output
  /// @{

  /// Write MTZ to a C FILE stream.
  /// @param stream Open FILE* stream (should be in binary write mode).
  void write_to_cstream(std::FILE* stream) const;

  /// Write MTZ to a string (binary data).
  /// @param str [out] String to append the binary MTZ data to.
  void write_to_string(std::string& str) const;

  /// Write MTZ to a file.
  /// @param path File path.
  void write_to_file(const std::string& path) const;

  /// Get the size of the binary MTZ output in bytes.
  /// @return Size needed for the complete MTZ file.
  size_t size_to_write() const;

  /// Write MTZ to a buffer.
  /// @param buf Pointer to output buffer.
  /// @param maxlen Maximum bytes to write.
  /// @return Number of bytes written.
  size_t write_to_buffer(char* buf, size_t maxlen) const;

private:
  /// Generic write implementation (template to support FILE*, string, buffer).
  /// @tparam Write Function type (size_t write(const void*, size_t, size_t)).
  template<typename Write> void write_to_stream(Write write) const;
};

/// @}

/// Convenience function: read MTZ from a file path.
/// @param path File path.
/// @return Loaded Mtz object.
inline Mtz read_mtz_file(const std::string& path) {
  Mtz mtz;
  mtz.read_file(path);
  return mtz;
}

/// Convenience function: read MTZ from an input object (handles gzip).
/// @tparam Input Type with path() and create_stream() methods.
/// @param input Input object (e.g., MaybeGzipped).
/// @param with_data If true, read reflection data; if false, headers only.
/// @return Loaded Mtz object.
template<typename Input>
Mtz read_mtz(Input&& input, bool with_data) {
  Mtz mtz;
  mtz.read_input(std::forward<Input>(input), with_data);
  return mtz;
}

/// Abstraction layer for accessing MTZ data uniformly.
/// Provides stride, data access, and cell/symmetry information.
/// Similar to ReflnDataProxy for reflection data in other formats.
struct MtzDataProxy {
  /// Reference to the MTZ object.
  const Mtz& mtz_;
  /// Stride (number of columns) between consecutive reflections.
  size_t stride() const { return mtz_.columns.size(); }
  /// Total number of floats in the data array.
  size_t size() const { return mtz_.data.size(); }
  /// Element type (always float).
  using num_type = float;
  /// Access a data element by index.
  /// @param n Index into the flat data array.
  float get_num(size_t n) const { return mtz_.data[n]; }
  /// Get the unit cell.
  const UnitCell& unit_cell() const { return mtz_.cell; }
  /// Get the space group.
  const SpaceGroup* spacegroup() const { return mtz_.spacegroup; }
  /// Get Miller indices from a reflection.
  /// @param offset Offset to the H element.
  Miller get_hkl(size_t offset) const { return mtz_.get_hkl(offset); }

  /// Find the column index for a given label.
  /// @param label Column label.
  /// @return Column index (idx).
  /// @throws std::runtime_error if label not found.
  size_t column_index(const std::string& label) const {
    if (const Mtz::Column* col = mtz_.column_with_label(label))
      return col->idx;
    fail("MTZ file has no column with label: " + label);
  }
};

/// MtzDataProxy variant for external data (not stored in Mtz).
/// Wraps MTZ metadata with a separate data array pointer.
struct MtzExternalDataProxy : MtzDataProxy {
  /// Pointer to external data array.
  const float* data_;
  /// Initialize with MTZ metadata and external data.
  /// @param mtz MTZ object (for structure info only).
  /// @param data Pointer to external float array (size = columns.size() * nreflections).
  MtzExternalDataProxy(const Mtz& mtz, const float* data)
    : MtzDataProxy{mtz}, data_(data) {}
  /// Total size of the external data array.
  size_t size() const { return mtz_.columns.size() * mtz_.nreflections; }
  /// Access element from external data.
  float get_num(size_t n) const { return data_[n]; }
  /// Get Miller indices from external data.
  Miller get_hkl(size_t offset) const {
    return {{(int)data_[offset + 0],
             (int)data_[offset + 1],
             (int)data_[offset + 2]}};
  }
};

/// Create a proxy for accessing MTZ data.
/// @param mtz MTZ object.
/// @return MtzDataProxy wrapping the MTZ.
inline MtzDataProxy data_proxy(const Mtz& mtz) { return {mtz}; }

} // namespace gemmi

#endif
