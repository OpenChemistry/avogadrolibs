/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cjsonformat.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/propertymap.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <nlohmann/json.hpp>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace Avogadro::Io {

using std::string;
using std::vector;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Cube;
using Core::GaussianSet;
using Core::LayerData;
using Core::LayerManager;
using Core::Molecule;
using Core::Residue;
using Core::Variant;

bool setJsonKey(json& j, Molecule& m, const std::string& key)
{
  if (j.count(key) && j.find(key)->is_string()) {
    m.setData(key, j.value(key, "undefined"));
    return true;
  }
  return false;
}

bool isNumericArray(const json& j)
{
  if (j.is_array() && j.size() > 0) {
    for (const auto& v : j) {
      if (!v.is_number()) {
        return false;
      }
    }
    return true;
  }
  return false;
}

bool isBooleanArray(const json& j)
{
  if (j.is_array() && j.size() > 0) {
    for (const auto& v : j) {
      if (!v.is_boolean()) {
        return false;
      }
    }
    return true;
  }
  return false;
}

// A member of a JSON object, looked up without the two side effects of
// operator[]: it throws when the parent is not an object at all, and it
// inserts a null member when the key is missing. CJSON is hand-editable, so a
// section the reader expects to be an object can be anything -- and a
// wrong-typed optional section should be skipped, not fail the whole file.
const json& member(const json& parent, const char* key)
{
  static const json missing;
  if (!parent.is_object())
    return missing;
  auto it = parent.find(key);
  return it == parent.end() ? missing : *it;
}

// Layer ids index per-layer state, and the label and cartoon plugins loop
// `for (layer < layerCount())` when rendering, so an unbounded id read from a
// file would just move the hang out of the reader and into the GUI. 255 is
// far beyond any real use.
constexpr size_t kMaxLayers = 255;

// A checked json-to-integer conversion. nlohmann's own numeric conversion is
// a bare static_cast: a double outside the target type's range is undefined
// behaviour, and reading the wrong json type throws rather than returning
// something a caller can skip. CJSON is hand-editable, so both are routine
// here, and a malformed field must be skipped rather than crash the reader.
template <typename T>
std::optional<T> toInteger(const json& j)
{
  if (!j.is_number())
    return std::nullopt;

  if (j.is_number_unsigned()) {
    const auto value = j.get<std::uint64_t>();
    if (value > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
      return std::nullopt;
    return static_cast<T>(value);
  }

  if (j.is_number_integer()) {
    const auto value = j.get<std::int64_t>();
    if constexpr (std::is_unsigned_v<T>) {
      if (value < 0 ||
          static_cast<std::uint64_t>(value) >
            static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
        return std::nullopt;
    } else {
      if (value < static_cast<std::int64_t>(std::numeric_limits<T>::min()) ||
          value > static_cast<std::int64_t>(std::numeric_limits<T>::max()))
        return std::nullopt;
    }
    return static_cast<T>(value);
  }

  // is_number_float(): truncate toward zero, matching the existing
  // static_cast<int>(1.5) == 1 behaviour for values already in range -- this
  // is not the place to start rejecting non-integral input. The range test
  // has to be exact for a 64-bit T, so compare against ldexp(1, digits)
  // rather than numeric_limits<T>::max() widened to double, which would round
  // up past the true bound for a 64-bit integer type.
  const double d = j.get<double>();
  const double upper = std::ldexp(1.0, std::numeric_limits<T>::digits);
  // Written so that NaN, which compares false against everything, is
  // rejected rather than falling through to the cast below. Unsigned uses an
  // exclusive -1.0 rather than -upper (== 0) so that a small negative value
  // whose truncated (toward zero) integral part is representable, e.g. -0.5,
  // still converts the way static_cast<unsigned>(-0.5) == 0 already does.
  const bool inRange = std::is_unsigned_v<T> ? (d > -1.0 && d < upper)
                                             : (d >= -upper && d < upper);
  if (!inRange)
    return std::nullopt;
  return static_cast<T>(d);
}

// Convert every element of a numeric array with toInteger<T>(), all or
// nothing: a partially converted array (e.g. one bad occupation out of a
// thousand) would silently misalign with whatever it is indexed against, so
// one failure discards the whole array rather than a single element of it.
template <typename T>
std::optional<std::vector<T>> toIntegerArray(const json& arr)
{
  if (!isNumericArray(arr))
    return std::nullopt;
  std::vector<T> result;
  result.reserve(arr.size());
  for (const auto& v : arr) {
    auto value = toInteger<T>(v);
    if (!value)
      return std::nullopt;
    result.push_back(*value);
  }
  return result;
}

// The std::vector<float> that Cube::setData() takes, built explicitly and
// clamped the way lexicalCast<float> (avogadro/core/utilities.h) is: nlohmann
// converts a double to float with a bare static_cast, which is undefined
// behaviour once the magnitude exceeds what float can hold, so a value beyond
// the representable range is saturated instead of passed through.
float toClampedFloat(const json& value)
{
  const double d = value.get<double>();
  constexpr double floatMax =
    static_cast<double>(std::numeric_limits<float>::max());
  if (d > floatMax)
    return std::numeric_limits<float>::max();
  if (d < -floatMax)
    return std::numeric_limits<float>::lowest();
  return static_cast<float>(d);
}

json eigenColToJson(const MatrixX& matrix, int column)
{
  json j;
  j = json::array();
  for (Eigen::Index i = 0; i < matrix.rows(); ++i) {
    j.push_back(matrix(i, column));
  }
  return j;
}

using Core::PropertyMap;

/** Deserialize a JSON object of named arrays into a PropertyMap. */
// Decimal index used as a key in a sparse map. Anything that is not a run of
// digits is not an index; those entries are skipped rather than folded into
// conformer 0, which would silently merge unrelated data.
bool parseIndexKey(const std::string& key, size_t& index)
{
  if (key.empty())
    return false;
  index = 0;
  for (char c : key) {
    if (c < '0' || c > '9')
      return false;
    index = index * 10 + static_cast<size_t>(c - '0');
  }
  return true;
}

// One conformer's vibrational data. Mirrors serializeVibrations().
void deserializeVibrations(const json& vibrations, Core::Molecule& molecule,
                           size_t conformerIndex)
{
  if (!vibrations.is_object())
    return;

  Array<double> freqs;
  const json& frequencies = member(vibrations, "frequencies");
  if (isNumericArray(frequencies)) {
    freqs.reserve(frequencies.size());
    for (const auto& frequency : frequencies)
      freqs.push_back(static_cast<double>(frequency));
    molecule.setVibrationFrequencies(freqs, conformerIndex);
  }

  // The intensity arrays are indexed by the frequency count elsewhere, so
  // only accept one that matches it. Unlike every other reader, CJSON is
  // hand-editable and may carry intensities without frequencies at all.
  const size_t modes = freqs.size();

  const json& intensities = member(vibrations, "intensities");
  if (isNumericArray(intensities) && intensities.size() == modes) {
    Array<double> intens;
    intens.reserve(modes);
    for (const auto& intensity : intensities)
      intens.push_back(static_cast<double>(intensity));
    molecule.setVibrationIRIntensities(intens, conformerIndex);
  }

  const json& raman = member(vibrations, "ramanIntensities");
  if (isNumericArray(raman) && raman.size() == modes) {
    Array<double> intens;
    intens.reserve(modes);
    for (const auto& i : raman)
      intens.push_back(static_cast<double>(i));
    molecule.setVibrationRamanIntensities(intens, conformerIndex);
  }

  const json& displacements = member(vibrations, "eigenVectors");
  if (displacements.is_array()) {
    Array<Array<Vector3>> disps;
    disps.reserve(displacements.size());
    // Take each eigenvector by reference: by value copies every coordinate
    // out of the document before reading it once.
    for (const auto& arr : displacements) {
      // Each eigenvector is a flat list of x,y,z triples written straight
      // into the Vector3 buffer below. A length that is not a multiple of
      // three would run past the end of that buffer. isNumericArray()
      // already rejects an empty array.
      if (isNumericArray(arr) && arr.size() % 3 == 0) {
        Array<Vector3> mode;
        mode.resize(arr.size() / 3);
        double* ptr = &mode[0][0];
        for (const auto& j : arr)
          *(ptr++) = static_cast<double>(j);
        disps.push_back(mode);
      }
    }
    molecule.setVibrationLx(disps, conformerIndex);
  }
}

void deserializeProperties(const json& obj, PropertyMap& props,
                           size_t expectedCount)
{
  if (!obj.is_object())
    return;
  for (auto& property : obj.items()) {
    const auto& value = property.value();
    const auto& key = property.key();

    // Sparse matrix column: object of {"_type":"matrix","entries":{...}}
    // member()==literal never throws, unlike value.value("_type", ""), which
    // throws if "_type" is present but not a string.
    if (value.is_object() && member(value, "_type") == "matrix" &&
        value.contains("entries") && value["entries"].is_object()) {
      for (auto& entry : value["entries"].items()) {
        const auto& m = entry.value();
        if (!m.is_object())
          continue;
        const auto rows = toInteger<Eigen::Index>(member(m, "rows"));
        const auto cols = toInteger<Eigen::Index>(member(m, "cols"));
        const json& data = member(m, "data");
        if (!rows || !cols || *rows <= 0 || *cols <= 0 || !data.is_array())
          continue;
        // Guard the rows*cols product against overflow before computing it,
        // rather than after.
        const auto dataSize = static_cast<Eigen::Index>(data.size());
        if (*cols > dataSize / *rows || dataSize != *rows * *cols)
          continue;
        bool allNumeric = true;
        for (const auto& v : data) {
          if (!v.is_number()) {
            allNumeric = false;
            break;
          }
        }
        if (!allNumeric)
          continue;
        MatrixX matrix(*rows, *cols);
        for (Eigen::Index r = 0; r < *rows; ++r)
          for (Eigen::Index c = 0; c < *cols; ++c)
            matrix(r, c) = data[r * *cols + c].get<double>();
        Index idx = 0;
        if (parseIndexKey(entry.key(), idx))
          props.setMatrix(key, idx, matrix);
      }
      continue;
    }

    if (!value.is_array() || value.size() != expectedCount)
      continue;

    // Detect type from array elements
    bool allString = true;
    bool hasFloat = false;
    for (size_t i = 0; i < value.size(); ++i) {
      if (value[i].is_number()) {
        allString = false;
        if (value[i].is_number_float())
          hasFloat = true;
      } else if (!value[i].is_string()) {
        allString = false;
      }
    }

    // Use bulk setters for efficiency
    if (allString) {
      Array<std::string> values;
      values.reserve(value.size());
      for (size_t i = 0; i < value.size(); ++i)
        values.push_back(value[i].is_string() ? value[i].get<std::string>()
                                              : std::string());
      props.setStrings(key, values);
    } else if (hasFloat) {
      Array<double> values;
      values.reserve(value.size());
      for (size_t i = 0; i < value.size(); ++i)
        values.push_back(value[i].is_number() ? value[i].get<double>() : 0.0);
      props.setDoubles(key, values);
    } else {
      Array<int> values;
      values.reserve(value.size());
      for (size_t i = 0; i < value.size(); ++i)
        values.push_back(value[i].is_number_integer() ? value[i].get<int>()
                                                      : 0);
      props.setInts(key, values);
    }
  }
}

/** Serialize a PropertyMap into a JSON object of named arrays. */
// One conformer's vibrational data, in the flat shape CJSON has always used
// for the single-Hessian case. Written both at the top level (for the active
// conformer) and as the values of the sparse "conformers" map.
json serializeVibrations(const Core::Molecule& molecule, size_t conformerIndex)
{
  const auto frequencies = molecule.vibrationFrequencies(conformerIndex);
  const auto irIntensities = molecule.vibrationIRIntensities(conformerIndex);
  const auto ramanIntensities =
    molecule.vibrationRamanIntensities(conformerIndex);

  // Each intensity array is optional and is only written when it lines up
  // with the frequencies, so a Raman-only or frequency-only calculation still
  // round trips instead of being dropped for want of IR data.
  const size_t count = frequencies.size();
  const bool hasIR = irIntensities.size() == count;
  const bool hasRaman = ramanIntensities.size() == count;

  json modes;
  json freqs;
  json inten;
  json raman;
  json eigenVectors;
  bool hasEigenVectors = true;
  for (size_t i = 0; i < count; ++i) {
    modes.push_back(static_cast<unsigned int>(i) + 1);
    freqs.push_back(frequencies[i]);
    if (hasIR)
      inten.push_back(irIntensities[i]);
    if (hasRaman)
      raman.push_back(ramanIntensities[i]);
    Core::Array<Vector3> atomDisplacements =
      molecule.vibrationLx(static_cast<int>(i), conformerIndex);
    if (atomDisplacements.empty())
      hasEigenVectors = false;
    json eigenVector;
    for (auto pos : atomDisplacements) {
      eigenVector.push_back(pos[0]);
      eigenVector.push_back(pos[1]);
      eigenVector.push_back(pos[2]);
    }
    eigenVectors.push_back(std::move(eigenVector));
  }

  // Moved rather than assigned: nlohmann's operator= takes its argument by
  // value, so assigning these lvalues would deep copy every eigenvector.
  json vibrations;
  vibrations["modes"] = std::move(modes);
  vibrations["frequencies"] = std::move(freqs);
  if (hasIR)
    vibrations["intensities"] = std::move(inten);
  if (hasRaman)
    vibrations["ramanIntensities"] = std::move(raman);
  // Only write displacements if every mode has them; a partial set would be
  // read back as a mode count that disagrees with the frequencies.
  if (hasEigenVectors)
    vibrations["eigenVectors"] = std::move(eigenVectors);
  return vibrations;
}

json serializeProperties(const PropertyMap& props)
{
  json result;
  for (const auto& name : props.doubleNames()) {
    json arr;
    const auto& values = props.doubles(name);
    for (Index i = 0; i < values.size(); ++i)
      arr.push_back(values[i]);
    result[name] = arr;
  }
  for (const auto& name : props.intNames()) {
    json arr;
    const auto& values = props.ints(name);
    for (Index i = 0; i < values.size(); ++i)
      arr.push_back(values[i]);
    result[name] = arr;
  }
  for (const auto& name : props.stringNames()) {
    json arr;
    const auto& values = props.strings(name);
    for (Index i = 0; i < values.size(); ++i)
      arr.push_back(values[i]);
    result[name] = arr;
  }
  for (const auto& name : props.matrixNames()) {
    json entries = json::object();
    for (const auto& kv : props.matrices(name)) {
      const MatrixX& matrix = kv.second;
      json data = json::array();
      for (Eigen::Index r = 0; r < matrix.rows(); ++r)
        for (Eigen::Index c = 0; c < matrix.cols(); ++c)
          data.push_back(matrix(r, c));
      json entry;
      entry["rows"] = matrix.rows();
      entry["cols"] = matrix.cols();
      entry["data"] = data;
      entries[std::to_string(kv.first)] = entry;
    }
    json col;
    col["_type"] = "matrix";
    col["entries"] = entries;
    result[name] = col;
  }
  return result;
}

// Sanitize a raw string by replacing invalid UTF-8 sequences with '?'
// (to work around a bug in Open Babel space group output)
std::string sanitizeUtf8(const std::string& s)
{
  std::string result;
  result.reserve(s.size());
  const unsigned char* bytes = reinterpret_cast<const unsigned char*>(s.data());
  size_t len = s.size();

  for (size_t i = 0; i < len; ++i) {
    if (bytes[i] <= 0x7F) {
      result.push_back(static_cast<char>(bytes[i]));
      continue;
    }

    size_t remaining = 0;
    if ((bytes[i] & 0xE0) == 0xC0)
      remaining = 1;
    else if ((bytes[i] & 0xF0) == 0xE0)
      remaining = 2;
    else if ((bytes[i] & 0xF8) == 0xF0)
      remaining = 3;
    else {
      result.push_back('?'); // invalid lead byte
      continue;
    }

    if (i + remaining >= len) {
      result.push_back('?'); // truncated sequence
      continue;
    }

    bool valid = true;
    for (size_t j = 1; j <= remaining; ++j) {
      if ((bytes[i + j] & 0xC0) != 0x80) {
        valid = false;
        break;
      }
    }

    if (valid) {
      for (size_t j = 0; j <= remaining; ++j)
        result.push_back(static_cast<char>(bytes[i + j]));
      i += remaining;
    } else {
      result.push_back('?'); // invalid continuation
    }
  }
  return result;
}

bool CjsonFormat::read(std::istream& file, Molecule& molecule)
{
  return deserialize(file, molecule);
}

bool CjsonFormat::deserialize(std::istream& file, Molecule& molecule)
{
  json jsonRoot;

  try {
    // allow_exceptions = false: a malformed input yields a discarded value,
    // handled below, rather than an exception.
    jsonRoot = json::parse(file, nullptr, false);
  } catch (const json::exception& e) {
    // The base class covers all five nlohmann error types, so a number the
    // parser cannot represent (out_of_range) cannot escape and terminate.
    appendError("Error reading CJSON file: " + string(e.what()));
    return false;
  }

  if (jsonRoot.is_discarded()) {
    // Initial parse failed - try sanitizing UTF-8 and re-parsing
    file.clear();
    file.seekg(0);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    std::string sanitizedContent = sanitizeUtf8(content);
    jsonRoot = json::parse(sanitizedContent, nullptr, false);
  }

  if (jsonRoot.is_discarded()) {
    appendError("Error reading CJSON file. Root is discarded.");
    return false;
  }

  if (!jsonRoot.is_object()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  auto jsonValue = jsonRoot.find("chemicalJson");
  if (jsonValue == jsonRoot.end())
    jsonValue = jsonRoot.find("chemical json");
  if (jsonValue == jsonRoot.end()) {
    appendError("Error: no \"chemical json\" key found.");
    return false;
  }
  if (*jsonValue != 0 && *jsonValue != 1) {
    appendError("Warning: chemical json version is not 0 or 1.");
    return false;
  }

  // Read some basic key-value pairs (all strings).
  setJsonKey(jsonRoot, molecule, "name");
  setJsonKey(jsonRoot, molecule, "inchi");
  setJsonKey(jsonRoot, molecule, "formula");

  // Read in the atoms.
  json atoms = jsonRoot["atoms"];
  if (!atoms.is_object()) {
    appendError("The 'atoms' key does not contain an object.");
    return false;
  }

  if (!atoms.contains("elements")) {
    appendError("The 'atoms' key does not contain an 'elements' key.");
    return false;
  }

  if (atoms.contains("elements") && !atoms["elements"].is_object()) {
    appendError("The 'elements' key does not contain an object.");
    return false;
  }

  json elements = atoms["elements"];
  if (!elements.contains("number")) {
    appendError("The 'elements' key does not contain a 'number' key.");
    return false;
  }

  json atomicNumbers = elements["number"];
  // This represents our minimal spec for a molecule - atoms that have an
  // atomic number.
  if (isNumericArray(atomicNumbers) && atomicNumbers.size() > 0) {
    for (auto& atomicNumber : atomicNumbers) {
      if (!atomicNumber.is_number_integer() || atomicNumber < 0 ||
          atomicNumber >= Core::element_count) {
        appendError("Error: atomic number is invalid.");
        return false;
      }
      molecule.addAtom(atomicNumber);
    }
  } else {
    // we're done, actually - this is an empty file
    return true;
  }
  Index atomCount = molecule.atomCount();

  if (atoms.contains("coords") && atoms["coords"].is_object()) {
    if (atoms["coords"].contains("3d") && atoms["coords"]["3d"].is_array()) {
      json atomicCoords = atoms["coords"]["3d"];
      if (isNumericArray(atomicCoords) &&
          atomicCoords.size() == 3 * atomCount) {
        for (Index i = 0; i < atomCount; ++i) {
          auto a = molecule.atom(i);
          a.setPosition3d(Vector3(atomicCoords[3 * i], atomicCoords[3 * i + 1],
                                  atomicCoords[3 * i + 2]));
        }
      }
    }

    if (atoms["coords"].contains("3dSets")) {
      // Check for coordinate sets, and read them in if found, e.g.
      // trajectories.
      json coordSets = atoms["coords"]["3dSets"];
      if (coordSets.is_array() && coordSets.size()) {
        for (unsigned int i = 0; i < coordSets.size(); ++i) {
          Array<Vector3> setArray;
          json set = coordSets[i];
          if (isNumericArray(set)) {
            for (unsigned int j = 0; j < set.size() / 3; ++j) {
              setArray.push_back(
                Vector3(set[3 * j], set[3 * j + 1], set[3 * j + 2]));
            }
            molecule.setCoordinate3d(setArray, i);
          }
        }
        // Restore the set that was on screen when this was written, falling
        // back to the first step for files that predate "3dSetsActive". This
        // has to happen before the vibrations are read, since the unindexed
        // vibration setters write to the active conformer.
        int activeSet = 0;
        if (atoms["coords"].contains("3dSetsActive")) {
          const json& active = atoms["coords"]["3dSetsActive"];
          if (auto value = toInteger<int>(active))
            activeSet = *value;
        }
        if (!molecule.setCoordinate3d(activeSet))
          molecule.setCoordinate3d(0);
      }
    }
  }

  // Array of vector3 for forces if available
  if (atoms.contains("forces")) {
    json forces = atoms["forces"];
    if (isNumericArray(forces) && forces.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        auto a = molecule.atom(i);
        a.setForceVector(
          Vector3(forces[3 * i], forces[3 * i + 1], forces[3 * i + 2]));
      }
    }
  }

  // labels
  if (atoms.contains("labels")) {
    json labels = atoms["labels"];
    if (labels.is_array() && labels.size() == atomCount) {
      for (size_t i = 0; i < atomCount; ++i) {
        // Skip a non-string label rather than let the implicit conversion
        // below throw over one bad entry.
        if (labels[i].is_string())
          molecule.setAtomLabel(i, labels[i].get<std::string>());
      }
    }
  }

  // formal charges
  if (atoms.contains("formalCharges")) {
    json formalCharges = atoms["formalCharges"];
    if (formalCharges.is_array() && formalCharges.size() == atomCount) {
      for (size_t i = 0; i < atomCount; ++i) {
        if (auto charge = toInteger<signed char>(formalCharges[i]))
          molecule.atom(i).setFormalCharge(*charge);
      }
    }
  }

  // Read in colors if they are present.
  if (atoms.contains("colors")) {
    json colors = atoms["colors"];
    if (colors.is_array() && colors.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        // Only set the colour when all three channels convert; a partial
        // colour is worse than the default one the atom already has.
        auto r = toInteger<unsigned char>(colors[3 * i]);
        auto g = toInteger<unsigned char>(colors[3 * i + 1]);
        auto b = toInteger<unsigned char>(colors[3 * i + 2]);
        if (r && g && b)
          molecule.setColor(i, Vector3ub(*r, *g, *b));
      }
    }
  }

  if (atoms.contains("properties"))
    deserializeProperties(atoms["properties"], molecule.atomProperties(),
                          atomCount);

  // Selection is optional, but if present should be loaded.
  if (atoms.contains("selected")) {
    json selection = atoms["selected"];
    if (isBooleanArray(selection) && selection.size() == atomCount)
      for (Index i = 0; i < atomCount; ++i)
        molecule.setAtomSelected(i, selection[i]);
    else if (isNumericArray(selection) && selection.size() == atomCount)
      for (Index i = 0; i < atomCount; ++i)
        molecule.setAtomSelected(i, selection[i] != 0);
  }

  if (atoms.contains("frozen")) {
    json frozen = atoms["frozen"];
    if (frozen.is_array() && frozen.size() == atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        bool freeze = false;
        if (frozen[i].is_number())
          freeze = (frozen[i] != 0);
        else if (frozen[i].is_boolean())
          freeze = frozen[i];
        molecule.setFrozenAtom(i, freeze);
      }
    } // might also be a 3xN array for per-axis freezing
    else if (frozen.is_array() && frozen.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        bool freeze = false;
        if (frozen[3 * i].is_number())
          freeze = (frozen[3 * i] != 0);
        else if (frozen[3 * i].is_boolean())
          freeze = frozen[3 * i];
        molecule.setFrozenAtomAxis(i, 0, freeze);

        if (frozen[3 * i + 1].is_number())
          freeze = (frozen[3 * i + 1] != 0);
        else if (frozen[3 * i + 1].is_boolean())
          freeze = frozen[3 * i + 1];
        molecule.setFrozenAtomAxis(i, 1, freeze);

        if (frozen[3 * i + 2].is_number())
          freeze = (frozen[3 * i + 2] != 0);
        else if (frozen[3 * i + 2].is_boolean())
          freeze = frozen[3 * i + 2];
        molecule.setFrozenAtomAxis(i, 2, freeze);
      }
    }
  }

  if (atoms.find("layer") != atoms.end()) {
    json layerJson = atoms["layer"];
    if (layerJson.is_array()) {
      auto& layer = LayerManager::getMoleculeInfo(&molecule)->layer;
      for (Index i = 0; i < atomCount && i < layerJson.size(); ++i) {
        auto id = toInteger<size_t>(layerJson[i]);
        if (!id) {
          // Malformed id: leave this atom in the default layer instead of
          // failing the whole array.
          continue;
        }
        if (*id == MaxIndex) {
          // The writer emits Layer::getLayerID(i), which returns MaxIndex
          // for an atom in no layer, and Layer::addAtom already treats
          // MaxIndex as "no layer" without touching m_maxLayer. Passing it
          // through preserves the round trip -- a file Avogadro itself wrote
          // could previously hang here, in the while() loop this replaced.
          layer.addAtom(MaxIndex, i);
        } else if (*id >= kMaxLayers) {
          continue; // absurd id from a hand-edited file; skip it
        } else {
          // Layer::addAtom() grows the layer range itself, so no
          // while (id > layer.maxLayer()) layer.addLayer() loop is needed --
          // that loop is also what hung given a huge id.
          layer.addAtom(*id, i);
        }
      }
    }
  }

  // look for isotopes if present
  if (atoms.contains("isotopes")) {
    json isotopes = atoms["isotopes"];
    if (isotopes.is_array() && isotopes.size() == atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        if (auto isotope = toInteger<unsigned short>(isotopes[i]))
          molecule.setIsotope(i, *isotope);
      }
    }
  }

  // Bonds are optional, but if present should be loaded.
  if (jsonRoot.contains("bonds")) {
    json bonds = jsonRoot["bonds"];
    // "connections" (and "index" within it) may be anything in a
    // hand-edited file, so look them up with member() rather than indexing
    // bonds["connections"]["index"] directly -- that throws whenever
    // "connections" is not itself an object.
    const json& connections = member(member(bonds, "connections"), "index");
    if (bonds.is_object() && isNumericArray(connections)) {
      for (unsigned int i = 0; i < connections.size() / 2; ++i) {
        auto atom1 = toInteger<Index>(connections[2 * i]);
        auto atom2 = toInteger<Index>(connections[2 * i + 1]);
        if (atom1 && atom2 && *atom1 < atomCount && *atom2 < atomCount &&
            *atom1 != *atom2) { // avoid self-bonds
          molecule.addBond(*atom1, *atom2, 1);
        }
      }
      if (bonds.contains("order")) {
        json order = bonds["order"];
        if (isNumericArray(order)) {
          for (unsigned int i = 0; i < molecule.bondCount() && i < order.size();
               ++i) {
            // A conversion failure is treated the same as an out-of-range
            // order below: both are an invalid file.
            auto bondOrder = toInteger<int>(order[i]);
            if (!bondOrder || *bondOrder < 1 || *bondOrder > 6) {
              appendError("Error: bond order is invalid.");
              return false;
            }

            molecule.bond(i).setOrder(*bondOrder);
          }
        }
      }

      // are there bond labels?
      if (bonds.contains("labels")) {
        json bondLabels = bonds["labels"];
        if (bondLabels.is_array()) {
          for (unsigned int i = 0;
               i < molecule.bondCount() && i < bondLabels.size(); ++i) {
            if (bondLabels[i].is_string())
              molecule.setBondLabel(i, bondLabels[i].get<std::string>());
          }
        }
      }

      if (bonds.contains("properties"))
        deserializeProperties(bonds["properties"], molecule.bondProperties(),
                              molecule.bondCount());
    }
  }

  // residues are optional, but should be loaded
  if (jsonRoot.contains("residues")) {
    json residues = jsonRoot["residues"];
    if (residues.is_array()) {
      for (auto residue : residues) {
        if (!residue.is_object())
          continue; // malformed

        // Validate required fields exist and have correct types
        if (!residue.contains("name") || !residue["name"].is_string())
          continue;
        if (!residue.contains("id") || !residue["id"].is_number_integer())
          continue;
        if (!residue.contains("chainId") ||
            !residue["chainId"].is_number_integer())
          continue;

        auto name = residue["name"].get<std::string>();
        auto id = static_cast<Index>(residue["id"]);
        auto chainId = static_cast<char>(residue["chainId"].get<int>());
        Residue newResidue(name, id, chainId);

        if (residue.contains("hetero") && residue["hetero"] == true)
          newResidue.setHeterogen(true);

        // residue.value("secStruct", -1) throws if "secStruct" is present
        // but not a number; toInteger() never does.
        int secStruct =
          toInteger<int>(member(residue, "secStruct")).value_or(-1);
        // Residue::SecondaryStructure has no fixed underlying type, so
        // casting an arbitrary int to it (an out-of-range value from a
        // hand-edited file) is undefined behaviour. Only actual enumerators
        // may be cast; -1 ("undefined") is the default and is left alone, as
        // before.
        switch (secStruct) {
          case Residue::piHelix:
          case Residue::bend:
          case Residue::alphaHelix:
          case Residue::betaSheet:
          case Residue::helix310:
          case Residue::betaBridge:
          case Residue::turn:
          case Residue::coil:
          case Residue::maybeBeta:
            newResidue.setSecondaryStructure(
              static_cast<Residue::SecondaryStructure>(secStruct));
            break;
          default:
            break;
        }

        if (residue.contains("atoms") && residue["atoms"].is_object()) {
          json atomsResidue = residue["atoms"];
          for (auto& item : atomsResidue.items()) {
            if (item.value().is_number_integer() &&
                static_cast<Index>(item.value()) < molecule.atomCount()) {
              const Atom& atom =
                molecule.atom(static_cast<Index>(item.value()));
              newResidue.addResidueAtom(item.key(), atom);
            }
          }
        }
        if (residue.contains("color") && residue["color"].is_array() &&
            residue["color"].size() == 3) {
          const json& color = residue["color"];
          // Only set the colour when all three channels convert.
          auto r = toInteger<unsigned char>(color[0]);
          auto g = toInteger<unsigned char>(color[1]);
          auto b = toInteger<unsigned char>(color[2]);
          if (r && g && b)
            newResidue.setColor(Vector3ub(*r, *g, *b));
        }

        molecule.addResidue(newResidue);

        if (residue.contains("label") && residue["label"].is_string())
          molecule.setResidueLabel(molecule.residueCount() - 1,
                                   residue["label"]);
      }
    }
  }

  // Read residue properties (parallel arrays stored at root level)
  if (jsonRoot.contains("residueProperties"))
    deserializeProperties(jsonRoot["residueProperties"],
                          molecule.residueProperties(),
                          molecule.residueCount());

  // Read conformer properties (parallel arrays sized to coordinate3dCount()).
  // Must come after conformer coords are loaded (above at "3dSets").
  if (jsonRoot.contains("conformerProperties"))
    deserializeProperties(jsonRoot["conformerProperties"],
                          molecule.conformerProperties(),
                          molecule.coordinate3dCount());

  if (jsonRoot.contains("unitCell") || jsonRoot.contains("unit cell")) {
    json unitCell = jsonRoot["unitCell"];
    if (!unitCell.is_object())
      unitCell = jsonRoot["unit cell"];

    if (unitCell.is_object()) {
      Core::UnitCell* unitCellObject = nullptr;

      // read in cell vectors in preference to a, b, c parameters
      json cellVectors = unitCell["cellVectors"];
      if (cellVectors.is_array() && cellVectors.size() == 9 &&
          isNumericArray(cellVectors)) {
        Vector3 aVector(cellVectors[0], cellVectors[1], cellVectors[2]);
        Vector3 bVector(cellVectors[3], cellVectors[4], cellVectors[5]);
        Vector3 cVector(cellVectors[6], cellVectors[7], cellVectors[8]);
        unitCellObject = new Core::UnitCell(aVector, bVector, cVector);
        if (!unitCellObject->isRegular()) {
          appendError("cellVectors are not linear independent");
          delete unitCellObject;
          return false;
        }
      } else if (unitCell["a"].is_number() && unitCell["b"].is_number() &&
                 unitCell["c"].is_number() && unitCell["alpha"].is_number() &&
                 unitCell["beta"].is_number() &&
                 unitCell["gamma"].is_number()) {
        Real a = static_cast<Real>(unitCell["a"]);
        Real b = static_cast<Real>(unitCell["b"]);
        Real c = static_cast<Real>(unitCell["c"]);
        Real alpha = static_cast<Real>(unitCell["alpha"]) * DEG_TO_RAD;
        Real beta = static_cast<Real>(unitCell["beta"]) * DEG_TO_RAD;
        Real gamma = static_cast<Real>(unitCell["gamma"]) * DEG_TO_RAD;
        unitCellObject = new Core::UnitCell(a, b, c, alpha, beta, gamma);
        if (!unitCellObject->isRegular()) {
          appendError(
            "cell parameters do not give linear-independent lattice vectors");
          delete unitCellObject;
          return false;
        }
      }
      if (unitCellObject != nullptr) {
        molecule.setUnitCell(unitCellObject);

        // check for Hall number if present
        if (unitCell["hallNumber"].is_number()) {
          // A value present but out of int's range would otherwise be a bare,
          // undefined-behaviour static_cast; toInteger() rejects it instead,
          // and it simply fails the range check right below like it always
          // did for any other out-of-range hallNumber.
          if (auto hallNumber = toInteger<int>(unitCell["hallNumber"])) {
            if (*hallNumber > 0 && *hallNumber < 531)
              molecule.setHallNumber(*hallNumber);
          }
        } else if (unitCell["spaceGroup"].is_string()) {
          auto hallNumber =
            Core::SpaceGroups::hallNumber(unitCell["spaceGroup"]);
          if (hallNumber != 0)
            molecule.setHallNumber(hallNumber);
        }
      }
    }
  }

  if (atoms["coords"].contains("3dFractional") ||
      atoms["coords"].contains("3d fractional")) {
    json fractional = atoms["coords"]["3dFractional"];
    if (!fractional.is_array())
      fractional = atoms["coords"]["3d fractional"];
    if (fractional.is_array() && fractional.size() == 3 * atomCount &&
        isNumericArray(fractional) && molecule.unitCell()) {
      Array<Vector3> fcoords;
      fcoords.reserve(atomCount);
      for (Index i = 0; i < atomCount; ++i) {
        fcoords.push_back(Vector3(static_cast<Real>(fractional[i * 3 + 0]),
                                  static_cast<Real>(fractional[i * 3 + 1]),
                                  static_cast<Real>(fractional[i * 3 + 2])));
      }
      CrystalTools::setFractionalCoordinates(molecule, fcoords);
    }
  }

  // Basis set is optional, if present read it in. Validate the whole shell
  // description before constructing anything: an invalid shell used to leak
  // the GaussianSet below (or attach a half-built one), because
  // molecule.setBasisSet() was called unconditionally at the end of this
  // block regardless of what the loop above it had actually managed to do.
  if (jsonRoot.contains("basisSet")) {
    json basisSet = jsonRoot["basisSet"];
    if (basisSet.is_object()) {
      const json& shellTypes = member(basisSet, "shellTypes");
      const json& primitivesPerShell = member(basisSet, "primitivesPerShell");
      const json& shellToAtomMap = member(basisSet, "shellToAtomMap");
      const json& exponents = member(basisSet, "exponents");
      const json& coefficients = member(basisSet, "coefficients");

      // The shell loop below is bounded by shellTypes.size() alone (as the
      // original reader's was), so primitivesPerShell/shellToAtomMap need
      // only be at least that long, not exactly that long -- some real files
      // (e.g. avogadrodata's formaldehyde.cjson) carry a trailing extra
      // element in primitivesPerShell that every reader so far has ignored.
      bool valid = isNumericArray(shellTypes) &&
                   isNumericArray(primitivesPerShell) &&
                   isNumericArray(shellToAtomMap) &&
                   primitivesPerShell.size() >= shellTypes.size() &&
                   shellToAtomMap.size() >= shellTypes.size() &&
                   isNumericArray(exponents) && isNumericArray(coefficients) &&
                   exponents.size() == coefficients.size();

      std::vector<int> shellType;
      std::vector<int> shellAtom;
      std::vector<int> shellPrimitiveCount;
      if (valid) {
        shellType.reserve(shellTypes.size());
        shellAtom.reserve(shellTypes.size());
        shellPrimitiveCount.reserve(shellTypes.size());
        size_t nGTO = 0;
        for (size_t i = 0; valid && i < shellTypes.size(); ++i) {
          auto type = toInteger<int>(shellTypes[i]);
          auto atomIdx = toInteger<int>(shellToAtomMap[i]);
          auto nPrim = toInteger<int>(primitivesPerShell[i]);
          // Each shell's atom must be a real atom and its primitive count
          // must not run the nGTO cursor past the exponents/coefficients
          // arrays it indexes into below.
          if (!type || !atomIdx || !nPrim || *atomIdx < 0 ||
              static_cast<Index>(*atomIdx) >= atomCount || *nPrim < 0 ||
              nGTO + static_cast<size_t>(*nPrim) > exponents.size()) {
            valid = false;
            break;
          }
          shellType.push_back(*type);
          shellAtom.push_back(*atomIdx);
          shellPrimitiveCount.push_back(*nPrim);
          nGTO += static_cast<size_t>(*nPrim);
        }
      }

      if (valid) {
        auto basis = std::make_unique<GaussianSet>();
        basis->setMolecule(&molecule);

        int nGTO = 0;
        for (size_t i = 0; i < shellType.size(); ++i) {
          GaussianSet::orbital type;
          switch (shellType[i]) {
            case 0:
              type = GaussianSet::S;
              break;
            case 1:
              type = GaussianSet::P;
              break;
            case 2:
              type = GaussianSet::D;
              break;
            case -2:
              type = GaussianSet::D5;
              break;
            case 3:
              type = GaussianSet::F;
              break;
            case -3:
              type = GaussianSet::F7;
              break;
            case 4:
              type = GaussianSet::G;
              break;
            case -4:
              type = GaussianSet::G9;
              break;
            default:
              // If we encounter GTOs we do not understand, the basis is
              // likely invalid
              type = GaussianSet::UU;
          }
          if (type != GaussianSet::UU) {
            int b =
              basis->addBasis(static_cast<unsigned int>(shellAtom[i]), type);
            for (int j = 0; j < shellPrimitiveCount[i]; ++j) {
              basis->addGto(b, coefficients[nGTO], exponents[nGTO]);
              ++nGTO;
            }
          }
        }

        const json& orbitals = member(jsonRoot, "orbitals");
        if (orbitals.is_object() && basis->isValid()) {
          // A missing or wrong-typed electronCount used to throw via the
          // implicit conversion below and fail the whole file; now the
          // basis set still loads, just without an electron count.
          if (auto electronCount =
                toInteger<unsigned int>(member(orbitals, "electronCount")))
            basis->setElectronCount(*electronCount);

          if (auto occs =
                toIntegerArray<unsigned char>(member(orbitals, "occupations")))
            basis->setMolecularOrbitalOccupancy(*occs);
          const json& energies = member(orbitals, "energies");
          if (isNumericArray(energies)) {
            std::vector<double> energyArray;
            energyArray.reserve(energies.size());
            for (const auto& energie : energies)
              energyArray.push_back(static_cast<double>(energie));
            basis->setMolecularOrbitalEnergy(energyArray);
          }
          if (auto numArray =
                toIntegerArray<unsigned int>(member(orbitals, "numbers")))
            basis->setMolecularOrbitalNumber(*numArray);
          const json& symmetryLabels = member(orbitals, "symmetries");
          if (symmetryLabels.is_array()) {
            std::vector<std::string> symArray;
            symArray.reserve(symmetryLabels.size());
            bool allStrings = true;
            for (const auto& sym : symmetryLabels) {
              if (!sym.is_string()) {
                allStrings = false;
                break;
              }
              symArray.push_back(sym.get<std::string>());
            }
            if (allStrings)
              basis->setSymmetryLabels(symArray);
          }
          json moCoefficients = member(orbitals, "moCoefficients");
          json moCoefficientsA = member(orbitals, "alphaCoefficients");
          json moCoefficientsB = member(orbitals, "betaCoefficients");
          bool openShell = false;
          if (isNumericArray(moCoefficients)) {
            std::vector<double> coeffs;
            for (auto& moCoefficient : moCoefficients)
              coeffs.push_back(static_cast<double>(moCoefficient));
            basis->setMolecularOrbitals(coeffs);
          } else if (isNumericArray(moCoefficientsA) &&
                     isNumericArray(moCoefficientsB)) {
            std::vector<double> coeffsA;
            for (auto& i : moCoefficientsA)
              coeffsA.push_back(static_cast<double>(i));
            std::vector<double> coeffsB;
            for (auto& i : moCoefficientsB)
              coeffsB.push_back(static_cast<double>(i));
            basis->setMolecularOrbitals(coeffsA, BasisSet::Alpha);
            basis->setMolecularOrbitals(coeffsB, BasisSet::Beta);
            openShell = true;
          } else {
            std::cout << "No orbital cofficients found!" << std::endl;
          }
          // Check for orbital coefficient sets, these are paired with
          // coordinates when they exist, but have constant basis set, atom
          // types, etc.
          const json& orbSets = member(orbitals, "sets");
          if (orbSets.is_array() && orbSets.size()) {
            for (unsigned int idx = 0; idx < orbSets.size(); ++idx) {
              // orbSets[idx] may not itself be an object in a hand-edited
              // file, so look its keys up with member() rather than
              // indexing it directly.
              moCoefficients = member(orbSets[idx], "moCoefficients");
              moCoefficientsA = member(orbSets[idx], "alphaCoefficients");
              moCoefficientsB = member(orbSets[idx], "betaCoefficients");
              if (isNumericArray(moCoefficients)) {
                std::vector<double> coeffs;
                for (auto& moCoefficient : moCoefficients)
                  coeffs.push_back(static_cast<double>(moCoefficient));
                basis->setMolecularOrbitals(coeffs, BasisSet::Paired, idx);
              } else if (isNumericArray(moCoefficientsA) &&
                         isNumericArray(moCoefficientsB)) {
                std::vector<double> coeffsA;
                for (auto& i : moCoefficientsA)
                  coeffsA.push_back(static_cast<double>(i));
                std::vector<double> coeffsB;
                for (auto& i : moCoefficientsB)
                  coeffsB.push_back(static_cast<double>(i));
                basis->setMolecularOrbitals(coeffsA, BasisSet::Alpha, idx);
                basis->setMolecularOrbitals(coeffsB, BasisSet::Beta, idx);
                openShell = true;
              }
            }
            // Set the first step as active.
            basis->setActiveSetStep(0);
          }
          if (openShell) {
            // look for alpha and beta orbital energies
            const json& energiesA = member(orbitals, "alphaEnergies");
            const json& energiesB = member(orbitals, "betaEnergies");
            // check if they are numeric arrays
            if (isNumericArray(energiesA) && isNumericArray(energiesB)) {
              std::vector<double> moEnergiesA;
              for (auto& i : energiesA)
                moEnergiesA.push_back(static_cast<double>(i));
              std::vector<double> moEnergiesB;
              for (auto& i : energiesB)
                moEnergiesB.push_back(static_cast<double>(i));
              basis->setMolecularOrbitalEnergy(moEnergiesA, BasisSet::Alpha);
              basis->setMolecularOrbitalEnergy(moEnergiesB, BasisSet::Beta);

              // look for alpha and beta orbital occupations, all-or-nothing
              // per array
              auto moOccupationsA = toIntegerArray<unsigned char>(
                member(orbitals, "alphaOccupations"));
              auto moOccupationsB = toIntegerArray<unsigned char>(
                member(orbitals, "betaOccupations"));
              if (moOccupationsA && moOccupationsB) {
                basis->setMolecularOrbitalOccupancy(*moOccupationsA,
                                                    BasisSet::Alpha);
                basis->setMolecularOrbitalOccupancy(*moOccupationsB,
                                                    BasisSet::Beta);
              }
            }
          }
        }
        molecule.setBasisSet(basis.release());
      }
    }
  }

  // See if there is any vibration data, load it if so.
  // By reference: copying would duplicate every conformer's eigenvectors out
  // of the document just to read each one once.
  json& vibrations = jsonRoot["vibrations"];
  if (vibrations.is_object()) {
    // A sparse map of conformer index to that conformer's modes, written when
    // a file carries a Hessian at more than one geometry. When it is present
    // it is authoritative: it also contains the active conformer's set, which
    // the flat keys duplicate for older readers.
    const json& perConformer = vibrations["conformers"];
    if (perConformer.is_object()) {
      for (const auto& entry : perConformer.items()) {
        size_t conformerIndex = 0;
        if (parseIndexKey(entry.key(), conformerIndex))
          deserializeVibrations(entry.value(), molecule, conformerIndex);
      }
    } else {
      deserializeVibrations(vibrations, molecule,
                            static_cast<size_t>(molecule.coordinate3d()));
    }
  }

  // check for spectra data
  json spectra = jsonRoot["spectra"];
  if (spectra.is_object()) {
    // electronic
    json electronic = spectra["electronic"];
    if (electronic.is_object()) {
      // check to see "energies" and "intensities"
      json energies = electronic["energies"];
      json intensities = electronic["intensities"];
      // make sure they are both numeric arrays
      if (isNumericArray(energies) && isNumericArray(intensities)) {
        // make sure they are the same size
        if (energies.size() == intensities.size()) {
          // create the matrix
          MatrixX electronicData(energies.size(), 2);
          // copy the data
          for (std::size_t i = 0; i < energies.size(); ++i) {
            electronicData(i, 0) = energies[i];
            electronicData(i, 1) = intensities[i];
          }
          // set the data
          molecule.setSpectra("Electronic", electronicData);
        }
      }
      // check if there's CD data for "rotation"
      json rotation = electronic["rotation"];
      // energies is also indexed below, so it must be checked here too --
      // otherwise a rotation array present without a valid energies array
      // would index into whatever energies happens to be.
      if (isNumericArray(rotation) && isNumericArray(energies) &&
          rotation.size() == energies.size()) {
        MatrixX rotationData(rotation.size(), 2);
        for (std::size_t i = 0; i < rotation.size(); ++i) {
          rotationData(i, 0) = energies[i];
          rotationData(i, 1) = rotation[i];
        }
        molecule.setSpectra("CircularDichroism", rotationData);
      }
    }

    // nmr
    json nmr = spectra["nmr"];
    if (nmr.is_object()) {
      // chemical shifts
      json chemicalShifts = nmr["shifts"];
      if (isNumericArray(chemicalShifts)) {
        MatrixX chemicalShiftData(chemicalShifts.size(), 2);
        for (std::size_t i = 0; i < chemicalShifts.size(); ++i) {
          chemicalShiftData(i, 0) = static_cast<double>(chemicalShifts[i]);
          chemicalShiftData(i, 1) = 1.0;
        }
        molecule.setSpectra("NMR", chemicalShiftData);
      }
    }
  }

  // constraints
  if (jsonRoot.find("constraints") != jsonRoot.end()) {
    json constraints = jsonRoot["constraints"];
    if (constraints.is_array()) {
      for (auto& constraint : constraints) {
        if (!isNumericArray(constraint))
          continue;
        // value, atom1, atom2, atom3, atom4 -- element 0 is the constrained
        // value (a Real) and needs no range check; the rest are atom indices
        // that must fit the molecule.
        std::vector<Index> idx;
        bool indicesOk = true;
        for (size_t i = 1; i < constraint.size(); ++i) {
          auto id = toInteger<Index>(constraint[i]);
          if (!id || *id >= atomCount) {
            indicesOk = false;
            break;
          }
          idx.push_back(*id);
        }
        if (!indicesOk)
          continue;
        Real value = static_cast<Real>(constraint[0]);
        if (constraint.size() == 3) { // bond
          molecule.addConstraint(value, idx[0], idx[1]);
        } else if (constraint.size() == 4) { // angle
          molecule.addConstraint(value, idx[0], idx[1], idx[2]);
        } else if (constraint.size() == 5) { // torsion
          molecule.addConstraint(value, idx[0], idx[1], idx[2], idx[3]);
        }
      }
    }
  }

  // properties
  if (jsonRoot.find("properties") != jsonRoot.end()) {
    json properties = jsonRoot["properties"];
    if (properties.is_object()) {
      if (auto totalCharge = toInteger<int>(member(properties, "totalCharge")))
        molecule.setData("totalCharge", *totalCharge);
      if (auto totalSpin =
            toInteger<int>(member(properties, "totalSpinMultiplicity")))
        molecule.setData("totalSpinMultiplicity", *totalSpin);
      if (properties.find("dipoleMoment") != properties.end()) {
        // read the numeric array
        json dipole = properties["dipoleMoment"];
        if (isNumericArray(dipole) && dipole.size() == 3) {
          Core::Variant dipoleMoment(dipole[0], dipole[1], dipole[2]);
          molecule.setData("dipoleMoment", dipoleMoment);
        }
      }
      // iterate through everything else
      for (auto& element : properties.items()) {
        if (element.key() == "totalCharge" ||
            element.key() == "totalSpinMultiplicity" ||
            element.key() == "dipoleMoment") {
          continue;
        }
        if (element.value().type() == json::value_t::array) {
          // check if it is a numeric array to go into Eigen::MatrixXd
          json j = element.value(); // convenience
          std::size_t rows = j.size();
          // Rows are not required to be the same length, so size the matrix to
          // the longest of them up front. Growing it row by row instead would
          // leave the columns added later uninitialized in every earlier row.
          std::size_t cols = 1;
          for (const auto& jrow : j) {
            if (jrow.type() == json::value_t::array)
              cols = std::max(cols, jrow.size());
          }
          MatrixX matrix = MatrixX::Zero(rows, cols);
          bool isNumeric = true;

          for (std::size_t row = 0; row < j.size(); ++row) {
            const auto& jrow = j.at(row);
            // check to see if we have a simple vector or a matrix
            if (jrow.type() == json::value_t::array) {
              for (std::size_t col = 0; col < jrow.size(); ++col) {
                const auto& value = jrow.at(col);
                if (value.type() == json::value_t::number_float ||
                    value.type() == json::value_t::number_integer ||
                    value.type() == json::value_t::number_unsigned)
                  matrix(row, col) = value.get<double>();
                else {
                  isNumeric = false;
                  break;
                }
              }
            } else if (jrow.type() == json::value_t::number_float ||
                       jrow.type() == json::value_t::number_integer ||
                       jrow.type() == json::value_t::number_unsigned) {
              // just a row vector
              matrix(row, 0) = jrow.get<double>();
            } else {
              isNumeric = false;
              break;
            }
          }
          if (isNumeric)
            molecule.setData(element.key(), matrix);
          // TODO: add support for non-numeric arrays
          // std::cout << " property: " << element.key() << " = " << matrix
          //           << " size " << matrix.rows() << 'x' << matrix.cols()
          //          << std::endl;
        } else if (element.value().type() == json::value_t::number_float) {
          molecule.setData(element.key(), element.value().get<double>());
        } else if (element.value().type() == json::value_t::number_integer) {
          molecule.setData(element.key(), element.value().get<int>());
        } else if (element.value().type() == json::value_t::boolean) {
          molecule.setData(element.key(), element.value().get<bool>());
        } else if (element.value().type() == json::value_t::string) {
          molecule.setData(element.key(), element.value().get<std::string>());
        } else {
          std::cout << " cannot store property: " << element.key() << " = "
                    << element.value() << " type "
                    << element.value().type_name() << std::endl;
        }
      }
    }
  }

  // inputParameters are calculation metadata
  if (jsonRoot.find("inputParameters") != jsonRoot.end()) {
    json inputParameters = jsonRoot["inputParameters"];
    // add this as a string to the molecule data
    molecule.setData("inputParameters", inputParameters.dump());
  }

  // Partial charges are optional, but if present should be loaded.
  json partialCharges;
  if (atoms.contains("partialCharges")) {
    partialCharges = atoms["partialCharges"];
  }
  // some inconsistent files have it as part of the root
  if (jsonRoot.contains("partialCharges")) {
    partialCharges = jsonRoot["partialCharges"];
  }
  if (partialCharges.is_object()) {
    // keys are types, values are arrays of charges
    for (auto& kv : partialCharges.items()) {
      MatrixX charges(atomCount, 1);
      if (isNumericArray(kv.value()) && kv.value().size() == atomCount) {
        for (size_t i = 0; i < kv.value().size(); ++i) {
          charges(i, 0) = kv.value()[i];
        }
        molecule.setPartialCharges(kv.key(), charges);
      }
    }
  }

  // look for possible cube data
  if (jsonRoot.find("cube") != jsonRoot.end()) {
    // "cube" itself may be anything in a hand-edited file (a fuzzer found
    // "cube": "caffeine"), so every lookup below goes through member()
    // rather than operator[], which throws once the parent turns out not to
    // be an object.
    const json& cubeObj = jsonRoot["cube"];
    const json& origin = member(cubeObj, "origin");
    const json& spacing = member(cubeObj, "spacing");
    const json& dimensions = member(cubeObj, "dimensions");
    const json& type = member(cubeObj, "type");
    const json& scalars = member(cubeObj, "scalars");

    Vector3i points;
    bool dimsOk = dimensions.is_array() && dimensions.size() == 3;
    for (int k = 0; dimsOk && k < 3; ++k) {
      auto d = toInteger<int>(dimensions[k]);
      if (!d || *d < 1)
        dimsOk = false;
      else
        points[k] = *d;
    }

    // The allocation cube->setLimits() performs below is sized from these
    // dimensions, so it must be tied to the scalar data actually present
    // before it runs -- the same lesson as the Gaussian fchk density-matrix
    // OOM fixed in commit 41345ac1d. Otherwise a 158-byte file that claims
    // "dimensions":[800,800,800] allocates ~2 GB before ever checking
    // whether "scalars" agrees, or even exists.
    //
    // The point count has to stay within int: Cube computes x * y * z as an
    // int itself, in setLimits() and setData(). Testing x * y against
    // maxPoints / z before multiplying also keeps the product from wrapping
    // (x * y alone cannot, each factor being below 2^31): three dimensions of
    // up to INT_MAX multiply to ~2^93, and a product taken modulo 2^64 could
    // land on a small number that a short scalars array happens to match.
    constexpr std::uint64_t maxPoints =
      static_cast<std::uint64_t>(std::numeric_limits<int>::max());
    bool scalarsOk = dimsOk;
    if (dimsOk) {
      const std::uint64_t xy = static_cast<std::uint64_t>(points[0]) *
                               static_cast<std::uint64_t>(points[1]);
      const auto z = static_cast<std::uint64_t>(points[2]);
      scalarsOk = xy <= maxPoints / z && isNumericArray(scalars) &&
                  scalars.size() == xy * z;
    }

    if (isNumericArray(origin) && origin.size() == 3 &&
        isNumericArray(spacing) && spacing.size() == 3 && scalarsOk) {
      Cube* cube = molecule.addCube();

      // types
      if (type == "vdw")
        cube->setCubeType(Cube::VdW);
      else if (type == "solventAccessible")
        cube->setCubeType(Cube::SolventAccessible);
      else if (type == "solventExcluded")
        cube->setCubeType(Cube::SolventExcluded);
      else if (type == "esp")
        cube->setCubeType(Cube::ESP);
      else if (type == "electronDensity")
        cube->setCubeType(Cube::ElectronDensity);
      else if (type == "spinDensity")
        cube->setCubeType(Cube::SpinDensity);
      else if (type == "mo")
        cube->setCubeType(Cube::MO);
      else
        cube->setCubeType(Cube::FromFile);

      const json& name = member(cubeObj, "name");
      if (name.is_string())
        cube->setName(name.get<std::string>());

      Vector3 min(origin[0], origin[1], origin[2]);
      Vector3 delta(spacing[0], spacing[1], spacing[2]);
      Vector3 max(min[0] + (points[0] - 1) * delta[0],
                  min[1] + (points[1] - 1) * delta[1],
                  min[2] + (points[2] - 1) * delta[2]);

      cube->setLimits(min, max, points);
      // The scalars are converted explicitly rather than handed to
      // Cube::setData() as json, clamping the way lexicalCast<float> does:
      // scalarsOk above only proved these are numeric, not that they fit in
      // a float, and nlohmann's implicit double-to-float narrowing is
      // undefined behaviour once a value's magnitude does not.
      std::vector<float> data;
      data.reserve(scalars.size());
      for (const auto& v : scalars)
        data.push_back(toClampedFloat(v));
      cube->setData(data);
    }
  }

  if (jsonRoot.find("layer") != jsonRoot.end()) {
    auto names = LayerManager::getMoleculeInfo(&molecule);
    // "layer" itself may not be an object at all (e.g. "layer": 5), so look
    // its children up with member() rather than jsonRoot["layer"]["visible"],
    // which throws in that case.
    const json& layerRoot = member(jsonRoot, "layer");
    // MoleculeInfo starts with one default entry in each of these, so drop it
    // before appending the file's -- otherwise every layer's flags come back
    // shifted by one, with a spurious extra entry on the end.
    const json& visible = member(layerRoot, "visible");
    if (isBooleanArray(visible)) {
      names->visible.clear();
      for (const auto& v : visible) {
        names->visible.push_back(v);
      }
    }
    const json& locked = member(layerRoot, "locked");
    if (isBooleanArray(locked)) {
      names->locked.clear();
      for (const auto& l : locked) {
        names->locked.push_back(l);
      }
    }

    const json& enables = member(layerRoot, "enable");
    if (enables.is_object()) {
      for (const auto& enable : enables.items()) {
        if (isBooleanArray(enable.value())) {
          names->enable[enable.key()] = std::vector<bool>();
          for (const auto& e : enable.value()) {
            names->enable[enable.key()].push_back(e);
          }
        }
      }
    }

    const json& settings = member(layerRoot, "settings");
    if (settings.is_object()) {
      for (const auto& setting : settings.items()) {
        // The writer emits one LayerData::serialize() string per layer. This
        // used to test isBooleanArray, copied from the enable block above, so
        // per-plugin layer settings were written out and then silently dropped
        // on every read.
        if (!setting.value().is_array())
          continue;
        names->settings[setting.key()] = Core::Array<Core::LayerDataPtr>();
        for (const auto& s : setting.value()) {
          // null means this layer has no settings for that plugin, which is
          // not the same as settings that serialize to an empty string.
          if (s.is_null()) {
            names->settings[setting.key()].push_back(nullptr);
            continue;
          }
          names->settings[setting.key()].push_back(std::make_shared<LayerData>(
            s.is_string() ? s.get<std::string>() : std::string()));
        }
      }
    }
  }

  return true;
}

bool CjsonFormat::write(std::ostream& file, const Molecule& molecule)
{
  return serialize(file, molecule);
}

bool CjsonFormat::serialize(std::ostream& file, const Molecule& molecule)
{
  bool writeProperties = true;
  boolOption("properties", writeProperties);

  ordered_json root;

  root["chemicalJson"] = 1;

  if (writeProperties) {
    if (molecule.data("name").type() == Variant::String)
      root["name"] = molecule.data("name").toString().c_str();
    if (molecule.data("inchi").type() == Variant::String)
      root["inchi"] = molecule.data("inchi").toString().c_str();
  }

  json properties;
  // these methods assume neutral singlet if not set
  // or approximate from formal charges and # of electrons
  properties["totalCharge"] = molecule.totalCharge();
  properties["totalSpinMultiplicity"] = molecule.totalSpinMultiplicity();
  // loop through all other properties
  const auto map = molecule.dataMap();
  for (const auto& element : map) {
    if (element.first == "name" || element.first == "inchi")
      continue;

    // check for "inputParameters" and handle it separately
    if (element.first == "inputParameters") {
      // Non-throwing overload: this value came from somewhere else and is not
      // guaranteed to be JSON, and writing a molecule must not terminate.
      json inputParameters =
        json::parse(element.second.toString(), nullptr, false);
      if (!inputParameters.is_discarded())
        root["inputParameters"] = inputParameters;
      continue;
    }

    // check if the key is atom.* or bond.* and handle it separately
    if (element.first.find("atom.") == 0 || element.first.find("bond.") == 0 ||
        element.first.find("residue.") == 0) {
      continue;
    }

    if (element.second.type() == Variant::String)
      properties[element.first] = element.second.toString().c_str();
    else if (element.second.type() == Variant::Double)
      properties[element.first] = element.second.toDouble();
    else if (element.second.type() == Variant::Float)
      properties[element.first] = element.second.toFloat();
    else if (element.second.type() == Variant::Int)
      properties[element.first] = element.second.toInt();
    else if (element.second.type() == Variant::Bool)
      properties[element.first] = element.second.toBool();
    else if (element.second.type() == Variant::Vector) {
      // e.g. dipole moment
      Vector3 v = element.second.toVector3();
      json vector;
      vector.push_back(v.x());
      vector.push_back(v.y());
      vector.push_back(v.z());
      properties[element.first] = vector;
    } else if (element.second.type() == Variant::Matrix) {
      MatrixX m = element.second.toMatrix();
      json matrix;
      for (int i = 0; i < m.rows(); ++i) {
        json row;
        for (int j = 0; j < m.cols(); ++j) {
          row.push_back(m(i, j));
        }
        matrix.push_back(row);
      }
      properties[element.first] = matrix;
    }
  }
  root["properties"] = properties;

  if (molecule.unitCell()) {
    json unitCell;
    unitCell["a"] = molecule.unitCell()->a();
    unitCell["b"] = molecule.unitCell()->b();
    unitCell["c"] = molecule.unitCell()->c();
    unitCell["alpha"] = molecule.unitCell()->alpha() * RAD_TO_DEG;
    unitCell["beta"] = molecule.unitCell()->beta() * RAD_TO_DEG;
    unitCell["gamma"] = molecule.unitCell()->gamma() * RAD_TO_DEG;

    json vectors;
    vectors.push_back(molecule.unitCell()->aVector().x());
    vectors.push_back(molecule.unitCell()->aVector().y());
    vectors.push_back(molecule.unitCell()->aVector().z());

    vectors.push_back(molecule.unitCell()->bVector().x());
    vectors.push_back(molecule.unitCell()->bVector().y());
    vectors.push_back(molecule.unitCell()->bVector().z());

    vectors.push_back(molecule.unitCell()->cVector().x());
    vectors.push_back(molecule.unitCell()->cVector().y());
    vectors.push_back(molecule.unitCell()->cVector().z());
    unitCell["cellVectors"] = vectors;

    // write the Hall number and space group
    unitCell["hallNumber"] = molecule.hallNumber();
    unitCell["spaceGroup"] =
      Core::SpaceGroups::international(molecule.hallNumber());

    root["unitCell"] = unitCell;
  }

  // check for spectra data
  // vibrations are separate
  if (molecule.spectraTypes().size() != 0) {
    json spectra, electronic, nmr;
    bool hasElectronic = false;
    for (const auto& type : molecule.spectraTypes()) {
      if (type == "Electronic") {
        hasElectronic = true;
        electronic["energies"] = eigenColToJson(molecule.spectra(type), 0);
        electronic["intensities"] = eigenColToJson(molecule.spectra(type), 1);
      } else if (type == "CircularDichroism") {
        electronic["rotation"] = eigenColToJson(molecule.spectra(type), 1);
      } else if (type == "NMR") {
        json data;
        data["shifts"] = eigenColToJson(molecule.spectra(type), 0);
        spectra["nmr"] = data;
      }
    }
    if (hasElectronic) {
      spectra["electronic"] = electronic;
    }
    root["spectra"] = spectra;
  }

  // Create a basis set/MO matrix we can round trip.
  if (molecule.basisSet() &&
      dynamic_cast<const GaussianSet*>(molecule.basisSet())) {
    json basis;
    auto gaussian = dynamic_cast<const GaussianSet*>(molecule.basisSet());

    // Map the shell types from enumeration to integer values.
    auto symmetry = gaussian->symmetry();
    json shellTypes;
    for (int i : symmetry) {
      switch (i) {
        case GaussianSet::S:
          shellTypes.push_back(0);
          break;
        case GaussianSet::P:
          shellTypes.push_back(1);
          break;
        case GaussianSet::D:
          shellTypes.push_back(2);
          break;
        case GaussianSet::D5:
          shellTypes.push_back(-2);
          break;
        case GaussianSet::F:
          shellTypes.push_back(3);
          break;
        case GaussianSet::F7:
          shellTypes.push_back(-3);
          break;
        case GaussianSet::G:
          shellTypes.push_back(4);
          break;
        case GaussianSet::G9:
          shellTypes.push_back(-4);
          break;
        default:
          // Something bad, put in a silly number...
          shellTypes.push_back(426942);
      }
    }
    basis["shellTypes"] = shellTypes;

    // This bit is slightly tricky, map from our index to primitives per
    // shell.
    if (gaussian->gtoIndices().size() && gaussian->atomIndices().size()) {
      auto gtoIndices = gaussian->gtoIndices();
      auto gtoA = gaussian->gtoA();
      json primitivesPerShell;
      for (size_t i = 0; i < gtoIndices.size() - 1; ++i)
        primitivesPerShell.push_back(gtoIndices[i + 1] - gtoIndices[i]);
      primitivesPerShell.push_back(gtoA.size() - gtoIndices.back());
      basis["primitivesPerShell"] = primitivesPerShell;

      auto atomIndices = gaussian->atomIndices();
      json shellToAtomMap;
      for (unsigned int& atomIndice : atomIndices)
        shellToAtomMap.push_back(atomIndice);
      basis["shellToAtomMap"] = shellToAtomMap;

      auto gtoC = gaussian->gtoC();
      json exponents;
      json coefficients;
      for (size_t i = 0; i < gtoA.size(); ++i) {
        exponents.push_back(gtoA[i]);
        coefficients.push_back(gtoC[i]);
      }
      basis["exponents"] = exponents;
      basis["coefficients"] = coefficients;

      // Write out the basis set if a valid one exists.
      root["basisSet"] = basis;
    }

    // Now get the MO matrix, potentially other things. Need to get a handle
    // on when we have just one (paired), or two (alpha and beta) to write.
    auto moMatrix = gaussian->moMatrix();
    auto betaMatrix = gaussian->moMatrix(BasisSet::Beta);
    json moCoefficients;
    for (int j = 0; j < moMatrix.cols(); ++j)
      for (int i = 0; i < moMatrix.rows(); ++i)
        moCoefficients.push_back(moMatrix(i, j));

    if (betaMatrix.cols() > 0 && betaMatrix.rows() > 0) {
      json moBeta;
      for (int j = 0; j < moMatrix.cols(); ++j)
        for (int i = 0; i < moMatrix.rows(); ++i)
          moBeta.push_back(moMatrix(i, j));

      root["orbitals"]["alphaCoefficients"] = moCoefficients;
      root["orbitals"]["betaCoefficients"] = moBeta;
    } else {
      root["orbitals"]["moCoefficients"] = moCoefficients;
    }

    // Some energy, occupation, and number data potentially.
    auto energies = gaussian->moEnergy();
    if (energies.size() > 0) {
      json energyData;
      for (double& energie : energies) {
        energyData.push_back(energie);
      }

      auto betaEnergies = gaussian->moEnergy(BasisSet::Beta);
      if (betaEnergies.size() > 0) {
        json betaEnergyData;
        for (double& energie : betaEnergies) {
          betaEnergyData.push_back(energie);
        }
        root["orbitals"]["alphaEnergies"] = energyData;
        root["orbitals"]["betaEnergies"] = betaEnergyData;
      } else
        root["orbitals"]["energies"] = energyData;
    }
    auto occ = gaussian->moOccupancy();
    if (occ.size() > 0) {
      json occData;
      for (unsigned char& it : occ)
        occData.push_back(static_cast<int>(it));

      auto betaOcc = gaussian->moOccupancy(BasisSet::Beta);
      if (betaOcc.size() > 0) {
        json betaOccData;
        for (unsigned char& it : betaOcc)
          betaOccData.push_back(static_cast<int>(it));
        root["orbitals"]["alphaOccupations"] = occData;
        root["orbitals"]["betaOccupations"] = betaOccData;
      } else
        root["orbitals"]["occupations"] = occData;
    }
    auto num = gaussian->moNumber();
    if (num.size() > 0) {
      json numData;
      for (unsigned int& it : num)
        numData.push_back(it);
      root["orbitals"]["numbers"] = numData;
    }

    root["orbitals"]["electronCount"] = gaussian->electronCount();
  }

  // Write out any cubes that are present in the molecule.
  if (molecule.cubeCount() > 0) {
    json cubeObj;
    const Cube* cube = molecule.cube(0);
    // Get the origin, max, spacing, and dimensions to place in the object.
    json cubeMin;
    cubeMin.push_back(cube->min().x());
    cubeMin.push_back(cube->min().y());
    cubeMin.push_back(cube->min().z());
    cubeObj["origin"] = cubeMin;
    json cubeSpacing;
    cubeSpacing.push_back(cube->spacing().x());
    cubeSpacing.push_back(cube->spacing().y());
    cubeSpacing.push_back(cube->spacing().z());
    cubeObj["spacing"] = cubeSpacing;
    json cubeDims;
    cubeDims.push_back(cube->dimensions().x());
    cubeDims.push_back(cube->dimensions().y());
    cubeDims.push_back(cube->dimensions().z());
    cubeObj["dimensions"] = cubeDims;

    // type
    switch (cube->cubeType()) {
      case Cube::VdW:
        cubeObj["type"] = "vdw";
        break;
      case Cube::SolventAccessible:
        cubeObj["type"] = "solventAccessible";
        break;
      case Cube::SolventExcluded:
        cubeObj["type"] = "solventExcluded";
        break;
      case Cube::ESP:
        cubeObj["type"] = "esp";
        break;
      case Cube::ElectronDensity:
        cubeObj["type"] = "electronDensity";
        break;
      case Cube::SpinDensity:
        cubeObj["type"] = "spinDensity";
        break;
      case Cube::MO:
        cubeObj["type"] = "mo";
        break;
      case Cube::FromFile:
      default:
        cubeObj["type"] = "fromFile";
        break;
    }

    // name
    cubeObj["name"] = cube->name();

    json cubeData;
    for (float it : *cube->data()) {
      cubeData.push_back(it);
    }
    cubeObj["scalars"] = cubeData;
    root["cube"] = cubeObj;
  }

  // Create and populate the atom arrays.
  if (molecule.atomCount()) {
    json atoms;
    json elements;
    json selected;
    json colors;

    Vector3ub color;
    bool hasCustomColors = molecule.colors().size() == molecule.atomCount();
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      elements.push_back(molecule.atom(i).atomicNumber());
      selected.push_back(molecule.atomSelected(i));

      color = molecule.color(i);
      colors.push_back(color.x());
      colors.push_back(color.y());
      colors.push_back(color.z());
    }
    atoms["elements"]["number"] = elements;
    if (!molecule.isSelectionEmpty())
      atoms["selected"] = selected;
    if (hasCustomColors)
      atoms["colors"] = colors;

    // check for frozen atoms
    json frozen;
    // any atoms frozen?
    bool anyFrozen = false;
    // any atoms with custom axis?
    // (i.e., we need to save the matrix)
    bool axisFrozen = false;
    Eigen::VectorXd frozenAtomMask = molecule.frozenAtomMask();
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      if (molecule.frozenAtom(i)) {
        anyFrozen = true;
        frozen.push_back(1);
      } else {
        frozen.push_back(0);
      }

      // check for custom axis
      if (i * 3 + 2 < frozenAtomMask.size()) {
        Real sum = frozenAtomMask[3 * i] + frozenAtomMask[3 * i + 1] +
                   frozenAtomMask[3 * i + 2];
        // check if it's not all frozen or all unfrozen
        if (sum != 3.0 && sum != 0.0) {
          axisFrozen = true;
        }
      }
    }

    if (anyFrozen) {
      atoms["frozen"] = frozen;
    }
    if (axisFrozen) {
      // iterate through the mask as an array
      json frozenAtomMaskArray;
      for (Index i = 0; i < frozenAtomMask.size(); ++i) {
        frozenAtomMaskArray.push_back(frozenAtomMask[i]);
      }
      atoms["frozen"] = frozenAtomMaskArray;
    }

    // check for partial charges
    auto partialCharges = molecule.partialChargeTypes();
    if (!partialCharges.empty()) {
      // add them to the atoms object
      for (const auto& type : partialCharges) {
        MatrixX chargesMatrix = molecule.partialCharges(type);
        json charges;
        for (Index i = 0; i < molecule.atomCount(); ++i) {
          charges.push_back(chargesMatrix(i, 0));
        }
        atoms["partialCharges"][type] = charges;
      }
    }

    json coords;
    // 3d positions:
    if (molecule.atomPositions3d().size() == molecule.atomCount()) {
      // everything gets real-space Cartesians
      json coords3d;
      for (const auto& it : molecule.atomPositions3d()) {
        coords3d.push_back(it.x());
        coords3d.push_back(it.y());
        coords3d.push_back(it.z());
      }
      coords["3d"] = coords3d;

      // if the unit cell exists, also write fractional coords
      if (molecule.unitCell()) {
        json coordsFractional;
        Array<Vector3> fcoords;
        CrystalTools::fractionalCoordinates(
          *molecule.unitCell(), molecule.atomPositions3d(), fcoords);
        for (auto& fcoord : fcoords) {
          coordsFractional.push_back(fcoord.x());
          coordsFractional.push_back(fcoord.y());
          coordsFractional.push_back(fcoord.z());
        }
        coords["3dFractional"] = coordsFractional;
      }

      // if the molecule has multiple coordinate sets, write them out
      if (molecule.coordinate3dCount() > 1) {
        json coords3dSets;
        for (Index i = 0; i < molecule.coordinate3dCount(); ++i) {
          json coordsSet;
          const auto& positions = molecule.coordinate3d(i);
          for (const auto& it : positions) {
            coordsSet.push_back(it.x());
            coordsSet.push_back(it.y());
            coordsSet.push_back(it.z());
          }
          coords3dSets.push_back(coordsSet);
        }
        coords["3dSets"] = coords3dSets;
        // Which set is on screen. Without this a reload silently lands on the
        // first step, which for an optimization is the starting geometry
        // rather than the result, and re-keys the active vibrations with it.
        coords["3dSetsActive"] =
          static_cast<unsigned int>(molecule.coordinate3d());
      }
    }

    // 2d positions:
    if (molecule.atomPositions2d().size() == molecule.atomCount()) {
      json coords2d;
      for (const auto& it : molecule.atomPositions2d()) {
        coords2d.push_back(it.x());
        coords2d.push_back(it.y());
      }
      coords["2d"] = coords2d;
    }
    atoms["coords"] = coords;

    // forces if present
    const auto forceVectors = molecule.forceVectors();
    if (forceVectors.size() == molecule.atomCount()) {
      json forces;
      for (const auto& force : forceVectors) {
        forces.push_back(force.x());
        forces.push_back(force.y());
        forces.push_back(force.z());
      }
      atoms["forces"] = forces;
    }

    // check for atom labels
    Array atomLabels = molecule.atomLabels();
    if (atomLabels.size() == molecule.atomCount()) {
      json labels;
      for (Index i = 0; i < molecule.atomCount(); ++i) {
        labels.push_back(atomLabels[i]);
      }
      atoms["labels"] = labels;
    }

    // formal charges
    json formalCharges;
    bool hasFormalCharges = false;
    for (size_t i = 0; i < molecule.atomCount(); ++i) {
      formalCharges.push_back(molecule.formalCharge(i));
      if (molecule.formalCharge(i) != 0)
        hasFormalCharges = true;
    }
    if (hasFormalCharges)
      atoms["formalCharges"] = formalCharges;

    // isotopes (if present)
    json isotopes;
    const auto isotopeList = molecule.isotopes();
    if (isotopeList.size() == molecule.atomCount()) {
      for (Index i = 0; i < molecule.atomCount(); ++i) {
        isotopes.push_back(isotopeList[i]);
      }
      atoms["isotopes"] = isotopes;
    }

    auto layer = LayerManager::getMoleculeInfo(&molecule)->layer;
    if (layer.atomCount() && molecule.atomCount()) {
      json atomLayer;
      // Use molecule atom count to avoid writing stale layer data
      for (Index i = 0; i < molecule.atomCount(); ++i) {
        atomLayer.push_back(layer.getLayerID(i));
      }
      atoms["layer"] = atomLayer;
    }

    // Write custom atom properties
    if (!molecule.atomProperties().empty()) {
      json atomProps = serializeProperties(molecule.atomProperties());
      if (!atomProps.empty())
        atoms["properties"] = atomProps;
    }
    root["atoms"] = atoms; // end atoms
  }

  // Create and populate the bond arrays.
  if (molecule.bondCount()) {
    json bonds;
    json connections;
    json order;
    for (Index i = 0; i < molecule.bondCount(); ++i) {
      Bond bond = molecule.bond(i);
      connections.push_back(bond.atom1().index());
      connections.push_back(bond.atom2().index());
      order.push_back(bond.order());
    }
    bonds["connections"]["index"] = connections;
    bonds["order"] = order;

    // check if there are bond labels
    Array bondLabels = molecule.bondLabels();
    if (bondLabels.size() == molecule.bondCount()) {
      json labels;
      for (Index i = 0; i < molecule.bondCount(); ++i) {
        labels.push_back(bondLabels[i]);
      }
      bonds["labels"] = labels;
    }

    // Write custom bond properties
    if (!molecule.bondProperties().empty()) {
      json bondProps = serializeProperties(molecule.bondProperties());
      if (!bondProps.empty())
        bonds["properties"] = bondProps;
    }
    root["bonds"] = bonds;
  }

  // Create and populate any residue arrays
  if (molecule.residues().size() > 0) {
    json residues; // array of objects
    Array residueLabels = molecule.residueLabels();
    for (auto residue : molecule.residues()) {
      json entry;
      entry["name"] = residue.residueName();
      entry["id"] = residue.residueId();
      entry["chainId"] = residue.chainId();
      entry["secStruct"] = residue.secondaryStructure();
      if (residue.isHeterogen())
        entry["hetero"] = true;

      json color;
      color.push_back(residue.color()[0]);
      color.push_back(residue.color()[1]);
      color.push_back(residue.color()[2]);
      entry["color"] = color;

      json atoms;
      for (const auto& item : residue.atomNameMap()) {
        // dictionary between names and atom Id
        atoms[item.first] = item.second.index();
      }
      entry["atoms"] = atoms;
      residues.push_back(entry);

      // do we have custom residue labels?
      if (residueLabels.size() > residue.residueId() + 1) {
        entry["label"] = residueLabels[residue.residueId()];
      }
    }
    root["residues"] = residues;

    // Write residue properties as parallel arrays alongside residues
    if (!molecule.residueProperties().empty()) {
      json resProps = serializeProperties(molecule.residueProperties());
      if (!resProps.empty())
        root["residueProperties"] = resProps;
    }
  }

  // Conformer properties (parallel arrays sized to coordinate3dCount())
  if (!molecule.conformerProperties().empty()) {
    json confProps = serializeProperties(molecule.conformerProperties());
    if (!confProps.empty())
      root["conformerProperties"] = confProps;
  }

  // any constraints?
  auto constraintList = molecule.constraints();
  if (!constraintList.empty()) {
    json constraints;
    for (auto& constraint : constraintList) {
      json constraintEntry;
      constraintEntry.push_back(constraint.value());
      constraintEntry.push_back(constraint.aIndex());
      constraintEntry.push_back(constraint.bIndex());
      if (constraint.cIndex() != MaxIndex) {
        constraintEntry.push_back(constraint.cIndex());
      }
      if (constraint.dIndex() != MaxIndex) {
        constraintEntry.push_back(constraint.dIndex());
      }
      constraints.push_back(constraintEntry);
    }
    root["constraints"] = constraints;
  }

  // If there is vibrational data write this out too.
  //
  // A calculation can produce a Hessian at more than one geometry (a
  // transition state search recomputes it every few steps), and those sets
  // belong to different conformers. The set of conformers carrying one is the
  // single source of truth here: gating on the *active* conformer's modes
  // instead would drop every Hessian in the file whenever the user had
  // stepped to a geometry that has none.
  const auto vibrationConformers = molecule.vibrationConformers();
  if (!vibrationConformers.empty()) {
    // The flat keys are the active conformer's data, so a file with one
    // Hessian is written exactly as before and older readers still find it.
    // Fall back to the first set that exists when the conformer on screen has
    // none, so the flat block is never empty while data exists.
    const auto active = static_cast<size_t>(molecule.coordinate3d());
    const bool activeHasModes = molecule.hasVibrations(active);
    const size_t flatConformer =
      activeHasModes ? active : vibrationConformers[0];

    json vibrations = serializeVibrations(molecule, flatConformer);

    // Sparse map keyed by conformer index: most conformers have no Hessian,
    // so a dense array parallel to the coordinate sets would be mostly empty.
    // This matches the sparse form already used for matrix properties. It is
    // only needed when the flat block alone cannot reproduce the molecule.
    if (vibrationConformers.size() > 1 || flatConformer != active) {
      json perConformer = json::object();
      for (size_t i = 0; i < vibrationConformers.size(); ++i) {
        const size_t conformer = vibrationConformers[i];
        // The flat block already holds this one; reuse it rather than
        // rebuilding every eigenvector.
        perConformer[std::to_string(conformer)] =
          conformer == flatConformer ? vibrations
                                     : serializeVibrations(molecule, conformer);
      }
      vibrations["conformers"] = std::move(perConformer);
    }

    root["vibrations"] = std::move(vibrations);
  }

  auto names = LayerManager::getMoleculeInfo(&molecule);
  json layer;
  json visible;
  for (const bool v : names->visible) {
    visible.push_back(v);
  }
  layer["visible"] = visible;
  json locked;
  for (const bool l : names->locked) {
    locked.push_back(l);
  }
  layer["locked"] = locked;
  for (const auto& enables : names->enable) {
    json enable;
    for (const bool e : enables.second) {
      enable.push_back(e);
    }
    layer["enable"][enables.first] = enable;
  }

  for (const auto& settings : names->settings) {
    json setting;
    for (const auto& e : settings.second) {
      if (e)
        setting.push_back(e->serialize());
      else
        setting.push_back(nullptr); // no settings for this layer
    }
    layer["settings"][settings.first] = setting;
  }
  root["layer"] = layer;

#ifndef NDEBUG
  // if debugging, pretty print
  file << std::setw(2) << root;
#else
  file << root;
#endif

  return true;
}

vector<std::string> CjsonFormat::fileExtensions() const
{
  vector<std::string> ext;
  ext.emplace_back("cjson");
  return ext;
}

vector<std::string> CjsonFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.emplace_back("chemical/x-cjson");
  return mime;
}

} // namespace Avogadro::Io
