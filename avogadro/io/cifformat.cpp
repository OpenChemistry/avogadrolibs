/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cifformat.h"

#include "cifsymmetry.h"
#include "fileformatmanager.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <gemmi/cif.hpp>
#include <gemmi/to_cif.hpp>

#include <algorithm>
#include <cmath>
#include <iterator>
#include <locale>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Avogadro::Io {

namespace cif = gemmi::cif;

namespace {

// The tag spellings of CIF 1 (underscores) and of DDLm / CIF 2 (dotted).
const char* const cellTags[6][2] = {
  { "_cell_length_a", "_cell.length_a" },
  { "_cell_length_b", "_cell.length_b" },
  { "_cell_length_c", "_cell.length_c" },
  { "_cell_angle_alpha", "_cell.angle_alpha" },
  { "_cell_angle_beta", "_cell.angle_beta" },
  { "_cell_angle_gamma", "_cell.angle_gamma" }
};
const char* const operationTags[] = { "_space_group_symop_operation_xyz",
                                      "_symmetry_equiv_pos_as_xyz",
                                      "_space_group_symop.operation_xyz" };
const char* const hallTags[] = { "_space_group_name_Hall",
                                 "_symmetry_space_group_name_Hall",
                                 "_space_group.name_Hall" };
const char* const hermannMauguinTags[] = { "_space_group_name_H-M_alt",
                                           "_symmetry_space_group_name_H-M",
                                           "_space_group.name_H-M_alt" };
const char* const tableNumberTags[] = { "_space_group_IT_number",
                                        "_symmetry_Int_Tables_number",
                                        "_space_group.IT_number" };

bool isAsciiAlpha(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool isAsciiLower(char c)
{
  return c >= 'a' && c <= 'z';
}
char asciiUpper(char c)
{
  return isAsciiLower(c) ? static_cast<char>(c - 'a' + 'A') : c;
}

unsigned char elementFromSymbol(const std::string& symbol)
{
  // The spelling of Elements: one uppercase letter, then lowercase ones.
  std::string name = Core::toLower(symbol);
  if (!name.empty())
    name[0] = asciiUpper(name[0]);
  return Core::Elements::atomicNumberFromSymbol(name);
}

bool isValidElement(unsigned char number)
{
  return number != InvalidElement && number > 0;
}

// The first of the tags that the block has, as a plain (unquoted) string.
// Empty if none has a value, or the value is "?" or ".".
template <std::size_t N>
std::string firstValue(const cif::Block& block, const char* const (&tags)[N])
{
  for (const char* tag : tags) {
    if (const std::string* value = block.find_value(tag)) {
      std::string text = Core::trimmed(cif::as_string(*value));
      if (!text.empty())
        return text;
    }
  }
  return std::string();
}

// A CIF number: "4.7855(4)" is 4.7855 with a standard uncertainty. "?" and "."
// mean unknown.
std::optional<double> parseCifNumber(const std::string& raw)
{
  std::string text = Core::trimmed(cif::as_string(raw));
  const std::size_t paren = text.find('(');
  if (paren != std::string::npos)
    text.erase(paren);
  text = Core::trimmed(text);
  if (text.empty())
    return std::nullopt;
  const std::optional<double> value = Core::lexicalCast<double>(text);
  if (!value || !std::isfinite(*value))
    return std::nullopt;
  return value;
}

// The element of a _atom_site_type_symbol: "O2-", "Fe3+" and "Cu1+" are O, Fe
// and Cu. D and T are hydrogen isotopes. Dummy atoms ("Q", "X", "Du") give
// 0, which is neither an element nor InvalidElement.
constexpr unsigned char dummyAtom = 0;

const char* const dummyFlag = "dum"; // codespell:ignore dum

unsigned char elementFromTypeSymbol(const std::string& type,
                                    unsigned short& isotope)
{
  std::string letters;
  for (char c : Core::trimmed(type)) {
    if (!isAsciiAlpha(c))
      break;
    letters += c;
  }
  if (letters.empty())
    return InvalidElement;

  std::string upper;
  for (char c : letters)
    upper += asciiUpper(c);
  if (upper == "Q" || upper == "X" || upper == "DU")
    return dummyAtom;
  if (upper == "D") {
    isotope = 2;
    return 1;
  }
  if (upper == "T") {
    isotope = 3;
    return 1;
  }

  // "Fe", "Cl"; a longer run of letters is read as its first two, then its
  // first letter.
  for (std::size_t length = std::min<std::size_t>(2, letters.size());
       length >= 1; --length) {
    const unsigned char number = elementFromSymbol(letters.substr(0, length));
    if (isValidElement(number))
      return number;
  }
  return InvalidElement;
}

// The element from an atom label ("Cl1", "C12", "O1W"), for a file without
// type symbols. A lower case second letter that makes a two-letter symbol wins
// ("Cl1" is chlorine), then the first letter alone ("C12", "CL1"), then the
// two letters in any case.
unsigned char elementFromLabel(const std::string& rawLabel)
{
  const std::string label = Core::trimmed(rawLabel);
  if (label.empty() || !isAsciiAlpha(label[0]))
    return InvalidElement;

  const bool secondIsLetter = label.size() > 1 && isAsciiAlpha(label[1]);
  if (secondIsLetter && isAsciiLower(label[1])) {
    const unsigned char number = elementFromSymbol(label.substr(0, 2));
    if (isValidElement(number))
      return number;
  }
  const unsigned char one = elementFromSymbol(label.substr(0, 1));
  if (isValidElement(one))
    return one;
  if (secondIsLetter) {
    const unsigned char number = elementFromSymbol(label.substr(0, 2));
    if (isValidElement(number))
      return number;
  }
  return InvalidElement;
}

// A table whose tags share a prefix, spelled with underscores (CIF 1) or with
// a dot (DDLm). Tags that start with '?' are optional.
cif::Table findTable(cif::Block& block, const std::string& category,
                     const std::vector<std::string>& tags)
{
  cif::Table table = block.find("_" + category + "_", tags);
  if (table.ok())
    return table;
  return block.find("_" + category + ".", tags);
}

bool hasFractionalCoordinates(cif::Block& block)
{
  return block.find_values("_atom_site_fract_x").item() != nullptr ||
         block.find_values("_atom_site.fract_x").item() != nullptr;
}

// An atom of the asymmetric unit.
struct Site
{
  std::string label;
  unsigned char atomicNumber = 0;
  unsigned short isotope = 0;
  Vector3 fractional = Vector3::Zero();
  std::string disorderGroup;    // empty if the atom is not disordered
  std::string disorderAssembly; // empty is the one implicit assembly
  double occupancy = 1.0;
};

// Everything a block says that the reader uses.
struct CifData
{
  double cell[6] = { 0, 0, 0, 0, 0, 0 }; // angstrom and degrees
  std::vector<Site> sites;
  std::vector<std::string> operations;
  std::string hallSymbol;
  std::string hermannMauguin;
  std::string tableNumber;
  std::string name;
  std::vector<std::pair<std::string, std::string>> bondedLabels;
};

// The longest operation that is re-joined from unquoted values. A real
// operation is a few dozen characters, so a longer run of values is not one
// (and joining it would cost time and memory for nothing).
constexpr std::size_t maxOperationLength = 256;

// The operations of the file. Unquoted operations written with spaces
// ("x, y, z") are split into several values by the tokenizer, so join values
// until there are three coordinates.
std::vector<std::string> readOperations(cif::Block& block)
{
  std::vector<std::string> operations;
  for (const char* tag : operationTags) {
    cif::Column column = block.find_values(tag);
    if (column.item() == nullptr)
      continue;
    std::string pending;
    int commas = 0; // the commas in pending
    auto flush = [&]() {
      // An incomplete operation is kept on purpose: a malformed entry then
      // matches no table entry, and the reader falls back to the name or the
      // Hall symbol instead of silently matching a smaller group.
      if (!pending.empty())
        operations.push_back(pending);
      pending.clear();
      commas = 0;
    };
    for (const std::string& value : column) {
      const bool quoted =
        !value.empty() &&
        (value[0] == '\'' || value[0] == '"' || value[0] == ';');
      if (quoted) {
        flush();
        operations.push_back(cif::as_string(value));
        continue;
      }
      if (!pending.empty() &&
          pending.size() + value.size() > maxOperationLength)
        flush();
      pending += value;
      commas += static_cast<int>(std::count(value.begin(), value.end(), ','));
      if ((commas >= 2 && pending.back() != ',') ||
          pending.size() > maxOperationLength)
        flush();
    }
    flush();
    if (!operations.empty())
      break;
  }
  return operations;
}

bool readCell(cif::Block& block, CifData& data)
{
  for (int i = 0; i < 3; ++i) {
    const std::optional<double> l =
      parseCifNumber(firstValue(block, cellTags[i]));
    const std::optional<double> a =
      parseCifNumber(firstValue(block, cellTags[3 + i]));
    if (!l || !a || *l <= 0.0 || *a <= 0.0 || *a >= 180.0)
      return false;
    data.cell[i] = *l;
    data.cell[3 + i] = *a;
  }
  return true;
}

void readSites(cif::Block& block, CifData& data)
{
  cif::Table table = findTable(
    block, "atom_site",
    { "label", "fract_x", "fract_y", "fract_z", "?type_symbol", "?calc_flag",
      "?disorder_assembly", "?disorder_group", "?occupancy" });
  if (!table.ok())
    return;

  for (auto row : table) {
    Site site;
    site.label = Core::trimmed(cif::as_string(row[0]));

    // dummy atoms: type symbol Q, X or Du, or the calc_flag for dummy atoms
    if (row.has(5) && Core::caseInsensitiveEquals(
                        Core::trimmed(cif::as_string(row[5])), dummyFlag))
      continue;

    unsigned char number = InvalidElement;
    if (row.has(4)) {
      number = elementFromTypeSymbol(cif::as_string(row[4]), site.isotope);
      if (number == dummyAtom)
        continue;
    }
    if (!isValidElement(number)) {
      site.isotope = 0;
      number = elementFromLabel(site.label);
    }
    if (!isValidElement(number))
      continue;
    site.atomicNumber = number;

    // atoms without coordinates cannot be placed
    bool placed = true;
    for (int i = 0; i < 3; ++i) {
      const std::optional<double> value = parseCifNumber(row[1 + i]);
      if (!value) {
        placed = false;
        break;
      }
      site.fractional[i] = *value;
    }
    if (!placed)
      continue;

    // "0", ".", "?" and an absent column all mean not disordered
    if (row.has(7)) {
      const std::string group = Core::trimmed(cif::as_string(row[7]));
      if (group != "0")
        site.disorderGroup = group;
    }
    if (row.has(6))
      site.disorderAssembly = Core::trimmed(cif::as_string(row[6]));

    // a missing or unreadable occupancy counts as a full one
    if (row.has(8)) {
      const std::optional<double> occupancy = parseCifNumber(row[8]);
      if (occupancy && std::isfinite(*occupancy) && *occupancy >= 0.0)
        site.occupancy = *occupancy;
    }

    data.sites.push_back(site);
  }
}

// The bonds of the file between atoms of the asymmetric unit: those without a
// symmetry code, or with the identity.
void readBonds(cif::Block& block, CifData& data)
{
  cif::Table table = findTable(block, "geom_bond",
                               { "atom_site_label_1", "atom_site_label_2",
                                 "?site_symmetry_1", "?site_symmetry_2" });
  if (!table.ok())
    return;

  auto isIdentity = [](const std::string& code) {
    const std::string text = Core::trimmed(cif::as_string(code));
    return text.empty() || text == "." || text == "?" || text == "1_555" ||
           text == "1";
  };
  for (auto row : table) {
    if ((row.has(2) && !isIdentity(row[2])) ||
        (row.has(3) && !isIdentity(row[3])))
      continue;
    data.bondedLabels.emplace_back(Core::trimmed(cif::as_string(row[0])),
                                   Core::trimmed(cif::as_string(row[1])));
  }
}

bool readBlock(cif::Block& block, CifData& data)
{
  if (!readCell(block, data))
    return false;
  readSites(block, data);
  if (data.sites.empty())
    return false;

  data.operations = readOperations(block);
  data.hallSymbol = firstValue(block, hallTags);
  data.hermannMauguin = firstValue(block, hermannMauguinTags);
  data.tableNumber = firstValue(block, tableNumberTags);

  const char* const commonName[] = { "_chemical_name_common" };
  const char* const systematicName[] = { "_chemical_name_systematic" };
  data.name = firstValue(block, commonName);
  if (data.name.empty())
    data.name = firstValue(block, systematicName);
  if (data.name.empty())
    data.name = block.name;

  readBonds(block, data);
  return true;
}

// Which sites to keep when only the major configuration of each disorder
// assembly is read. Keeping every group would put all the alternatives on the
// same atoms (six Cl on one carbon for a CHCl3 split over two groups), which
// is rarely wanted for a model, so the default is one configuration (the
// atoms keep their labels either way). Within an assembly the group with the
// highest mean occupancy is kept, the first one in the file on a tie. The only
// group of an assembly is kept only at a mean occupancy of 0.5 or more,
// otherwise it is the minor part of a disorder whose other part is labeled
// elsewhere or not at all. Negative groups (SHELX disorder across a symmetry
// element) and sites without a group are always kept.
std::vector<bool> majorDisorderMask(const std::vector<Site>& sites)
{
  struct Group
  {
    std::string label;
    double sum = 0.0;
    std::size_t count = 0;
    double mean() const { return count > 0 ? sum / double(count) : 0.0; }
  };
  std::map<std::string, std::vector<Group>> assemblies;
  for (const Site& site : sites) {
    if (site.disorderGroup.empty() || site.disorderGroup[0] == '-')
      continue;
    std::vector<Group>& groups = assemblies[site.disorderAssembly];
    auto it = std::find_if(groups.begin(), groups.end(), [&](const Group& g) {
      return g.label == site.disorderGroup;
    });
    if (it == groups.end()) {
      groups.emplace_back();
      it = groups.end() - 1;
      it->label = site.disorderGroup;
    }
    it->sum += site.occupancy;
    ++it->count;
  }

  std::map<std::string, std::string> major;
  for (const auto& assembly : assemblies) {
    const Group* best = nullptr;
    for (const Group& group : assembly.second) {
      if (best == nullptr || group.mean() > best->mean())
        best = &group;
    }
    if (best != nullptr && (assembly.second.size() > 1 || best->mean() >= 0.5))
      major[assembly.first] = best->label;
  }

  std::vector<bool> keep(sites.size(), true);
  for (std::size_t i = 0; i < sites.size(); ++i) {
    const Site& site = sites[i];
    if (site.disorderGroup.empty() || site.disorderGroup[0] == '-')
      continue;
    const auto it = major.find(site.disorderAssembly);
    keep[i] = it != major.end() && it->second == site.disorderGroup;
  }
  return keep;
}

} // namespace

std::vector<std::string> CifFormat::fileExtensions() const
{
  return { "cif" };
}

std::vector<std::string> CifFormat::mimeTypes() const
{
  return { "chemical/x-cif" };
}

bool CifFormat::read(std::istream& inStream, Core::Molecule& molecule)
{
  // An empty stream sets the failbit of the buffer, which is not an error.
  std::ostringstream buffer;
  buffer << inStream.rdbuf();
  std::string text = std::move(buffer).str();

  CifData data;
  std::string reason;
  bool found = false;
  try {
    cif::Document document = cif::read_memory(text.data(), text.size(), "cif");
    for (cif::Block& block : document.blocks) {
      if (!hasFractionalCoordinates(block))
        continue;
      found = readBlock(block, data);
      if (!found)
        reason = "the first data block with fractional coordinates has no "
                 "valid unit cell or no usable atoms";
      break;
    }
    if (!found && reason.empty())
      reason = "no data block has fractional coordinates";
  } catch (const std::exception& e) {
    reason = e.what();
    found = false;
  } catch (...) {
    reason = "unknown error";
    found = false;
  }

  if (!found) {
    // A macromolecular CIF, or a file we cannot make sense of: hand it to
    // whatever else reads CIF (normally Open Babel), which reads mmCIF
    // residues and is more lenient.
    const FileFormat* candidate = nullptr;
    for (const FileFormat* format :
         FileFormatManager::instance().fileFormatsFromFileExtension(
           "cif", FileFormat::Read)) {
      if (Core::startsWith(format->identifier(), "OpenBabel")) {
        candidate = format;
        break;
      }
    }
    if (candidate == nullptr) {
      appendError("This CIF file could not be read (" + reason +
                  "), and no other CIF reader (Open Babel) is available.");
      return false;
    }

    std::unique_ptr<FileFormat> reader(candidate->newInstance());
    reader->setOptions(options());
    bool success = false;
    if (candidate->supportedOperations() & FileFormat::Stream) {
      std::istringstream stream(std::move(text));
      success = reader->read(stream, molecule);
    } else if (!fileName().empty()) {
      success = reader->readFile(fileName(), molecule);
    } else {
      appendError("This CIF file needs another reader (" +
                  candidate->identifier() + ") that can only read files.");
      return false;
    }
    if (!success) {
      appendError("The CIF file was not read natively (" + reason + ") and " +
                  candidate->identifier() + " failed too.");
      const std::string delegateError = reader->error();
      if (!delegateError.empty())
        appendError(delegateError, false);
    }
    return success;
  }

  // Build the unit cell first: its parameters may still be impossible.
  constexpr double degreesToRadians = DEG_TO_RAD_D;
  auto cell = std::make_unique<Core::UnitCell>(
    data.cell[0], data.cell[1], data.cell[2], data.cell[3] * degreesToRadians,
    data.cell[4] * degreesToRadians, data.cell[5] * degreesToRadians);
  if (!cell->isRegular() || !std::isfinite(cell->volume()) ||
      cell->volume() <= 0.0) {
    appendError("The unit cell of this CIF file is not valid.");
    return false;
  }

  std::string disorder = "major";
  stringOption("disorder", disorder);
  std::vector<bool> keepSite(data.sites.size(), true);
  if (!Core::caseInsensitiveEquals(disorder, "all"))
    keepSite = majorDisorderMask(data.sites);

  std::vector<Site> sites;
  std::vector<Vector3> positions;
  for (std::size_t i = 0; i < data.sites.size(); ++i) {
    if (!keepSite[i])
      continue;
    const Site& site = data.sites[i];
    const Vector3 position = cell->toCartesian(site.fractional);
    if (!position.allFinite())
      continue;
    sites.push_back(site);
    positions.push_back(position);
  }
  if (sites.empty()) {
    appendError("This CIF file has no atoms with usable coordinates.");
    return false;
  }

  Core::Molecule& mol = molecule;
  mol.setUnitCell(cell.release());
  std::map<std::string, Index> indexOfLabel;
  // The site occupancy is stored on every atom, but only if some site is not a
  // full one, so an ordinary file does not start to write occupancies.
  Core::Array<double> occupancies;
  bool anyPartialOccupancy = false;
  for (std::size_t i = 0; i < sites.size(); ++i) {
    occupancies.push_back(sites[i].occupancy);
    if (sites[i].occupancy != 1.0)
      anyPartialOccupancy = true;
  }
  for (std::size_t i = 0; i < sites.size(); ++i) {
    Core::Atom atom = mol.addAtom(sites[i].atomicNumber);
    atom.setPosition3d(positions[i]);
    if (sites[i].isotope != 0)
      atom.setIsotope(sites[i].isotope);
    mol.setAtomLabel(atom.index(), sites[i].label);
    indexOfLabel.emplace(sites[i].label, atom.index());
  }
  if (anyPartialOccupancy)
    mol.setOccupancies(occupancies);
  // The disorder labels as the file gives them, if any atom is in a group
  Core::Array<std::string> disorderAssemblies;
  Core::Array<std::string> disorderGroups;
  bool anyDisorder = false;
  for (const Site& site : sites) {
    disorderAssemblies.push_back(site.disorderAssembly);
    disorderGroups.push_back(site.disorderGroup);
    if (!site.disorderGroup.empty())
      anyDisorder = true;
  }
  if (anyDisorder)
    mol.setDisorders(disorderAssemblies, disorderGroups);
  if (!data.name.empty())
    mol.setData("name", data.name);

  // The space group. The name of the group first, so that applyCifSymmetry()
  // can keep it when the file lists only the identity; the operations and the
  // Hall symbol are exact and replace it.
  if (!data.hermannMauguin.empty())
    Core::SpaceGroups::setSpaceGroup(mol, data.hermannMauguin);
  if (mol.hallNumber() == 0 && !data.tableNumber.empty())
    Core::SpaceGroups::setSpaceGroup(mol, data.tableNumber);
  bool perceiveBonds = true;
  boolOption("perceiveBonds", perceiveBonds);

  applyCifSymmetry(
    makeCifSymmetry(data.operations, data.hallSymbol, data.hermannMauguin),
    mol);

  // Atoms of different disorder groups are never bonded (the molecule
  // knows which they are).
  if (perceiveBonds)
    mol.perceiveBondsSimple();

  for (const auto& labels : data.bondedLabels) {
    const auto first = indexOfLabel.find(labels.first);
    const auto second = indexOfLabel.find(labels.second);
    if (first == indexOfLabel.end() || second == indexOfLabel.end() ||
        first->second == second->second)
      continue;
    if (!mol.bond(first->second, second->second).isValid())
      mol.addBond(first->second, second->second, 1);
  }

  if (perceiveBonds)
    mol.perceiveBondOrders();

  return true;
}

namespace {

// A number with a fixed count of decimals, whatever the global locale is.
std::string formatNumber(double value, int decimals)
{
  std::ostringstream stream;
  stream.imbue(std::locale::classic());
  stream.setf(std::ios::fixed, std::ios::floatfield);
  stream.precision(decimals);
  stream << value;
  std::string text = stream.str();
  // "-0.000000" is just zero
  if (text.size() > 1 && text[0] == '-' &&
      text.find_first_not_of("-0.") == std::string::npos)
    text.erase(0, 1);
  return text;
}

// An occupancy with four decimals, but one so small that it would round to
// zero or nearly so keeps four significant digits instead, so that it still
// reads back as a partial site.
std::string formatOccupancy(double value)
{
  if (value == 0.0 || std::abs(value) >= 0.001)
    return formatNumber(value, 4);
  std::ostringstream stream;
  stream.imbue(std::locale::classic());
  stream.setf(std::ios::scientific, std::ios::floatfield);
  stream.precision(4);
  stream << value;
  return stream.str();
}

// A data block name has no white space; keep it readable.
std::string blockName(const std::string& name)
{
  std::string result;
  for (char c : name) {
    const unsigned char u = static_cast<unsigned char>(c);
    result += (u > 32 && u < 127) ? c : '_';
  }
  // trim the underscores that stand for spaces at either end
  const std::size_t first = result.find_first_not_of('_');
  if (first == std::string::npos)
    return "avogadro";
  const std::size_t last = result.find_last_not_of('_');
  return result.substr(first, last - first + 1);
}

// Labels must be unique and have no white space. Keep the label of an atom
// if it has one that is not used yet, else make "<Symbol><n>" with the next
// number that is free for that element.
std::vector<std::string> uniqueLabels(const Core::Molecule& molecule)
{
  const std::size_t count = molecule.atomCount();
  std::vector<std::string> labels(count);
  std::set<std::string> used;
  std::vector<bool> keep(count, false);

  for (std::size_t i = 0; i < count; ++i) {
    std::string label;
    for (char c : molecule.atomLabel(i)) {
      const unsigned char u = static_cast<unsigned char>(c);
      label += (u > 32 && u < 127) ? c : '_';
    }
    if (label.empty() || !used.insert(Core::toLower(label)).second)
      continue;
    labels[i] = label;
    keep[i] = true;
  }

  std::map<std::string, unsigned int> counters;
  for (std::size_t i = 0; i < count; ++i) {
    if (keep[i])
      continue;
    const std::string symbol = Core::Elements::symbol(molecule.atomicNumber(i));
    unsigned int& counter = counters[symbol];
    std::string label;
    do {
      label = symbol + std::to_string(++counter);
    } while (!used.insert(Core::toLower(label)).second);
    labels[i] = label;
  }
  return labels;
}

} // namespace

bool CifFormat::write(std::ostream& outStream, const Core::Molecule& molecule)
{
  if (molecule.unitCell() == nullptr) {
    appendError("A CIF file needs a unit cell, and this molecule has none.");
    return false;
  }
  if (molecule.atomCount() == 0) {
    appendError("There are no atoms to write.");
    return false;
  }

  try {
    // A space group other than P1 means the molecule holds the asymmetric
    // unit: write every atom of the cell, so the file can say P1.
    const Core::Molecule* source = &molecule;
    std::unique_ptr<Core::Molecule> filled;
    if (molecule.hallNumber() > 1) {
      filled = std::make_unique<Core::Molecule>(molecule);
      Core::SpaceGroups::fillUnitCell(*filled, molecule.hallNumber());
      source = filled.get();
    } else if (molecule.hallNumber() == 0) {
      // A file whose operations are in no table entry: its molecule keeps the
      // operations instead of a Hall number.
      const std::vector<std::string> operations =
        Core::SpaceGroups::storedOperations(molecule);
      if (!operations.empty()) {
        filled = std::make_unique<Core::Molecule>(molecule);
        if (Core::SpaceGroups::fillUnitCellFromOperations(*filled, operations))
          source = filled.get();
      }
    }
    const Core::UnitCell* cell = source->unitCell();
    if (cell == nullptr)
      return false;

    cif::Document document;
    cif::Block& block =
      document.add_new_block(blockName(molecule.data("name").toString()));

    block.set_pair("_audit_creation_method",
                   cif::quote("Generated by Avogadro"));

    const char* const lengthTags[] = { "_cell_length_a", "_cell_length_b",
                                       "_cell_length_c" };
    const double lengths[] = { cell->a(), cell->b(), cell->c() };
    for (int i = 0; i < 3; ++i)
      block.set_pair(lengthTags[i], formatNumber(lengths[i], 6));
    const char* const angleTags[] = { "_cell_angle_alpha", "_cell_angle_beta",
                                      "_cell_angle_gamma" };
    const double angles[] = { cell->alpha(), cell->beta(), cell->gamma() };
    for (int i = 0; i < 3; ++i)
      block.set_pair(angleTags[i], formatNumber(angles[i] * RAD_TO_DEG_D, 5));
    block.set_pair("_cell_volume", formatNumber(cell->volume(), 4));

    block.set_pair("_space_group_name_H-M_alt", cif::quote("P 1"));
    block.set_pair("_space_group_name_Hall", cif::quote("P 1"));
    block.set_pair("_space_group_IT_number", "1");

    cif::Loop& operations =
      block.init_loop("_space_group_symop_", { "id", "operation_xyz" });
    operations.add_row({ "1", "x,y,z" });

    // The occupancy column is only written for a molecule that has them
    const bool writeOccupancy = !source->occupancies().empty();
    std::vector<std::string> siteTags = { "label", "type_symbol", "fract_x",
                                          "fract_y", "fract_z" };
    if (writeOccupancy)
      siteTags.push_back("occupancy");
    // and the disorder columns only for one with disorder groups
    bool writeDisorder = false;
    for (std::size_t i = 0; i < source->atomCount() && !writeDisorder; ++i)
      writeDisorder = !source->disorderGroup(i).empty();
    if (writeDisorder) {
      siteTags.push_back("disorder_assembly");
      siteTags.push_back("disorder_group");
    }
    cif::Loop& sites = block.init_loop("_atom_site_", siteTags);
    const std::vector<std::string> labels = uniqueLabels(*source);
    for (std::size_t i = 0; i < source->atomCount(); ++i) {
      const Vector3 fractional = cell->toFractional(source->atomPosition3d(i));
      // D and T are the symbols of the hydrogen isotopes, which the reader
      // understands
      std::string symbol = Core::Elements::symbol(source->atomicNumber(i));
      if (source->atomicNumber(i) == 1 && source->isotope(i) == 2)
        symbol = "D";
      else if (source->atomicNumber(i) == 1 && source->isotope(i) == 3)
        symbol = "T";
      std::vector<std::string> row = { cif::quote(labels[i]),
                                       cif::quote(symbol),
                                       formatNumber(fractional.x(), 8),
                                       formatNumber(fractional.y(), 8),
                                       formatNumber(fractional.z(), 8) };
      if (writeOccupancy)
        row.push_back(formatOccupancy(source->occupancy(i)));
      if (writeDisorder) {
        const std::string assembly = source->disorderAssembly(i);
        const std::string group = source->disorderGroup(i);
        row.push_back(assembly.empty() ? "." : cif::quote(assembly));
        row.push_back(group.empty() ? "." : cif::quote(group));
      }
      sites.add_row(row);
    }

    cif::write_cif_to_stream(outStream, document);
  } catch (const std::exception& e) {
    appendError(std::string("Could not write the CIF file: ") + e.what());
    return false;
  }
  return outStream.good();
}

} // namespace Avogadro::Io
