/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mopacaux.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/conformerquantity.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <algorithm>
#include <cmath>
#include <iostream>
#include <limits>
#include <optional>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::SlaterSet;

namespace {

// The n in a "KEY[n]=" header, or nullopt when the key has no complete
// bracket pair or its contents are not an integer. Counts used to be parsed
// from just after find('[') even when there was none, i.e. from the start of
// the line, so a data line that merely contained e.g. "ATOM_X" and began with
// a number was taken as a header carrying that number.
std::optional<int> arrayCount(const string& key)
{
  const auto lBracket = key.find('[');
  if (lBracket == string::npos)
    return std::nullopt;
  const auto rBracket = key.find(']', lBracket);
  if (rBracket == string::npos)
    return std::nullopt;
  return Core::lexicalCast<int>(
    key.substr(lBracket + 1, rBracket - lBracket - 1));
}

} // namespace

MopacAux::MopacAux() : m_electrons(0) {}

MopacAux::~MopacAux() {}

std::vector<std::string> MopacAux::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("aux");
  return extensions;
}

std::vector<std::string> MopacAux::mimeTypes() const
{
  return std::vector<std::string>();
}

bool MopacAux::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  while (!in.eof()) {
    if (!processLine(in))
      return false;
  }

  auto* basis = new SlaterSet;

  // The element and coordinate counts come from separate headers in the file
  // and need not agree.
  const size_t numAtoms = std::min(m_atomPos.size(), m_atomNums.size());
  for (size_t i = 0; i < numAtoms; ++i) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_atomNums[i]));
    a.setPosition3d(m_atomPos[i]);
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);

  // Bank the last Hessian, which has no following geometry to trigger it.
  flushVibrationData();

  const Index atomCount = molecule.atomCount();

  // Geometries too short to hold every atom are skipped when the conformers
  // are added below, so map each geometry in the file to the conformer index
  // it actually receives; vibrations keyed to a skipped one are dropped.
  constexpr size_t skipped = std::numeric_limits<size_t>::max();
  vector<size_t> conformerIndices(m_coordSets.size(), skipped);
  size_t accepted = 0;
  for (size_t i = 0; i < m_coordSets.size(); ++i) {
    if (m_coordSets[i].size() >= atomCount)
      conformerIndices[i] = accepted++;
  }

  for (const auto& set : m_vibrationSets) {
    if (set.conformerIndex >= conformerIndices.size() ||
        conformerIndices[set.conformerIndex] == skipped)
      continue;

    Core::Molecule::VibrationData data;
    data.frequencies =
      Core::Array<double>(set.frequencies.begin(), set.frequencies.end());

    // The intensities are optional, so pad with zeros unless a full set was
    // read.
    data.irIntensities = Core::Array<double>(set.frequencies.size(), 0.0);
    if (set.irIntensities.size() == set.frequencies.size())
      data.irIntensities =
        Core::Array<double>(set.irIntensities.begin(), set.irIntensities.end());

    // The modes arrive as one displacement per atom per mode, flattened, so
    // they are sliced every atomCount entries. Testing i % atomCount == 0
    // instead emitted a one-displacement first mode and left every later
    // mode straddling two real ones. A trailing partial mode is dropped.
    for (size_t i = 0; atomCount > 0 && i + atomCount <= set.normalModes.size();
         i += atomCount) {
      data.lx.push_back(Core::Array<Vector3>(
        set.normalModes.begin() + i, set.normalModes.begin() + i + atomCount));
    }

    molecule.setVibrationData(data, conformerIndices[set.conformerIndex]);
  }

  // add charges and properties
  // MOPAC reports energies in kcal/mol; store kJ/mol so units are consistent
  // with the rest of Avogadro (e.g. the force-field energies).
  molecule.setData("totalCharge", m_charge);
  molecule.setData("totalSpinMultiplicity", m_spin);
  molecule.setData("dipoleMoment", m_dipoleMoment);
  molecule.setData("DeltaH", m_heatOfFormation * KCAL_TO_KJ);
  molecule.setData("Area", m_area);
  molecule.setData("Volume", m_volume);
  if (!m_energies.empty()) {
    for (auto& e : m_energies)
      e *= KCAL_TO_KJ;
    molecule.setData("energies", m_energies);
  }
  // What the values are, not what MOPAC printed: the loop above has already
  // taken them out of kcal/mol.
  Core::setEnergyUnit(molecule, "kJ/mol");
  if (!m_forces.empty()) {
    // MOPAC reports the gradient norm (GRADIENT_NORM); convert to an RMS
    // gradient (norm / sqrt(3N)) so it is comparable across molecule sizes
    // and matches the convention used elsewhere for per-conformer forces.
    // Also convert kcal/mol/A to kJ/mol/A.
    const size_t dof = 3 * molecule.atomCount();
    const double scale =
      dof > 0 ? KCAL_TO_KJ / std::sqrt(static_cast<double>(dof)) : KCAL_TO_KJ;
    for (auto& f : m_forces)
      f *= scale;
    molecule.setData("forces", m_forces);
  }

  if (!m_partialCharges.empty()) {
    MatrixX charges(m_partialCharges.size(), 1);
    for (size_t i = 0; i < m_partialCharges.size(); ++i)
      charges(i, 0) = m_partialCharges[i];
    molecule.setPartialCharges("MOPAC", charges);
  }

  // if we have more than one coordinate set
  if (m_coordSets.size() > 1) {
    int coordSet = 0;
    for (const auto& coords : m_coordSets) {
      // Each geometry has its own count in the file; skip one too short to
      // hold every atom rather than read past its end.
      if (coords.size() < molecule.atomCount())
        continue;
      Core::Array<Vector3> positions;
      positions.reserve(molecule.atomCount());
      for (size_t j = 0; j < molecule.atomCount(); ++j) {
        positions.push_back(coords[j]);
      }
      molecule.setCoordinate3d(positions, coordSet++);
    }
    // The atoms were added from the last block (ATOM_X_OPT, the optimized
    // geometry), so the active index has to name that set rather than being
    // left at 0 - the input geometry. Anything reading the active conformer,
    // vibrations included, would otherwise be looking at a different
    // structure than the one on screen.
    molecule.setCoordinate3d(coordSet - 1);
  }

  return true;
}

bool MopacAux::processLine(std::istream& in)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!Core::getLine(in, line) || Core::trimmed(line).empty())
    return true;

  string key = Core::trimmed(line);

  // Every array count below comes from a KEY[n]= header and reaches the
  // readers as an unsigned int, where a negative count asks for billions of
  // values.
  if (arrayCount(key).value_or(0) < 0) {
    appendError("Negative array count: " + key);
    return false;
  }

  // Big switch statement checking for various things we are interested in
  if (Core::contains(key, "ATOM_EL")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of atoms = " << tmp << '\n';
    m_atomNums = readArrayElements(in, tmp);
  } else if (Core::contains(key, "HEAT_OF_FORMATION:KCAL/MOL")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_heatOfFormation = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Heat of formation = " << m_heatOfFormation << " kcal/mol"
           << '\n';
    }
  } else if (Core::contains(key, "HEAT_OF_FORM_UPDATED:KCAL/MOL")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_energies.push_back(Core::lexicalCast<double>(list[1]).value_or(0.0));
    }
  } else if (Core::contains(key, "GRADIENT_NORM_UPDATED:KCAL/MOL")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_forces.push_back(Core::lexicalCast<double>(list[1]).value_or(0.0));
    }
  } else if (Core::contains(key, "AREA:SQUARE ANGSTROMS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_area = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Area = " << m_area << " square Angstroms" << '\n';
    }
  } else if (Core::contains(key, "VOLUME:CUBIC ANGSTROMS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_volume = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Volume = " << m_volume << " cubic Angstroms" << '\n';
    }
  } else if (Core::contains(key, "KEYWORDS=")) {
    // parse for charge and spin
    std::vector<std::string> list = Core::split(key, ' ');
    for (size_t i = 0; i < list.size(); ++i) {
      if (Core::contains(list[i], "CHARGE=")) {
        m_charge = Core::lexicalCast<int>(list[i].substr(7)).value_or(0);
      } else if (Core::contains(list[i], "DOUBLET")) {
        m_spin = 2;
      } else if (Core::contains(list[i], "TRIPLET")) {
        m_spin = 3;
      } else if (Core::contains(list[i], "QUARTET")) {
        m_spin = 4;
      } else if (Core::contains(list[i], "QUINTET")) {
        m_spin = 5;
      } else if (Core::contains(list[i], "SEXTET")) {
        m_spin = 6;
      } else if (Core::contains(list[i], "SEPTET")) {
        m_spin = 7;
      } else if (Core::contains(list[i], "OCTET")) {
        m_spin = 8;
      } else if (Core::contains(list[i], "NONET")) {
        m_spin = 9;
      }
    }
  } else if (Core::contains(key, "DIP_VEC:DEBYE")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      // split based on spaces
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      vector<string> dipole = Core::split(list[1], ' ');
      if (dipole.size() == 3) {
        m_dipoleMoment =
          Vector3(Core::lexicalCast<double>(dipole[0]).value_or(0.0),
                  Core::lexicalCast<double>(dipole[1]).value_or(0.0),
                  Core::lexicalCast<double>(dipole[2]).value_or(0.0));
      }
    }
    cout << "Dipole moment " << m_dipoleMoment.norm() << " Debye" << '\n';
  } else if (Core::contains(key, "AO_ATOMINDEX")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of atomic orbitals = " << tmp << '\n';
    m_atomIndex = readArrayI(in, tmp);
    for (int& i : m_atomIndex)
      --i;
  } else if (Core::contains(key, "ATOM_SYMTYPE")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of atomic orbital types = " << tmp << '\n';
    m_atomSym = readArraySym(in, tmp);
  } else if (Core::contains(key, "AO_ZETA")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of zeta values = " << tmp << '\n';
    m_zeta = readArrayD(in, tmp);
  } else if (Core::contains(key, "ATOM_CHARGES")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of atomic charges = " << tmp << '\n';
    m_partialCharges = readArrayD(in, tmp);
  } else if (Core::contains(key, "ATOM_PQN")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of PQN values =" << tmp << '\n';
    m_pqn = readArrayI(in, tmp);
  } else if (Core::contains(key, "NUM_ELECTRONS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      m_electrons = Core::lexicalCast<int>(list[1]).value_or(0);
      cout << "Number of electrons = " << m_electrons << '\n';
    }
  } else if (Core::contains(key, "ATOM_X")) {
    int tmp = arrayCount(key).value_or(0);
    cout << "Number of atomic coordinates = " << tmp << '\n';
    // A new geometry means any Hessian read so far belongs to the previous
    // one, so bank it before the geometry changes underneath it.
    //
    // This branch matches every MOPAC key containing ATOM_X, which is five
    // families: the optimization steps ATOM_X, ATOM_X_UPDATED and ATOM_X_OPT,
    // plus ORIENTATION_ATOM_X and ATOM_X_FORCE. The last two are the same
    // structure re-expressed in the frame the vibrational analysis runs in -
    // the frame the normal modes are given in - rather than another
    // optimization step, so they must not close off the Hessian being read.
    // Otherwise the modes end up keyed to the frame before the one on screen
    // and the molecule reads as having no vibrations at all.
    //
    // Tested by name rather than by substring so that an unrecognised ATOM_X*
    // key from a future MOPAC does not silently match "FORCE" anywhere in it.
    const bool analysisFrame = Core::contains(key, "ORIENTATION_ATOM_X") ||
                               Core::contains(key, "ATOM_X_FORCE");
    if (!analysisFrame)
      flushVibrationData();

    m_atomPos = readArrayVec(in, tmp);
    m_coordSets.push_back(m_atomPos);
  } else if (Core::contains(key, "OVERLAP_MATRIX")) {
    cout << "Size of lower half triangle of overlap matrix = "
         << m_zeta.size() * (m_zeta.size() + 1) / 2 << '\n';
    if (!readOverlapMatrix(in))
      return false;
  } else if (Core::contains(key, "EIGENVECTORS")) {
    // For large molecules the Eigenvectors counter overflows to [*****]
    // So just use the square of the basis size (the number of AO_ZETA values)
    cout << "Size of eigen vectors matrix = " << m_zeta.size() * m_zeta.size()
         << '\n';
    if (!readEigenVectors(in))
      return false;
  } else if (Core::contains(key, "TOTAL_DENSITY_MATRIX")) {
    cout << "Size of lower half triangle of density matrix = "
         << m_zeta.size() * (m_zeta.size() + 1) / 2 << '\n';
    if (!readDensityMatrix(in))
      return false;
  } else if (Core::contains(key, "VIB._FREQ")) {
    int tmp = arrayCount(key).value_or(0);
    readVibrationFrequencies(in, tmp);
  } else if (Core::contains(key, "VIB._T_DIP")) {
    int tmp = arrayCount(key).value_or(0);
    readVibrationIntensities(in, tmp);
  } else if (Core::contains(key, "NORMAL_MODES")) {
    int tmp = arrayCount(key).value_or(0);
    readNormalModes(in, tmp);
  }
  return true;
}

void MopacAux::load(SlaterSet* basis)
{
  if (m_atomPos.empty()) {
    cout << "No atoms found in .aux file. Bailing out." << '\n';
    // basis->setIsValid(false);
    return;
  }
  // Now load up our basis set
  basis->addSlaterIndices(m_atomIndex);
  basis->addSlaterTypes(m_atomSym);
  basis->addZetas(m_zeta);
  basis->addPQNs(m_pqn);
  basis->setElectronCount(m_electrons);
  basis->addOverlapMatrix(m_overlap);
  basis->addEigenVectors(m_eigenVectors);
  basis->addDensityMatrix(m_density);
}

vector<int> MopacAux::readArrayElements(std::istream& in, unsigned int n)
{
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    // A truncated .aux file that promises n elements but never delivers them
    // would otherwise spin forever: the loop condition only checks tmp.size(),
    // not the stream state.
    if (!Core::getLine(in, line))
      break;
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list) {
      tmp.push_back(
        static_cast<int>(Core::Elements::atomicNumberFromSymbol(i)));
    }
  }
  return tmp;
}

vector<int> MopacAux::readArrayI(std::istream& in, unsigned int n)
{
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    // Stop at end of file; see readArrayElements().
    if (!Core::getLine(in, line))
      break;
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list)
      tmp.push_back(Core::lexicalCast<int>(i).value_or(0));
  }
  return tmp;
}

vector<double> MopacAux::readArrayD(std::istream& in, unsigned int n)
{
  vector<double> tmp;
  while (tmp.size() < n) {
    string line;
    // Stop at end of file; see readArrayElements().
    if (!Core::getLine(in, line))
      break;
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list)
      tmp.push_back(Core::lexicalCast<double>(i).value_or(0.0));
  }
  return tmp;
}

vector<int> MopacAux::readArraySym(std::istream& in, unsigned int n)
{
  int type;
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    // Stop at end of file; see readArrayElements().
    if (!Core::getLine(in, line))
      break;
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list) {
      if (i == "S")
        type = SlaterSet::S;
      else if (i == "PX")
        type = SlaterSet::PX;
      else if (i == "PY")
        type = SlaterSet::PY;
      else if (i == "PZ")
        type = SlaterSet::PZ;
      else if (i == "X2")
        type = SlaterSet::X2;
      else if (i == "XZ")
        type = SlaterSet::XZ;
      else if (i == "Z2")
        type = SlaterSet::Z2;
      else if (i == "YZ")
        type = SlaterSet::YZ;
      else if (i == "XY")
        type = SlaterSet::XY;
      else
        type = SlaterSet::UU;
      tmp.push_back(type);
    }
  }
  return tmp;
}

vector<Vector3> MopacAux::readArrayVec(std::istream& in, unsigned int n)
{
  // The vectors are built as the values arrive rather than sized from n: the
  // count is only a header claim, and a bogus one must not decide how much
  // memory is requested. The result is bounded by the file size instead.
  vector<Vector3> tmp;
  const size_t size = 3 * static_cast<size_t>(n / 3);
  Vector3 current;
  size_t cnt = 0;
  // Only whole vectors are stored, and a line may hold more values than the
  // header promised, so never read past 3 * (n / 3) values.
  while (cnt < size) {
    string line;
    // Stop at end of file; see readArrayElements().
    if (!Core::getLine(in, line))
      break;
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list) {
      if (cnt >= size)
        break;
      current[cnt % 3] = Core::lexicalCast<double>(i).value_or(0.0);
      if (++cnt % 3 == 0)
        tmp.push_back(current);
    }
  }
  // A file that ends mid-vector leaves current partly filled; it is dropped.
  return tmp;
}

void MopacAux::flushVibrationData()
{
  if (!m_frequencies.empty() && !m_coordSets.empty()) {
    VibrationSet set;
    // The Hessian belongs to the geometry that precedes it: the last pushed.
    set.conformerIndex = m_coordSets.size() - 1;
    // These are plain std::vectors, so assigning them would be a real deep
    // copy of every displacement; the accumulators are cleared below anyway.
    set.frequencies = std::move(m_frequencies);
    set.irIntensities = std::move(m_irIntensities);
    set.normalModes = std::move(m_normalModes);
    m_vibrationSets.push_back(std::move(set));
  }

  m_frequencies.clear();
  m_irIntensities.clear();
  m_normalModes.clear();
}

bool MopacAux::readVibrationFrequencies(std::istream& in, unsigned int n)
{
  vector<double> tmp = readArrayD(in, n);
  m_frequencies.insert(m_frequencies.end(), tmp.begin(), tmp.end());
  return true;
}

bool MopacAux::readVibrationIntensities(std::istream& in, unsigned int n)
{
  vector<double> tmp = readArrayD(in, n);
  m_irIntensities.insert(m_irIntensities.end(), tmp.begin(), tmp.end());
  return true;
}

bool MopacAux::readNormalModes(std::istream& in, unsigned int n)
{
  vector<Vector3> tmp = readArrayVec(in, n);
  m_normalModes.insert(m_normalModes.end(), tmp.begin(), tmp.end());
  return true;
}

// Read whole lines of numbers until at least n values are held or the stream
// ends. The result is bounded by the size of the input, not by n.
static std::vector<double> readMatrixValues(std::istream& in, size_t n)
{
  vector<double> values;
  string line;
  while (values.size() < n) {
    // Stop at end of file; see readArrayElements().
    if (!Core::getLine(in, line))
      break;
    for (auto& k : Core::split(line, ' '))
      values.push_back(Core::lexicalCast<double>(k).value_or(0.0));
  }
  return values;
}

// The matrices below are basis x basis (m_zeta.size()) no matter how much data
// the block holds, and MOPAC's bracket counts overflow to asterisks for large
// systems, so the expected number of values comes from the basis size. The
// values are read first and the matrix is only allocated once the block is
// known to be complete: a corrupt AO_ZETA count followed by a short block
// used to reserve gigabytes for a file of a few hundred kilobytes.
bool MopacAux::readOverlapMatrix(std::istream& in)
{
  const size_t dim = m_zeta.size();
  const size_t expected = dim * (dim + 1) / 2;
  // Skip the first comment line...
  string line;
  Core::getLine(in, line);
  const vector<double> values = readMatrixValues(in, expected);
  if (values.size() != expected) {
    appendError("Overlap matrix size does not match the basis.");
    return false;
  }
  m_overlap.resize(dim, dim);
  size_t cnt = 0;
  for (size_t j = 0; j < dim; ++j) {
    // Lower triangle, row by row; mirror it into the upper triangle
    for (size_t i = 0; i <= j; ++i)
      m_overlap(i, j) = m_overlap(j, i) = values[cnt++];
  }
  return true;
}

bool MopacAux::readEigenVectors(std::istream& in)
{
  const size_t dim = m_zeta.size();
  const size_t expected = dim * dim;
  const vector<double> values = readMatrixValues(in, expected);
  if (values.size() != expected) {
    appendError("Eigenvector matrix size does not match the basis.");
    return false;
  }
  m_eigenVectors.resize(dim, dim);
  // Stored one eigenvector (column) after another
  size_t cnt = 0;
  for (size_t j = 0; j < dim; ++j) {
    for (size_t i = 0; i < dim; ++i)
      m_eigenVectors(i, j) = values[cnt++];
  }
  return true;
}

bool MopacAux::readDensityMatrix(std::istream& in)
{
  const size_t dim = m_zeta.size();
  const size_t expected = dim * (dim + 1) / 2;
  // Skip the first comment line...
  string line;
  Core::getLine(in, line);
  const vector<double> values = readMatrixValues(in, expected);
  if (values.size() != expected) {
    appendError("Density matrix size does not match the basis.");
    return false;
  }
  m_density.resize(dim, dim);
  size_t cnt = 0;
  for (size_t j = 0; j < dim; ++j) {
    for (size_t i = 0; i <= j; ++i)
      m_density(i, j) = m_density(j, i) = values[cnt++];
  }
  return true;
}

void MopacAux::outputAll()
{
  cout << "Shell mappings:\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    cout << i << ": type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << '\n';
  cout << "MO coefficients:\n";
  for (double m_MOcoeff : m_MOcoeffs)
    cout << m_MOcoeff << "\t";
  cout << '\n';
}
} // namespace Avogadro::QuantumIO
