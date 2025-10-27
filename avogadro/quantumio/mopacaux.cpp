/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mopacaux.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::SlaterSet;

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
  while (!in.eof())
    processLine(in);

  auto* basis = new SlaterSet;

  for (unsigned int i = 0; i < m_atomPos.size(); ++i) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_atomNums[i]));
    a.setPosition3d(m_atomPos[i]);
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);

  // check if there is vibrational data
  if (m_frequencies.size() > 0) {
    // convert the std::vector to Array
    Core::Array<double> frequencies(m_frequencies.size());
    for (unsigned int i = 0; i < m_frequencies.size(); ++i)
      frequencies[i] = m_frequencies[i];
    molecule.setVibrationFrequencies(frequencies);

    // convert the std::vector to Array
    Core::Array<double> intensities(m_frequencies.size(), 0.0);
    if (m_irIntensities.size() == m_frequencies.size()) {
      for (unsigned int i = 0; i < m_irIntensities.size(); ++i)
        intensities[i] = m_irIntensities[i];
    }
    molecule.setVibrationIRIntensities(intensities);

    // wrap the normal modes into a vector of vectors
    Core::Array<Core::Array<Vector3>> normalModes;
    Core::Array<Vector3> normalMode;
    Index atomCount = molecule.atomCount();
    for (unsigned int i = 0; i < m_normalModes.size(); ++i) {
      normalMode.push_back(m_normalModes[i]);
      if (i % atomCount == 0 && normalMode.size() > 0) {
        normalModes.push_back(normalMode);
        normalMode.clear();
      }
    }
    molecule.setVibrationLx(normalModes);
  }

  // add charges and properties
  molecule.setData("totalCharge", m_charge);
  molecule.setData("totalSpinMultiplicity", m_spin);
  molecule.setData("dipoleMoment", m_dipoleMoment);
  molecule.setData("DeltaH", m_heatOfFormation);
  molecule.setData("Area", m_area);
  molecule.setData("Volume", m_volume);

  if (m_partialCharges.size() > 0) {
    MatrixX charges(m_partialCharges.size(), 1);
    for (size_t i = 0; i < m_partialCharges.size(); ++i)
      charges(i, 0) = m_partialCharges[i];
    molecule.setPartialCharges("MOPAC", charges);
  }

  // if we have more than one coordinate set
  if (m_coordSets.size() > 1) {
    for (unsigned int i = 0; i < m_coordSets.size(); ++i) {
      Core::Array<Vector3> positions;
      positions.reserve(molecule.atomCount());
      for (size_t j = 0; j < molecule.atomCount(); ++j) {
        positions.push_back(m_coordSets[i][j]);
      }
      molecule.setCoordinate3d(positions, i);
    }
  }

  return true;
}

void MopacAux::processLine(std::istream& in)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  string key = Core::trimmed(line);

  // Big switch statement checking for various things we are interested in
  if (Core::contains(key, "ATOM_EL")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of atoms = " << tmp << endl;
    m_atomNums = readArrayElements(in, tmp);
  } else if (Core::contains(key, "HEAT_OF_FORMATION:KCAL/MOL")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_heatOfFormation = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Heat of formation = " << m_heatOfFormation << " kcal/mol"
           << endl;
    }
  } else if (Core::contains(key, "AREA:SQUARE ANGSTROMS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_area = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Area = " << m_area << " square Angstroms" << endl;
    }
  } else if (Core::contains(key, "VOLUME:CUBIC ANGSTROMS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      std::replace(list[1].begin(), list[1].end(), 'D', 'E');
      m_volume = Core::lexicalCast<double>(list[1]).value_or(0.0);
      cout << "Volume = " << m_volume << " cubic Angstroms" << endl;
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
    cout << "Dipole moment " << m_dipoleMoment.norm() << " Debye" << endl;
  } else if (Core::contains(key, "AO_ATOMINDEX")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of atomic orbitals = " << tmp << endl;
    m_atomIndex = readArrayI(in, tmp);
    for (int& i : m_atomIndex)
      --i;
  } else if (Core::contains(key, "ATOM_SYMTYPE")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of atomic orbital types = " << tmp << endl;
    m_atomSym = readArraySym(in, tmp);
  } else if (Core::contains(key, "AO_ZETA")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of zeta values = " << tmp << endl;
    m_zeta = readArrayD(in, tmp);
  } else if (Core::contains(key, "ATOM_CHARGES")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of atomic charges = " << tmp << endl;
    m_partialCharges = readArrayD(in, tmp);
  } else if (Core::contains(key, "ATOM_PQN")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of PQN values =" << tmp << endl;
    m_pqn = readArrayI(in, tmp);
  } else if (Core::contains(key, "NUM_ELECTRONS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      m_electrons = Core::lexicalCast<int>(list[1]).value_or(0);
      cout << "Number of electrons = " << m_electrons << endl;
    }
  } else if (Core::contains(key, "ATOM_X")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4)).value_or(0);
    cout << "Number of atomic coordinates = " << tmp << endl;
    m_atomPos = readArrayVec(in, tmp);
    m_coordSets.push_back(m_atomPos);
  } else if (Core::contains(key, "OVERLAP_MATRIX")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6)).value_or(0);
    cout << "Size of lower half triangle of overlap matrix = " << tmp << endl;
    readOverlapMatrix(in, tmp);
  } else if (Core::contains(key, "EIGENVECTORS")) {
    // For large molecules the Eigenvectors counter overflows to [*****]
    // So just use the square of the m_atomIndex array
    //      QString tmp = key.mid(key.indexOf('[')+1, 6);
    cout << "Size of eigen vectors matrix = "
         << m_atomIndex.size() * m_atomIndex.size() << endl;
    readEigenVectors(in,
                     static_cast<int>(m_atomIndex.size() * m_atomIndex.size()));
  } else if (Core::contains(key, "TOTAL_DENSITY_MATRIX")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6)).value_or(0);
    cout << "Size of lower half triangle of density matrix = " << tmp << endl;
    readDensityMatrix(in, tmp);
  } else if (Core::contains(key, "VIB._FREQ")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6)).value_or(0);
    readVibrationFrequencies(in, tmp);
  } else if (Core::contains(key, "VIB._T_DIP")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6)).value_or(0);
    readVibrationIntensities(in, tmp);
  } else if (Core::contains(key, "NORMAL_MODES")) {
    int tmp =
      Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6)).value_or(0);
    readNormalModes(in, tmp);
  }
}

void MopacAux::load(SlaterSet* basis)
{
  if (m_atomPos.size() == 0) {
    cout << "No atoms found in .aux file. Bailing out." << endl;
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
    getline(in, line);
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
    getline(in, line);
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
    getline(in, line);
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
    getline(in, line);
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
  vector<Vector3> tmp(n / 3);
  double* ptr = tmp[0].data();
  unsigned int cnt = 0;
  while (cnt < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto& i : list)
      ptr[cnt++] = Core::lexicalCast<double>(i).value_or(0.0);
  }
  return tmp;
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

bool MopacAux::readOverlapMatrix(std::istream& in, unsigned int n)
{
  m_overlap.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first comment line...
  string line;
  getline(in, line);
  while (cnt < n) {
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto& k : list) {
      // m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_overlap(i, j) = m_overlap(j, i) =
        Core::lexicalCast<double>(k).value_or(0.0);
      ++i;
      ++cnt;
      if (i == f) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++f;
        ++j;
      }
    }
  }
  return true;
}

bool MopacAux::readEigenVectors(std::istream& in, unsigned int n)
{
  m_eigenVectors.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  while (cnt < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto& k : list) {
      m_eigenVectors(i, j) = Core::lexicalCast<double>(k).value_or(0.0);
      ++i;
      ++cnt;
      if (i == m_zeta.size()) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++j;
      }
    }
  }
  return true;
}

bool MopacAux::readDensityMatrix(std::istream& in, unsigned int n)
{
  m_density.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first comment line...
  string line;
  getline(in, line);
  while (cnt < n) {
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto& k : list) {
      // m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_density(i, j) = m_density(j, i) =
        Core::lexicalCast<double>(k).value_or(0.0);
      ++i;
      ++cnt;
      if (i == f) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++f;
        ++j;
      }
    }
  }
  return true;
}

void MopacAux::outputAll()
{
  cout << "Shell mappings:\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    cout << i << ": type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << endl;
  cout << "MO coefficients:\n";
  for (double m_MOcoeff : m_MOcoeffs)
    cout << m_MOcoeff << "\t";
  cout << endl;
}
} // namespace Avogadro::QuantumIO
