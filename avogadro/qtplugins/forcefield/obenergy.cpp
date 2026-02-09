/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
  It links to the Open Babel library, which is released under the GNU GPL v2.
******************************************************************************/

#include "obenergy.h"

#include <avogadro/core/molecule.h>

#include <openbabel/babelconfig.h>

#include <openbabel/atom.h>
#include <openbabel/base.h>
#include <openbabel/forcefield.h>
#include <openbabel/math/vector3.h>
#include <openbabel/mol.h>
#include <openbabel/obconversion.h>
#include <openbabel/obiter.h>

#include <QCoreApplication>
#include <QDebug>
#include <QDir>

using namespace OpenBabel;

namespace Avogadro::QtPlugins {

class OBEnergy::Private
{
public:
  // OBMol and OBForceField are owned by this class
  OBMol* m_obmol = nullptr;
  OBForceField* m_forceField = nullptr;
  bool setup = false;

  ~Private()
  {
    if (m_obmol != nullptr)
      delete m_obmol;
  }
};

OBEnergy::OBEnergy(const std::string& method)
  : m_identifier(method), m_name(method), m_molecule(nullptr)
{
  d = new Private;

  // make sure we set the Open Babel variables for data files
#ifdef _WIN32
  QByteArray dataDir =
    QString(QCoreApplication::applicationDirPath() + "/data").toLocal8Bit();
  qputenv("BABEL_DATADIR", dataDir);
#else
  // check if BABEL_DATADIR is set in the environment
  QStringList filters;
  filters << "3.*"
          << "2.*";
  if (qgetenv("BABEL_DATADIR").isEmpty()) {
    QDir dir(QCoreApplication::applicationDirPath() + "/../share/openbabel");
    QStringList dirs = dir.entryList(filters);
    if (dirs.size() == 1) {
      // versioned data directory
      QString dataDir = QCoreApplication::applicationDirPath() +
                        "/../share/openbabel/" + dirs[0];
      qputenv("BABEL_DATADIR", dataDir.toLocal8Bit());
    } else {
      qDebug() << "Error, Open Babel data directory not found.";
    }
  }

  // Check if BABEL_LIBDIR is set
  if (qgetenv("BABEL_LIBDIR").isEmpty()) {
    QDir dir(QCoreApplication::applicationDirPath() + "/../lib/openbabel");
    QStringList dirs = dir.entryList(filters);
    if (dirs.size() == 0) {
      QString libDir =
        QCoreApplication::applicationDirPath() + "/../lib/openbabel/";
      qputenv("BABEL_LIBDIR", libDir.toLocal8Bit());
    } else if (dirs.size() == 1) {
      QString libDir =
        QCoreApplication::applicationDirPath() + "/../lib/openbabel/" + dirs[0];
      qputenv("BABEL_LIBDIR", libDir.toLocal8Bit());
    } else {
      qDebug() << "Error, Open Babel plugins directory not found.";
    }
  }
#endif
  // Ensure the plugins are loaded
  OBPlugin::LoadAllPlugins();

  d->m_forceField = static_cast<OBForceField*>(
    OBPlugin::GetPlugin("forcefields", method.c_str()));

#ifndef NDEBUG
  qDebug() << "OBEnergy: method: " << method.c_str();
  if (d->m_forceField == nullptr) {
    qDebug() << "OBEnergy: method not found: " << method.c_str();
    qDebug() << OBPlugin::ListAsString("forcefields").c_str();
  }
#endif

  if (method == "UFF") {
    m_description = tr("Universal Force Field");
    m_elements.reset();
    for (unsigned int i = 1; i < 102; ++i)
      m_elements.set(i);
  } else if (method == "GAFF") {
    m_description = tr("Generalized Amber Force Field");

    // H, C, N, O, F, P, S, Cl, Br, and I
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);
  } else if (method == "MMFF94") {
    m_description = tr("Merck Molecular Force Field 94");
    m_elements.reset();

    // H, C, N, O, F, Si, P, S, Cl, Br, and I
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(14);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);
  }
}

OBEnergy::~OBEnergy() {}

bool OBEnergy::acceptsRadicals() const
{
  if (m_identifier == "UFF")
    return true;

  return false;
}

Calc::EnergyCalculator* OBEnergy::newInstance() const
{
  return new OBEnergy(m_name);
}

void OBEnergy::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr || mol->atomCount() == 0) {
    return; // nothing to do
  }

  // set up our internal OBMol
  d->m_obmol = new OBMol;
  // copy the atoms, bonds, and coordinates
  d->m_obmol->BeginModify();
  for (size_t i = 0; i < mol->atomCount(); ++i) {
    const Core::Atom& atom = mol->atom(i);
    OBAtom* obAtom = d->m_obmol->NewAtom();
    obAtom->SetAtomicNum(atom.atomicNumber());
    auto pos = atom.position3d().cast<double>();
    obAtom->SetVector(pos.x(), pos.y(), pos.z());
  }
  for (size_t i = 0; i < mol->bondCount(); ++i) {
    const Core::Bond& bond = mol->bond(i);
    d->m_obmol->AddBond(bond.atom1().index() + 1, bond.atom2().index() + 1,
                        bond.order());
  }
  d->m_obmol->EndModify();

  // make sure we can set up the force field
  if (d->m_forceField != nullptr) {
    d->setup = d->m_forceField->Setup(*d->m_obmol);
  } else {
    d->m_forceField = static_cast<OBForceField*>(
      OBPlugin::GetPlugin("forcefields", m_identifier.c_str()));
    if (d->m_forceField != nullptr) {
      d->setup = d->m_forceField->Setup(*d->m_obmol);
    }
  }
}

Real OBEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      d->m_obmol == nullptr || !d->setup)
    return 0.0; // nothing to do

  // update all coordinates at once (SetCoordinates copies the array)
  d->m_obmol->SetCoordinates(const_cast<double*>(x.data()));

  double energy = 0.0;
  if (d->m_forceField != nullptr) {
    d->m_forceField->SetCoordinates(*d->m_obmol);
    energy = d->m_forceField->Energy(false);
  }

  // if method is not GAFF, convert to kJ/mol
  if (m_identifier != "GAFF")
    energy *= Calc::KCAL_TO_KJ;

  // make sure to add in any constraint penalties
  energy += constraintEnergies(x);

  return energy;
}

void OBEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      d->m_obmol == nullptr || !d->setup)
    return;

  // update all coordinates at once (SetCoordinates copies the array)
  d->m_obmol->SetCoordinates(const_cast<double*>(x.data()));

  if (d->m_forceField != nullptr) {
    d->m_forceField->SetCoordinates(*d->m_obmol);

    // make sure gradients are calculated
    double energy = d->m_forceField->Energy(true);

    // GetGradientPtr returns forces (not gradients), so negate
    auto n = m_molecule->atomCount();
    Eigen::Map<const Eigen::VectorXd> obForces(
      d->m_forceField->GetGradientPtr(), 3 * n);
    grad = -obForces;

    // if method is not GAFF, convert to kJ/mol
    if (m_identifier != "GAFF")
      grad *= Calc::KCAL_TO_KJ;

    cleanGradients(grad);
    // add in any constraints
    constraintGradients(x, grad);
  }
}

} // namespace Avogadro::QtPlugins
