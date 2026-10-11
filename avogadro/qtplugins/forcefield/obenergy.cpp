/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
  It links to the Open Babel library, which is released under the GNU GPL v2.
******************************************************************************/

#include "obenergy.h"

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/utilities.h>

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

#include <iostream>
#include <memory>

using namespace OpenBabel;

namespace Avogadro::QtPlugins {

class OBEnergy::Private
{
public:
  // OBMol and OBForceField are owned by this class
  std::unique_ptr<OBMol> m_obmol;
  // A private clone, never the plugin singleton (see setupForceField).
  std::unique_ptr<OBForceField> m_forceField;
  bool setup = false;

  // Open Babel hands out one global instance per force field plugin.
  // Setup() reassigns that instance's molecule and reallocates its gradient
  // array, so sharing it across the energy readout, the optimizer worker and
  // the AutoOpt worker thread means one caller frees the atoms and gradients
  // another is still reading. MakeNewInstance() is Open Babel's documented
  // way to get a private copy for exactly this reason.
  bool setupForceField(const std::string& method)
  {
    if (m_forceField != nullptr)
      return true;

    auto* plugin = static_cast<OBForceField*>(
      OBPlugin::GetPlugin("forcefields", method.c_str()));
    if (plugin == nullptr)
      return false;

    m_forceField.reset(plugin->MakeNewInstance());
    if (m_forceField == nullptr)
      return false;

    // OBForceField leaves _loglvl and _logos uninitialized: no constructor
    // sets them, and the plugin singleton only escaped that because static
    // storage zeroed it. A heap clone gets whatever the allocator hands back,
    // so a garbage _loglvl enables logging and a garbage _logos is then
    // dereferenced (OBFFLog only checks it against null). Pin both.
    m_forceField->SetLogLevel(OBFF_LOGLVL_NONE);
    m_forceField->SetLogFile(&std::clog);
    return true;
  }
};

OBEnergy::OBEnergy(const std::string& method)
  : m_molecule(nullptr), m_identifier(method), m_name(method)
{
  d = new Private;

  // make sure we set the Open Babel variables for data files, leaving any
  // setting from the environment alone
  if (qgetenv("BABEL_DATADIR").isEmpty()) {
    const QString dataDir = QtGui::Utilities::openBabelDataDirectory();
    if (!dataDir.isEmpty())
      qputenv("BABEL_DATADIR", dataDir.toLocal8Bit());
    else
      qDebug() << "Error, Open Babel data directory not found.";
  }

  if (qgetenv("BABEL_LIBDIR").isEmpty()) {
    const QString pluginDir = QtGui::Utilities::openBabelLibraryDirectory();
    if (!pluginDir.isEmpty())
      qputenv("BABEL_LIBDIR", pluginDir.toLocal8Bit());
  }
  // Ensure the plugins are loaded
  OBPlugin::LoadAllPlugins();

  // The private force field instance is created lazily in setMolecule():
  // MakeNewInstance() allocates it and the first Setup() then calls
  // ParseParamFile() to load the parameters. Neither is worth doing for an
  // instance that is only ever queried for its identifier or element mask.

#ifndef NDEBUG
  qDebug() << "OBEnergy: method: " << method.c_str();
  if (OBPlugin::GetPlugin("forcefields", method.c_str()) == nullptr) {
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

    // also Fe+2, Fe+3, Li+, Na+, K+, Zn+2, Ca+2, Cu+1, Cu+2, and Mg+2
    m_elements.set(26);
    m_elements.set(3);
    m_elements.set(11);
    m_elements.set(19);
    m_elements.set(20);
    m_elements.set(29);
    m_elements.set(30);
    m_elements.set(12);
  }
}

OBEnergy::~OBEnergy()
{
  delete d;
}

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

  // set up our internal OBMol, discarding any molecule from a previous call
  d->setup = false;
  d->m_obmol = std::make_unique<OBMol>();
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
  if (d->setupForceField(m_identifier))
    d->setup = d->m_forceField->Setup(*d->m_obmol);
}

Real OBEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      d->m_obmol == nullptr || !d->setup)
    return 0.0; // nothing to do

  // OBMol::SetCoordinates() blindly copies 3 * NumAtoms() doubles out of the
  // supplied array, so a stale coordinate vector would read off the end.
  const auto n = d->m_obmol->NumAtoms();
  if (x.size() != static_cast<Eigen::Index>(3 * n))
    return 0.0;

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

Real OBEnergy::evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* grad)
{
  if (grad == nullptr)
    return value(x);

  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      d->m_obmol == nullptr || !d->setup) {
    grad->setZero();
    return 0.0;
  }

  // The gradient array is sized for the molecule the force field was set up
  // with, which is not necessarily the molecule we were handed since - bail
  // out rather than read past either buffer. Zero the caller's gradient so a
  // reused buffer can't feed a previous iteration's forces back to the
  // optimizer alongside our zero energy.
  const auto n = d->m_obmol->NumAtoms();
  if (x.size() != static_cast<Eigen::Index>(3 * n)) {
    grad->setZero();
    return 0.0;
  }

  d->m_obmol->SetCoordinates(const_cast<double*>(x.data()));

  double energy = 0.0;
  if (d->m_forceField != nullptr) {
    d->m_forceField->SetCoordinates(*d->m_obmol);
    energy = d->m_forceField->Energy(true);

    // GetGradientPtr returns forces (not gradients), so negate
    Eigen::Map<const Eigen::VectorXd> obForces(
      d->m_forceField->GetGradientPtr(), 3 * n);
    *grad = -obForces;

    // if method is not GAFF, convert to kJ/mol
    if (m_identifier != "GAFF") {
      energy *= Calc::KCAL_TO_KJ;
      *grad *= Calc::KCAL_TO_KJ;
    }

    cleanGradients(*grad);
    constraintGradients(x, *grad);
  }

  energy += constraintEnergies(x);
  return energy;
}

void OBEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  evaluate(x, &grad);
}

} // namespace Avogadro::QtPlugins
