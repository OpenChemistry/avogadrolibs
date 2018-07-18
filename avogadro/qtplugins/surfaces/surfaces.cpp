/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.
  Copyright 2018 Geoffrey Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#include "surfaces.h"
#include "surfacedialog.h"

#include "gaussiansetconcurrent.h"
#include "slatersetconcurrent.h"

#include <avogadro/core/variant.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussiansettools.h>

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>

#include <QtCore/QDebug>
#include <QtWidgets/QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

using Core::Cube;
using Core::GaussianSet;

Surfaces::Surfaces(QObject* p)
  : ExtensionPlugin(p)
  , m_progressDialog(nullptr)
  , m_molecule(nullptr)
  , m_basis(nullptr)
  , m_gaussianConcurrent(nullptr)
  , m_slaterConcurrent(nullptr)
  , m_cube(nullptr)
  , m_mesh1(nullptr)
  , m_mesh2(nullptr)
  , m_meshGenerator1(nullptr)
  , m_meshGenerator2(nullptr)
  , m_dialog(nullptr)
{
  QAction* action = new QAction(this);
  action->setText(tr("Create Surfaces..."));
  connect(action, SIGNAL(triggered()), SLOT(surfacesActivated()));
  m_actions.push_back(action);

  // Register quantum file formats
  Io::FileFormatManager::registerFormat(new QuantumIO::GAMESSUSOutput);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianFchk);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianCube);
  Io::FileFormatManager::registerFormat(new QuantumIO::MoldenFile);
  Io::FileFormatManager::registerFormat(new QuantumIO::MopacAux);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemJson);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemLog);
}

Surfaces::~Surfaces()
{
  delete m_cube;
}

void Surfaces::setMolecule(QtGui::Molecule* mol)
{
  if (mol->basisSet()) {
    m_basis = mol->basisSet();
  } else if (mol->cubes().size() != 0) {
    m_cubes = mol->cubes();
  }

  m_molecule = mol;
}

QList<QAction*> Surfaces::actions() const
{
  return m_actions;
}

QStringList Surfaces::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Extensions");
  return path;
}

void Surfaces::surfacesActivated()
{
  if (!m_dialog) {
    m_dialog = new SurfaceDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(calculateClickedSignal()),
            SLOT(calculateSurface()));
  }

  if (m_basis) {
    // we have quantum data, set up the dialog accordingly
    auto gaussian = dynamic_cast<Core::GaussianSet*>(m_basis);
    bool beta = false;
    if (gaussian) {
      auto b = gaussian->moMatrix(GaussianSet::Beta);
      if (b.rows() > 0 && b.cols() > 0)
        beta = true;
    }
    m_dialog->setupBasis(m_basis->electronCount(),
                         m_basis->molecularOrbitalCount(), beta);
  }
  if (m_cubes.size() > 0) {
    QStringList cubeNames;
    for (unsigned int i = 0; i < m_cubes.size(); ++i) {
      cubeNames << m_cubes[i]->name().c_str();
    }

    m_dialog->setupCubes(cubeNames);
  }

  m_dialog->show();
}

void Surfaces::calculateSurface()
{
  if (!m_dialog)
    return;

  Type type = m_dialog->surfaceType();
  if (!m_cube)
    m_cube = m_molecule->addCube();
  // TODO we should add a name, type, etc.

  switch (type) {
    case VanDerWaals:
    case SolventAccessible:
    case SolventExcluded:
      calculateEDT();
      // pass a molecule and return a Cube for m_cube
      //   displayMesh();
      break;

    case ElectronDensity:
    case MolecularOrbital:
    case ElectrostaticPotential:
    case SpinDensity:
      calculateQM();
      break;

    case FromFile:
    default:
      calculateCube();
      break;
  }
}

void Surfaces::calculateEDT()
{
  // pass the molecule to the EDT, plus the surface type
  // get back a Cube object in m_cube
}

void Surfaces::calculateQM()
{
  if (!m_basis || !m_dialog)
    return; // nothing to do

  // set up QtConcurrent calculators for Gaussian or Slater basis sets
  if (dynamic_cast<GaussianSet*>(m_basis)) {
    if (!m_gaussianConcurrent)
      m_gaussianConcurrent = new GaussianSetConcurrent(this);
    m_gaussianConcurrent->setMolecule(m_molecule);
  } else {
    if (!m_slaterConcurrent)
      m_slaterConcurrent = new SlaterSetConcurrent(this);
    m_slaterConcurrent->setMolecule(m_molecule);
  }

  // TODO: Check to see if this cube or surface has already been computed
  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
    m_progressDialog->setCancelButtonText(nullptr);
    m_progressDialog->setWindowModality(Qt::NonModal);
  }

  if (!m_cube)
    m_cube = m_molecule->addCube();

  Type type = m_dialog->surfaceType();
  int index = m_dialog->surfaceIndex();
  m_isoValue = m_dialog->isosurfaceValue();
  m_cube->setLimits(*m_molecule, m_dialog->resolution(), 5.0);

  QString progressText;
  if (type == ElectronDensity) {
    progressText = tr("Calculating electron density");
    if (dynamic_cast<GaussianSet*>(m_basis)) {
      m_gaussianConcurrent->calculateElectronDensity(m_cube);
    } else {
      m_slaterConcurrent->calculateElectronDensity(m_cube);
    }
  }

  else if (type == MolecularOrbital) {
    progressText = tr("Calculating molecular orbital %L1").arg(index);
    if (dynamic_cast<GaussianSet*>(m_basis)) {
      m_gaussianConcurrent->calculateMolecularOrbital(m_cube, index,
                                                      m_dialog->beta());
    } else {
      m_slaterConcurrent->calculateMolecularOrbital(m_cube, index);
    }
  }

  // Set up the progress dialog.
  if (dynamic_cast<GaussianSet*>(m_basis)) {
    m_progressDialog->setWindowTitle(progressText);
    m_progressDialog->setRange(
      m_gaussianConcurrent->watcher().progressMinimum(),
      m_gaussianConcurrent->watcher().progressMaximum());
    m_progressDialog->setValue(m_gaussianConcurrent->watcher().progressValue());
    m_progressDialog->show();

    connect(&m_gaussianConcurrent->watcher(), SIGNAL(progressValueChanged(int)),
            m_progressDialog, SLOT(setValue(int)));
    connect(&m_gaussianConcurrent->watcher(),
            SIGNAL(progressRangeChanged(int, int)), m_progressDialog,
            SLOT(setRange(int, int)));
    connect(&m_gaussianConcurrent->watcher(), SIGNAL(finished()),
            SLOT(displayMesh()));
  } else {
    // slaters
    m_progressDialog->setWindowTitle(progressText);
    m_progressDialog->setRange(m_slaterConcurrent->watcher().progressMinimum(),
                               m_slaterConcurrent->watcher().progressMaximum());
    m_progressDialog->setValue(m_slaterConcurrent->watcher().progressValue());
    m_progressDialog->show();

    connect(&m_slaterConcurrent->watcher(), SIGNAL(progressValueChanged(int)),
            m_progressDialog, SLOT(setValue(int)));
    connect(&m_slaterConcurrent->watcher(),
            SIGNAL(progressRangeChanged(int, int)), m_progressDialog,
            SLOT(setRange(int, int)));
    connect(&m_slaterConcurrent->watcher(), SIGNAL(finished()),
            SLOT(displayMesh()));
  }
}

void Surfaces::calculateCube()
{
  if (!m_dialog || m_cubes.size() == 0)
    return;

  // check bounds
  m_cube = m_cubes[m_dialog->surfaceIndex()];
  m_isoValue = m_dialog->isosurfaceValue();
  displayMesh();
}

void Surfaces::displayMesh()
{
  if (!m_cube)
    return;

  if (!m_mesh1)
    m_mesh1 = m_molecule->addMesh();
  if (!m_meshGenerator1) {
    m_meshGenerator1 = new QtGui::MeshGenerator;
    connect(m_meshGenerator1, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator1->initialize(m_cube, m_mesh1, m_isoValue);
  m_meshGenerator1->start();

  // TODO - only do this if we're generating an orbital
  //    and we need two meshes
  //   How do we know? - likely ask the cube if it's an MO?
  if (!m_mesh2)
    m_mesh2 = m_molecule->addMesh();
  if (!m_meshGenerator2) {
    m_meshGenerator2 = new QtGui::MeshGenerator;
    connect(m_meshGenerator2, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator2->initialize(m_cube, m_mesh2, -m_isoValue, true);
  m_meshGenerator2->start();
}

void Surfaces::meshFinished()
{
  m_dialog->reenableCalculateButton();
  m_molecule->emitChanged(QtGui::Molecule::Added);
  // TODO: enable the mesh display type
}

} // namespace QtPlugins
} // namespace Avogadro
