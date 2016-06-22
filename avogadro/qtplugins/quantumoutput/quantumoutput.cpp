/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#include "quantumoutput.h"
#include "surfacedialog.h"

#include "gaussiansetconcurrent.h"
#include "slatersetconcurrent.h"

#include <avogadro/core/variant.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussiansettools.h>

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/gaussiancube.h>
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

using Core::GaussianSet;
using Core::Cube;

QuantumOutput::QuantumOutput(QObject *p) :
  ExtensionPlugin(p),
  m_progressDialog(NULL),
  m_molecule(NULL),
  m_basis(NULL),
  m_concurrent(NULL),
  m_concurrent2(NULL),
  m_cube(NULL),
  m_mesh1(NULL),
  m_mesh2(NULL),
  m_meshGenerator1(NULL),
  m_meshGenerator2(NULL),
  m_dialog(NULL)
{
  QAction *action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Calculate electronic surfaces..."));
  connect(action, SIGNAL(triggered()), SLOT(surfacesActivated()));
  m_actions.push_back(action);

  // Register our quantum file format.
  Io::FileFormatManager::registerFormat(new QuantumIO::GAMESSUSOutput);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianFchk);
  Io::FileFormatManager::registerFormat(new QuantumIO::GaussianCube);
  Io::FileFormatManager::registerFormat(new QuantumIO::MoldenFile);
  Io::FileFormatManager::registerFormat(new QuantumIO::MopacAux);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemJson);
  Io::FileFormatManager::registerFormat(new QuantumIO::NWChemLog);
}

QuantumOutput::~QuantumOutput()
{
  delete m_cube;
}

void QuantumOutput::setMolecule(QtGui::Molecule *mol)
{
  if (mol->basisSet()) {
    m_basis = mol->basisSet();
    m_actions[0]->setEnabled(true);
  }
  else if (mol->cubes().size() != 0) {
    m_cubes = mol->cubes();
    m_actions[0]->setEnabled(true);
  }

  m_molecule = mol;
}

QList<QAction *> QuantumOutput::actions() const
{
  return m_actions;
}

QStringList QuantumOutput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Quantum");
  return path;
}

void QuantumOutput::surfacesActivated()
{
  if (!m_basis && !(m_cubes.size() > 0))
    return;

  if (!m_dialog) {
    m_dialog = new SurfaceDialog(qobject_cast<QWidget *>(parent()));
    connect(m_dialog, SIGNAL(calculateClickedSignal(int, float, float)),
            SLOT(calculateSurface(int, float, float)));
  }

  if (m_basis) {
    m_cubes.resize(m_basis->molecularOrbitalCount() + 1);
    m_dialog->setupBasis(m_basis->electronCount(),
                         m_basis->molecularOrbitalCount());
  }
  else if (m_cubes.size() > 0) {
    m_dialog->setupCube(m_cubes.size());
  }

  m_dialog->show();
}

void QuantumOutput::calculateSurface(int index, float isosurfaceValue,
                      float resolutionStepSize)
{
  if (m_basis) {
    if (!m_progressDialog) {
      m_progressDialog = new QProgressDialog(qobject_cast<QWidget *>(parent()));
      m_progressDialog->setCancelButtonText(NULL);
      m_progressDialog->setWindowModality(Qt::NonModal);
    }

    if (!m_cube)
      m_cube = m_molecule->addCube();

    if (!m_concurrent)
      m_concurrent = new GaussianSetConcurrent(this);
    if (!m_concurrent2)
      m_concurrent2 = new SlaterSetConcurrent(this);
    m_concurrent->setMolecule(m_molecule);
    m_concurrent2->setMolecule(m_molecule);

    m_isoValue = isosurfaceValue;
    m_cube->setLimits(*m_molecule, resolutionStepSize, 5.0);
    QString progressText;
    if (index == 0) {
      if (dynamic_cast<GaussianSet *>(m_basis)) {
        m_concurrent->calculateElectronDensity(m_cube);
      }
      else {
        m_concurrent2->calculateElectronDensity(m_cube);
      }
      progressText = tr("Calculating electron density");
    }
    else {
      if (dynamic_cast<GaussianSet *>(m_basis)) {
        m_concurrent->calculateMolecularOrbital(m_cube, index - 1);
      }
      else {
        m_concurrent2->calculateMolecularOrbital(m_cube, index - 1);
      }
      progressText = tr("Calculating molecular orbital %L1").arg(index - 1);
    }
    // Set up the progress dialog.
    if (dynamic_cast<GaussianSet *>(m_basis)) {
      m_progressDialog->setWindowTitle(progressText);
      m_progressDialog->setRange(m_concurrent->watcher().progressMinimum(),
                                  m_concurrent->watcher().progressMaximum());
      m_progressDialog->setValue(m_concurrent->watcher().progressValue());
      m_progressDialog->show();

      connect(&m_concurrent->watcher(), SIGNAL(progressValueChanged(int)),
              m_progressDialog, SLOT(setValue(int)));
      connect(&m_concurrent->watcher(), SIGNAL(progressRangeChanged(int, int)),
              m_progressDialog, SLOT(setRange(int, int)));
      connect(&m_concurrent->watcher(), SIGNAL(finished()),
              SLOT(displayCube()));
    }
    else {
      m_progressDialog->setWindowTitle(progressText);
      m_progressDialog->setRange(m_concurrent2->watcher().progressMinimum(),
                                  m_concurrent2->watcher().progressMaximum());
      m_progressDialog->setValue(m_concurrent2->watcher().progressValue());
      m_progressDialog->show();

      connect(&m_concurrent2->watcher(), SIGNAL(progressValueChanged(int)),
              m_progressDialog, SLOT(setValue(int)));
      connect(&m_concurrent2->watcher(), SIGNAL(progressRangeChanged(int, int)),
              m_progressDialog, SLOT(setRange(int, int)));
      connect(&m_concurrent2->watcher(), SIGNAL(finished()),
              SLOT(displayCube()));
    }
  }

  else if (m_cubes.size() > 0) {
    m_cube = m_cubes[index];
    m_isoValue = isosurfaceValue;
    displayCube();
  }
}

void QuantumOutput::displayCube()
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

  if (!m_mesh2)
    m_mesh2 = m_molecule->addMesh();
  if (!m_meshGenerator2) {
    m_meshGenerator2 = new QtGui::MeshGenerator;
    connect(m_meshGenerator2, SIGNAL(finished()), SLOT(meshFinished()));
  }
  m_meshGenerator2->initialize(m_cube, m_mesh2, -m_isoValue, true);
  m_meshGenerator2->start();
}

void QuantumOutput::meshFinished()
{
  m_dialog->reenableCalculateButton();
  m_molecule->emitChanged(QtGui::Molecule::Added);
}

}
}
