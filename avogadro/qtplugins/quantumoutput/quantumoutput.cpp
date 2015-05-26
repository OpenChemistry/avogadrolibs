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
  action->setText(tr("Calculate HOMO"));
  connect(action, SIGNAL(triggered()), SLOT(homoActivated()));
  m_actions.push_back(action);
  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Calculate LUMO"));
  connect(action, SIGNAL(triggered()), SLOT(lumoActivated()));
  m_actions.push_back(action);
  action = new QAction(this);
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
}

QuantumOutput::~QuantumOutput()
{
  delete m_cube;
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

void QuantumOutput::setMolecule(QtGui::Molecule *mol)
{
  bool isQuantum(false);
  if (mol->basisSet()) {
    m_basis = mol->basisSet();
    isQuantum = true;
  }
  m_actions[0]->setEnabled(isQuantum);
  m_actions[1]->setEnabled(isQuantum);
  m_actions[2]->setEnabled(isQuantum);
  m_molecule = mol;
}

void QuantumOutput::homoActivated()
{
  if (m_basis)
    calculateMolecularOrbital(m_basis->electronCount() / 2, 0.02f, 0.2f);
}

void QuantumOutput::lumoActivated()
{
  if (m_basis)
    calculateMolecularOrbital(m_basis->electronCount() / 2 + 1, 0.02f, 0.2f);
}

void QuantumOutput::surfacesActivated()
{
  if (!m_basis)
    return;

  if (!m_dialog) {
    m_dialog = new SurfaceDialog(qobject_cast<QWidget *>(parent()));
    connect(m_dialog, SIGNAL(calculateMO(int,float,float)),
            SLOT(calculateMolecularOrbital(int,float,float)));
    connect(m_dialog, SIGNAL(calculateElectronDensity(float,float)),
            SLOT(calculateElectronDensity(float,float)));
  }

  m_dialog->setNumberOfElectrons(m_basis->electronCount(),
                                 m_basis->molecularOrbitalCount());
  m_dialog->show();
}

void QuantumOutput::calculateMolecularOrbital(int molecularOrbital,
                                              float isoValue, float stepSize)
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

    m_isoValue = isoValue;
    m_cube->setLimits(*m_molecule, stepSize, 5.0);
    QString progressText;
    if (molecularOrbital == -1) {
      if (dynamic_cast<GaussianSet *>(m_basis))
        m_concurrent->calculateElectronDensity(m_cube);
      else
        m_concurrent2->calculateElectronDensity(m_cube);
      progressText = tr("Calculating electron density");
    }
    else {
      if (dynamic_cast<GaussianSet *>(m_basis))
        m_concurrent->calculateMolecularOrbital(m_cube, molecularOrbital);
      else
        m_concurrent2->calculateMolecularOrbital(m_cube, molecularOrbital);
      progressText =
          tr("Calculating molecular orbital %L1").arg(molecularOrbital);
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
    connect(&m_concurrent->watcher(), SIGNAL(progressRangeChanged(int,int)),
            m_progressDialog, SLOT(setRange(int,int)));
    //connect(&m_concurrent->watcher(), SIGNAL(canceled()), SLOT(calculateCanceled()));
    connect(&m_concurrent->watcher(), SIGNAL(finished()), SLOT(calculateFinished()));
    }
    else {
      m_progressDialog->setWindowTitle(progressText);
      m_progressDialog->setRange(m_concurrent2->watcher().progressMinimum(),
                                 m_concurrent2->watcher().progressMaximum());
      m_progressDialog->setValue(m_concurrent2->watcher().progressValue());
      m_progressDialog->show();

      connect(&m_concurrent2->watcher(), SIGNAL(progressValueChanged(int)),
              m_progressDialog, SLOT(setValue(int)));
      connect(&m_concurrent2->watcher(), SIGNAL(progressRangeChanged(int,int)),
              m_progressDialog, SLOT(setRange(int,int)));
      //connect(&m_concurrent->watcher(), SIGNAL(canceled()), SLOT(calculateCanceled()));
      connect(&m_concurrent2->watcher(), SIGNAL(finished()), SLOT(calculateFinished()));
    }
  }
}

void QuantumOutput::calculateElectronDensity(float isoValue, float stepSize)
{
  // Call through to calculate molecular orbital using -1 for density.
  calculateMolecularOrbital(-1, isoValue, stepSize);
}

void QuantumOutput::calculateFinished()
{
  qDebug() << "The calculation finished!";
  if (!m_cube)
    return;

  disconnect(&m_concurrent->watcher(), 0, 0, 0);

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

  if (m_dialog)
    m_dialog->setCalculationEnabled(true);
}

void QuantumOutput::meshFinished()
{
  qDebug() << "The mesh has finished, mesh1 has" << m_mesh1->numVertices()
           << "vertices, and mesh 2 has" << m_mesh2->numVertices() << ".";
  m_molecule->emitChanged(QtGui::Molecule::Added);
}

}
}
