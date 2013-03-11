/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "quantumoutput.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/cube.h>
#include <avogadro/qtgui/mesh.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <avogadro/quantum/basisset.h>
#include <avogadro/quantumio/basissetloader.h>

#include <QtCore/QDebug>
#include <QtGui/QAction>
#include <QtGui/QFileDialog>
#include <QtGui/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

static const double BOHR_TO_ANGSTROM = 0.529177249;

QuantumOutput::QuantumOutput(QObject *p) :
  ExtensionPlugin(p),
  m_progressDialog(NULL),
  m_molecule(NULL),
  m_basis(NULL),
  m_cube(NULL),
  m_mesh1(NULL),
  m_mesh2(NULL),
  m_meshGenerator(NULL),
  m_meshGenerator2(NULL)
{
  QAction *action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Load QM Output"));
  connect(action, SIGNAL(triggered()), SLOT(loadMoleculeActivated()));
  m_actions.push_back(action);
  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Calculate HOMO"));
  connect(action, SIGNAL(triggered()), SLOT(homoActivated()));
  m_actions.push_back(action);
  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Calculate LUMO"));
  connect(action, SIGNAL(triggered()), SLOT(lumoActivated()));
  m_actions.push_back(action);
}

QuantumOutput::~QuantumOutput()
{
  delete m_basis;
  delete m_cube;
}

QList<QAction *> QuantumOutput::actions() const
{
  return m_actions;
}

QStringList QuantumOutput::menuPath(QAction *currentAction) const
{
  if (m_actions[0] == currentAction) {
    QStringList path;
    path << tr("&File");
    return path;
  }
  else if (m_actions[1] == currentAction || m_actions[2] == currentAction) {
    QStringList path;
    path << tr("&Quantum");
    return path;
  }
  return QStringList();
}

void QuantumOutput::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

bool QuantumOutput::readMolecule(QtGui::Molecule &mol)
{
  qDebug() << "Reading the molecule in the Quantum Output plugin!";
  Core::Molecule oqmol = m_basis->molecule();
  for (size_t i = 0; i < oqmol.atomCount(); ++i) {
    Core::Atom a = mol.addAtom(oqmol.atom(i).atomicNumber());
    a.setPosition3d(oqmol.atom(i).position3d() * BOHR_TO_ANGSTROM);
  }
  return true;
}

void QuantumOutput::loadMoleculeActivated()
{
  QString fileName = QFileDialog::getOpenFileName(qobject_cast<QWidget *>(parent()),
                                                  tr("Open QM file"),
                                                  "",
                                                  tr("QM Output Files (*.log *.gamout *.fchk)"));
  openFile(fileName);
}

void QuantumOutput::homoActivated()
{
  if (m_basis)
    calculateMolecularOrbital(m_basis->numElectrons() / 2);
}

void QuantumOutput::lumoActivated()
{
  if (m_basis)
    calculateMolecularOrbital(m_basis->numElectrons() / 2 + 1);
}

void QuantumOutput::calculateMolecularOrbital(int mo)
{
  if (m_basis) {
    qDebug() << "We have a valid basis set loaded, with" << m_basis->numMOs()
             << "molecular orbitals.";
    if (!m_progressDialog) {
      m_progressDialog = new QProgressDialog(qobject_cast<QWidget *>(parent()));
      m_progressDialog->setCancelButtonText(tr("Abort Calculation"));
      m_progressDialog->setWindowModality(Qt::NonModal);
    }
    if (!m_cube) {
      m_cube = new QtGui::Cube;
      m_cube->setLimits(m_molecule, 0.2, 5.0);
    }
    m_basis->calculateCubeMO(m_cube, mo);
    // Set up the progress dialog.
    m_progressDialog->setWindowTitle(
          tr("Calculating molecular orbital %L1").arg(mo));
    m_progressDialog->setRange(m_basis->watcher().progressMinimum(),
                               m_basis->watcher().progressMaximum());
    m_progressDialog->setValue(m_basis->watcher().progressValue());
    m_progressDialog->show();

    connect(&m_basis->watcher(), SIGNAL(progressValueChanged(int)),
            m_progressDialog, SLOT(setValue(int)));
    connect(&m_basis->watcher(), SIGNAL(progressRangeChanged(int,int)),
            m_progressDialog, SLOT(setRange(int,int)));
//    connect(&m_basis->watcher(), SIGNAL(canceled()), SLOT(calculateCanceled()));
    connect(&m_basis->watcher(), SIGNAL(finished()), SLOT(calculateFinished()));
  }
}

void QuantumOutput::calculateFinished()
{
  qDebug() << "The calculation finished!";
  if (!m_cube)
    return;

  if (!m_mesh1)
    m_mesh1 = m_molecule->addMesh();
  if (!m_meshGenerator)
    m_meshGenerator = new QtGui::MeshGenerator;
  m_meshGenerator->initialize(m_cube, m_mesh1, 0.02);
  connect(m_meshGenerator, SIGNAL(finished()), SLOT(meshFinished()));
  m_meshGenerator->start();

  if (!m_mesh2)
    m_mesh2 = m_molecule->addMesh();
  if (!m_meshGenerator2)
    m_meshGenerator2 = new QtGui::MeshGenerator;
  m_meshGenerator2->initialize(m_cube, m_mesh2, -0.02, true);
  connect(m_meshGenerator2, SIGNAL(finished()), SLOT(meshFinished()));
  m_meshGenerator2->start();

}

void QuantumOutput::meshFinished()
{
  qDebug() << "The mesh has finished, seeing" << m_mesh1->numVertices()
           << "vertices.";
}

void QuantumOutput::openFile(const QString &fileName)
{
  qDebug() << "Trying to open" << fileName;
  if (m_basis) {
    delete m_basis;
    m_basis = NULL;
  }

  m_basis = QuantumIO::BasisSetLoader::LoadBasisSet(fileName);
  if (m_basis) {
    qDebug() << "Number of MOs:" << m_basis->numMOs();
    m_actions[1]->setEnabled(true);
    m_actions[2]->setEnabled(true);
    emit moleculeReady(1);
  }
}

}
}
