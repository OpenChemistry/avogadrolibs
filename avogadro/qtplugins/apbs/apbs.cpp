/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "apbs.h"
#include "apbsdialog.h"
#include "opendxreader.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

using Core::Mesh;

Apbs::Apbs(QObject* parent_)
  : QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_progressDialog(nullptr), m_dialog(nullptr)
{
  QAction* action = new QAction(this);
  action->setText(tr("Run APBS..."));
  connect(action, SIGNAL(triggered()), this, SLOT(onRunApbs()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Open Output File..."));
  connect(action, SIGNAL(triggered()), this, SLOT(onOpenOutputFile()));
  m_actions.append(action);
}

Apbs::~Apbs()
{
  delete m_dialog;
  delete m_progressDialog;
}

QStringList Apbs::menuPath(QAction*) const
{
  return QStringList() << tr("&Input") << tr("&APBS");
}

void Apbs::setMolecule(QtGui::Molecule* mol)
{
  if (mol != m_molecule)
    m_molecule = mol;
}

void Apbs::onOpenOutputFile()
{
  QString fileName = QFileDialog::getOpenFileName(
    qobject_cast<QWidget*>(parent()), tr("Open Output File"), QString(),
    tr("OpenDX File (*.dx)"));
  if (fileName.isEmpty())
    return;

  if (!m_molecule)
    return;

  loadOpenDxFile(fileName, *m_molecule);
}

void Apbs::meshGeneratorFinished()
{
  QtGui::MeshGenerator* generator =
    qobject_cast<QtGui::MeshGenerator*>(sender());
  if (!generator) {
    return;
  }

  // delete the generator
  generator->deleteLater();

  m_progressDialog->setValue(m_progressDialog->maximum());
  m_progressDialog->hide();
}

void Apbs::onMeshGeneratorProgress(int value)
{
  m_progressDialog->setValue(value);
  qApp->processEvents();
}

void Apbs::onRunApbs()
{
  if (!m_dialog)
    m_dialog = new ApbsDialog(qobject_cast<QWidget*>(parent()));

  m_dialog->setMolecule(m_molecule);
  int code = m_dialog->exec();
  m_dialog->hide();
  if (code == QDialog::Accepted) {
    m_pqrFileName = m_dialog->pqrFileName();
    m_cubeFileName = m_dialog->cubeFileName();

    emit moleculeReady(1);
  }
}

bool Apbs::readMolecule(QtGui::Molecule& molecule)
{
  bool ok = Io::FileFormatManager::instance().readFile(
    molecule, m_pqrFileName.toStdString());
  if (!ok) {
    QMessageBox::critical(
      qobject_cast<QWidget*>(parent()), tr("IO Error"),
      tr("Error reading structure file (%1).").arg(m_pqrFileName));
    return false;
  }

  if (!m_cubeFileName.isEmpty()) {
    // load the cube file and generate meshes
    ok = loadOpenDxFile(m_cubeFileName, molecule);
    if (!ok)
      return false;
  }

  return true;
}

bool Apbs::loadOpenDxFile(const QString& fileName, QtGui::Molecule& molecule)
{
  OpenDxReader reader;
  bool ok = reader.readFile(fileName);
  if (!ok) {
    QMessageBox::critical(
      qobject_cast<QWidget*>(parent()), tr("OpenDX Error"),
      tr("Error reading OpenDX file: %1").arg(reader.errorString()));
  } else {
    const Core::Cube* cube = reader.cube();

    if (!cube) {
      QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                            tr("OpenDX Error"),
                            tr("Error reading OpenDX file: No cube found"));
    } else {
      if (!m_progressDialog)
        m_progressDialog =
          new QProgressDialog(qobject_cast<QWidget*>(parent()));

      // generate positive mesh
      m_progressDialog->setLabelText("Generating Positive Potential Mesh");
      m_progressDialog->setRange(0, 100);
      m_progressDialog->setValue(1);
      qApp->processEvents();

      Mesh* mesh = molecule.addMesh();
      QtGui::MeshGenerator* meshGenerator =
        new QtGui::MeshGenerator(cube, mesh, 0.1f);
      connect(meshGenerator, SIGNAL(finished()), this,
              SLOT(meshGeneratorFinished()));
      connect(meshGenerator, SIGNAL(progressValueChanged(int)), this,
              SLOT(onMeshGeneratorProgress(int)));
      meshGenerator->run();

      // generate negative mesh
      m_progressDialog->setLabelText("Generating Negative Potential Mesh");
      m_progressDialog->setRange(0, 100);
      m_progressDialog->setValue(1);
      qApp->processEvents();

      mesh = molecule.addMesh();
      meshGenerator = new QtGui::MeshGenerator(cube, mesh, -0.1f);
      connect(meshGenerator, SIGNAL(finished()), this,
              SLOT(meshGeneratorFinished()));
      connect(meshGenerator, SIGNAL(progressValueChanged(int)), this,
              SLOT(onMeshGeneratorProgress(int)));
      meshGenerator->run();

      m_progressDialog->setValue(100);
      m_progressDialog->hide();
    }
  }

  return true;
}
}
}
