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
#include "opendxreader.h"

#include <avogadro/qtgui/cube.h>
#include <avogadro/qtgui/mesh.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <QAction>
#include <QFileDialog>
#include <QProgressDialog>
#include <QMessageBox>
#include <QApplication>

namespace Avogadro {
namespace QtPlugins {

Apbs::Apbs(QObject *parent_)
  : QtGui::ExtensionPlugin(parent_),
    m_molecule(0)
{
  QAction *action = new QAction(this);
  action->setText(tr("Open Output File"));
  connect(action, SIGNAL(triggered()), this, SLOT(onOpenOutputFile()));
  m_actions.append(action);

  m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent_));
  m_progressDialog->hide();
}

Apbs::~Apbs()
{
  delete m_progressDialog;
}

QStringList Apbs::menuPath(QAction *) const
{
  return QStringList() << tr("&Extensions") << tr("&APBS");
}

void Apbs::setMolecule(QtGui::Molecule *mol)
{
  if (mol != m_molecule)
    m_molecule = mol;
}

void Apbs::onOpenOutputFile()
{
  QString fileName =
    QFileDialog::getOpenFileName(qobject_cast<QWidget *>(parent()),
                                 tr("Open Output File"), QString(),
                                 tr("OpenDX File (*.dx)"));
  if (fileName.isEmpty())
    return;

  m_progressDialog->show();
  m_progressDialog->setMinimumDuration(0);
  m_progressDialog->setRange(0, 0);
  m_progressDialog->setLabelText(tr("Reading OpenDX File"));
  qApp->processEvents();

  OpenDxReader reader;
  bool ok = reader.readFile(fileName);
  if (!ok) {
    QMessageBox::critical(qobject_cast<QWidget *>(parent()),
                          tr("APBS Error"),
                          tr("Error: %1").arg(reader.errorString()));
    return;
  }

  const QtGui::Cube *cube = reader.cube();
  if (!cube) {
    QMessageBox::critical(qobject_cast<QWidget *>(parent()),
                          tr("APBS Error"),
                          tr("Error: No Cube Found"));
    return;
  }

  if (!m_molecule) {
    QMessageBox::critical(qobject_cast<QWidget *>(parent()),
                          tr("APBS Error"),
                          tr("Error: No Molecule Found"));
    return;
  }

  // generate positive potential mesh
  m_progressDialog->setLabelText("Generating Positive Potential Mesh");
  m_progressDialog->setRange(0, 100);
  m_progressDialog->setValue(1);
  qApp->processEvents();

  QtGui::Mesh *positivePotentialMesh = m_molecule->addMesh();
  QtGui::MeshGenerator *positiveMeshGenerator =
    new QtGui::MeshGenerator(cube, positivePotentialMesh, 0.1f);
  connect(positiveMeshGenerator, SIGNAL(finished()),
          this, SLOT(cubeGeneratorFinished()));
  connect(positiveMeshGenerator, SIGNAL(progressValueChanged(int)),
          this, SLOT(onMeshGeneratorProgress(int)));
  positiveMeshGenerator->run();

  m_progressDialog->setLabelText("Generating Negative Potential Mesh");
  m_progressDialog->setValue(1);
  qApp->processEvents();

  // generate negative potential mesh
  QtGui::Mesh *negativePotentialMesh = m_molecule->addMesh();
  QtGui::MeshGenerator *negativeMeshGenerator =
    new QtGui::MeshGenerator(cube, negativePotentialMesh, -0.1f);
  connect(negativeMeshGenerator, SIGNAL(finished()),
          this, SLOT(cubeGeneratorFinished()));
  connect(negativeMeshGenerator, SIGNAL(progressValueChanged(int)),
          this, SLOT(onMeshGeneratorProgress(int)));
  negativeMeshGenerator->run();

  m_progressDialog->setValue(100);
  m_progressDialog->hide();
}

void Apbs::cubeGeneratorFinished()
{
  QtGui::MeshGenerator *generator =
    qobject_cast<QtGui::MeshGenerator *>(sender());
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

}
}
