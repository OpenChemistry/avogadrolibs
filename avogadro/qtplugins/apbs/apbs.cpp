
#include "apbs.h"
#include "opendxreader.h"

#include <avogadro/qtgui/cube.h>
#include <avogadro/qtgui/mesh.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <QAction>
#include <QDebug>
#include <QFileDialog>
#include <QProgressDialog>
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

  m_progressDialog = new QProgressDialog;
  m_progressDialog->hide();
}

Apbs::~Apbs()
{
  delete m_progressDialog;
}

void Apbs::setMolecule(QtGui::Molecule *mol)
{
  if (mol != m_molecule)
    m_molecule = mol;
}

void Apbs::onOpenOutputFile()
{
  QString fileName =
    QFileDialog::getOpenFileName(0, tr("Open Output File"), QString(),
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
    qDebug() << "apbs error: " << reader.errorString();
    return;
  }

  const QtGui::Cube *positivePotentialCube = reader.positivePotentialCube();
  if (!positivePotentialCube) {
    qDebug() << "apbs error: no positive cube";
    return;
  }

  const QtGui::Cube *negativePotentialCube = reader.negativePotentialCube();
  if (!negativePotentialCube) {
    qDebug() << "apbs error: no negative cube";
    return;
  }

  if (!m_molecule) {
    qDebug() << "apbs error: no molecule";
    return;
  }

  // generate positive potential mesh
  m_progressDialog->setLabelText("Generating Positive Potential Mesh");
  m_progressDialog->setRange(0, 100);
  m_progressDialog->setValue(1);
  qApp->processEvents();

  QtGui::Mesh *positivePotentialMesh = m_molecule->addMesh();
  QtGui::MeshGenerator *positiveMeshGenerator =
    new QtGui::MeshGenerator(positivePotentialCube, positivePotentialMesh,
                             0.1f);
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
    new QtGui::MeshGenerator(negativePotentialCube, negativePotentialMesh,
                             -0.1f);
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
