/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "povray.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/povrayvisitor.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QTextStream>
#include <QtGui/QClipboard>
#include <QtGui/QIcon>
#include <QtGui/QKeySequence>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

#include <string>
#include <vector>

namespace Avogadro::QtPlugins {

POVRay::POVRay(QObject* p)
  : Avogadro::QtGui::ExtensionPlugin(p), m_molecule(nullptr), m_scene(nullptr),
    m_camera(nullptr), m_action(new QAction(tr("POV-Ray Render…"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(render()));
}

POVRay::~POVRay()
{
}

QList<QAction*> POVRay::actions() const
{
  QList<QAction*> result;
  return result << m_action;
}

QStringList POVRay::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Export");
}

void POVRay::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void POVRay::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
}

void POVRay::setCamera(Rendering::Camera* camera)
{
  m_camera = camera;
}

void POVRay::render()
{
  if (!m_scene || !m_camera)
    return;

  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("POV-Ray (*.pov);;Text file (*.txt)"));
  QFile file(filename);
  if (!file.open(QIODevice::WriteOnly))
    return;

  QTextStream fileStream(&file);
  Rendering::POVRayVisitor visitor(*m_camera);
  visitor.begin();
  m_scene->rootNode().accept(visitor);
  fileStream << visitor.end().c_str();

  file.close();
}

} // namespace Avogadro
