/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "ply.h"

#include <avogadro/qtgui/iodevicestreambuf.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/plyvisitor.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QFile>
#include <QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

#include <ostream>

namespace Avogadro::QtPlugins {

PLY::PLY(QObject* p)
  : Avogadro::QtGui::ExtensionPlugin(p), m_molecule(nullptr), m_scene(nullptr),
    m_camera(nullptr), m_action(new QAction(tr("PLY Render…"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(render()));
}

PLY::~PLY() {}

QList<QAction*> PLY::actions() const
{
  QList<QAction*> result;
  return result << m_action;
}

QStringList PLY::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Export");
}

void PLY::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void PLY::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
}

void PLY::setCamera(Rendering::Camera* camera)
{
  m_camera = camera;
}

void PLY::render()
{
  if (!m_scene || !m_camera)
    return;

  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("PLY (*.ply)"));
  if (filename.isEmpty())
    return;

  QWidget* widget = qobject_cast<QWidget*>(parent());
  QFile file(filename);
  // Binary mode: the file is binary PLY.
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    QMessageBox::warning(
      widget, tr("PLY Export"),
      tr("Cannot open %1 for writing: %2").arg(filename, file.errorString()));
    return;
  }

  Rendering::PLYVisitor visitor(*m_camera);
  visitor.begin();
  m_scene->rootNode().accept(visitor);

  // Centre on the atoms (not on the exported geometry, so that e.g.
  // ball-and-stick and surface exports coincide), in Molecular Nodes units.
  visitor.centerOn(m_molecule);
  visitor.setScale(Rendering::PLYVisitor::MolecularNodesScale);

  QtGui::IODeviceStreamBuf buffer(file);
  std::ostream stream(&buffer);
  bool ok = visitor.write(stream);
  file.close();
  if (!ok || file.error() != QFileDevice::NoError) {
    QMessageBox::warning(
      widget, tr("PLY Export"),
      tr("Writing %1 failed: %2").arg(filename, file.errorString()));
    file.remove();
  }
}

} // namespace Avogadro::QtPlugins
