/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltf.h"

#include <avogadro/qtgui/iodevicestreambuf.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/gltfvisitor.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>

#include <ostream>
#include <string>

namespace Avogadro::QtPlugins {

GLTF::GLTF(QObject* p)
  : Avogadro::QtGui::ExtensionPlugin(p), m_molecule(nullptr), m_scene(nullptr),
    m_camera(nullptr), m_action(new QAction(tr("glTF Scene (.glb)…"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(exportScene()));
}

GLTF::~GLTF() {}

QList<QAction*> GLTF::actions() const
{
  QList<QAction*> result;
  return result << m_action;
}

QStringList GLTF::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Export");
}

void GLTF::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void GLTF::setScene(Rendering::Scene* scene)
{
  m_scene = scene;
}

void GLTF::setCamera(Rendering::Camera* camera)
{
  m_camera = camera;
}

void GLTF::exportScene()
{
  if (!m_scene || !m_camera)
    return;

  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("glTF Binary (*.glb)"));
  if (filename.isEmpty())
    return;

  QWidget* widget = qobject_cast<QWidget*>(parent());

  // How to colour bonds between different elements: the remembered choice is
  // the default.
  QSettings settings;
  const QString split = tr("Split at midpoint");
  const QString gradient = tr("Gradient");
  const bool wasSplit =
    settings.value("gltf/cylinderColoring", "split").toString() != "gradient";
  bool accepted = false;
  const QString choice = QInputDialog::getItem(
    widget, tr("glTF Export"), tr("Bond colors:"), { split, gradient },
    wasSplit ? 0 : 1, false, &accepted);
  if (!accepted)
    return;
  const bool useSplit = (choice == split);
  settings.setValue("gltf/cylinderColoring", useSplit ? "split" : "gradient");

  QFile file(filename);
  // Binary mode: the file is binary glTF.
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    QMessageBox::warning(
      widget, tr("glTF Export"),
      tr("Cannot open %1 for writing: %2").arg(filename, file.errorString()));
    return;
  }

  Rendering::GltfVisitor visitor;
  visitor.setCamera(*m_camera);
  visitor.setCylinderColoring(
    useSplit ? Rendering::TessellatingVisitor::CylinderColoring::Split
             : Rendering::TessellatingVisitor::CylinderColoring::Gradient);
  visitor.begin();
  m_scene->rootNode().accept(visitor);

  // Centre on the atoms (not on the exported geometry, so that e.g.
  // ball-and-stick and surface exports coincide), in Molecular Nodes units.
  visitor.centerOn(m_molecule);
  visitor.setScale(Rendering::GltfVisitor::MolecularNodesScale);

  QtGui::IODeviceStreamBuf buffer(file);
  std::ostream stream(&buffer);
  bool ok = visitor.write(stream);
  file.close();
  if (!ok || file.error() != QFileDevice::NoError) {
    const QString reason = visitor.error().empty()
                             ? file.errorString()
                             : QString::fromStdString(visitor.error());
    QMessageBox::warning(widget, tr("glTF Export"),
                         tr("Writing %1 failed: %2").arg(filename, reason));
    file.remove();
  }
}

} // namespace Avogadro::QtPlugins
