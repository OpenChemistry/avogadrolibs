/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltf.h"

#include <avogadro/qtgui/iodevicestreambuf.h>
#include <avogadro/qtgui/commandregistry.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/utilities.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/gltfvisitor.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QSaveFile>
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
  registerExportCommand();
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

GLTF::CylinderColoring GLTF::rememberedColoring()
{
  QSettings settings;
  return settings.value("gltf/cylinderColoring", "split").toString() ==
             "gradient"
           ? CylinderColoring::Gradient
           : CylinderColoring::Split;
}

bool GLTF::exportTo(const QString& fileName, CylinderColoring coloring,
                    QString* error)
{
  auto fail = [error](const QString& message) {
    if (error != nullptr)
      *error = message;
    return false;
  };
  if (!m_scene || !m_camera)
    return fail(tr("There is no scene to export."));
  if (fileName.isEmpty())
    return fail(tr("No file name was given."));

  Rendering::GltfVisitor visitor;
  visitor.setCamera(*m_camera);
  visitor.setCylinderColoring(
    coloring == CylinderColoring::Split
      ? Rendering::TessellatingVisitor::CylinderColoring::Split
      : Rendering::TessellatingVisitor::CylinderColoring::Gradient);
  visitor.begin();
  m_scene->rootNode().accept(visitor);

  // Centre on the atoms (not on the exported geometry, so that e.g.
  // ball-and-stick and surface exports coincide), in Molecular Nodes units.
  visitor.centerOn(m_molecule);
  visitor.setScale(Rendering::GltfVisitor::MolecularNodesScale);

  // Written to a temporary file that replaces the destination only on
  // commit(), so a failed export leaves an existing file as it was. Binary
  // mode: the file is binary glTF.
  QSaveFile file(fileName);
  if (!file.open(QIODevice::WriteOnly))
    return fail(
      tr("Cannot open %1 for writing: %2").arg(fileName, file.errorString()));

  QtGui::IODeviceStreamBuf buffer(file);
  std::ostream stream(&buffer);
  const bool ok = visitor.write(stream);
  if (!ok || !stream || file.error() != QFileDevice::NoError) {
    const QString reason = !visitor.error().empty()
                             ? QString::fromStdString(visitor.error())
                             : file.errorString();
    file.cancelWriting();
    return fail(tr("Writing %1 failed: %2").arg(fileName, reason));
  }
  if (!file.commit())
    return fail(tr("Writing %1 failed: %2").arg(fileName, file.errorString()));
  return true;
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
  // the default, and is used as is when nobody can answer a question.
  CylinderColoring coloring = rememberedColoring();
  if (!QtGui::Utilities::dialogsSkipped()) {
    QSettings settings;
    const QString split = tr("Split at midpoint");
    const QString gradient = tr("Gradient");
    bool accepted = false;
    const QString choice = QInputDialog::getItem(
      widget, tr("glTF Export"), tr("Bond colors:"), { split, gradient },
      coloring == CylinderColoring::Split ? 0 : 1, false, &accepted);
    if (!accepted)
      return;
    coloring =
      (choice == split) ? CylinderColoring::Split : CylinderColoring::Gradient;
    settings.setValue("gltf/cylinderColoring",
                      coloring == CylinderColoring::Split ? "split"
                                                          : "gradient");
  }

  QString error;
  if (!exportTo(filename, coloring, &error))
    QMessageBox::warning(widget, tr("glTF Export"), error);
}

void GLTF::registerExportCommand()
{
  using QtGui::CommandArgumentSpec;

  QtGui::CommandSpec spec;
  spec.name = "exportGltf";
  spec.description =
    tr("Export the current scene as a glTF binary (.glb) file: "
       "{\"fileName\": path, \"bondColors\": \"split\"|\"gradient\"}. "
       "\"bondColors\" says how bonds between different elements are "
       "coloured; it defaults to the choice last made in the export dialog "
       "(\"split\" at first). An existing file is only replaced if the "
       "export succeeds. Returns {\"fileName\": path}.");
  spec.arguments = { CommandArgumentSpec::string(
                       "fileName", tr("Path of the .glb file to write."))
                       .withRequired(),
                     CommandArgumentSpec::enumeration(
                       "bondColors",
                       tr("How to colour bonds between different elements."),
                       { "split", "gradient" }) };
  // The scene is exported, not the molecule.
  spec.needsMolecule = false;
  spec.handler = [this](const QtGui::CommandArguments& args) {
    const QString fileName = args.string("fileName");
    CylinderColoring coloring = rememberedColoring();
    if (args.has("bondColors"))
      coloring = args.string("bondColors") == "gradient"
                   ? CylinderColoring::Gradient
                   : CylinderColoring::Split;
    QString error;
    if (!exportTo(fileName, coloring, &error)) {
      emit commandFailed(error);
      return;
    }
    QVariantMap result;
    result[QStringLiteral("fileName")] = fileName;
    emit commandFinished(tr("Exported %1.").arg(fileName), result);
  };
  commandRegistry().add(std::move(spec));
}

bool GLTF::handleCommand(const QString& command, const QVariantMap& options)
{
  return commandRegistry().handle(command, options, m_molecule);
}

} // namespace Avogadro::QtPlugins
