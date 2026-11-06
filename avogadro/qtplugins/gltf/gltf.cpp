/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltf.h"

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/gltfvisitor.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QFile>
#include <QtGui/QClipboard>
#include <QtGui/QIcon>
#include <QtGui/QKeySequence>
#include <QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

#include <ostream>
#include <streambuf>
#include <string>
#include <vector>

namespace Avogadro::QtPlugins {

namespace {

// A std::ostream buffer that writes straight to a QIODevice, checking every
// write (a short write makes the stream fail).
class DeviceBuf : public std::streambuf
{
public:
  explicit DeviceBuf(QIODevice& device) : m_device(device) {}

protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override
  {
    std::streamsize done = 0;
    while (done < count) {
      qint64 written = m_device.write(data + done, count - done);
      if (written <= 0)
        break;
      done += written;
    }
    return done;
  }

  int_type overflow(int_type ch) override
  {
    if (traits_type::eq_int_type(ch, traits_type::eof()))
      return traits_type::not_eof(ch);
    char c = traits_type::to_char_type(ch);
    return xsputn(&c, 1) == 1 ? ch : traits_type::eof();
  }

private:
  QIODevice& m_device;
};

// Export defaults, chosen to match Molecular Nodes (Blender), whose
// world_scale is 0.1: 1 Angstrom = 0.1 Blender units. The scene is centred on
// the molecule's atoms so that several exports of one molecule line up.
constexpr float kExportScale = 0.1f;

} // namespace

GLTF::GLTF(QObject* p)
  : Avogadro::QtGui::ExtensionPlugin(p), m_molecule(nullptr), m_scene(nullptr),
    m_camera(nullptr), m_action(new QAction(tr("glTF Scene (.glb)…"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(render()));
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

void GLTF::render()
{
  if (!m_scene || !m_camera)
    return;

  QString filename = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Save File"), QDir::homePath(),
    tr("glTF Binary (*.glb)"));
  if (filename.isEmpty())
    return;

  QWidget* widget = qobject_cast<QWidget*>(parent());
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
  visitor.begin();
  m_scene->rootNode().accept(visitor);

  // Centre on the plain centroid of the atoms (not of the exported geometry,
  // so that e.g. ball-and-stick and surface exports coincide). Without atoms,
  // fall back to the centre of the exported geometry's bounding box.
  Vector3f center = Vector3f::Zero();
  const auto* positions = m_molecule ? &m_molecule->atomPositions3d() : nullptr;
  if (positions != nullptr && positions->size() > 0) {
    Vector3 sum = Vector3::Zero();
    for (const auto& position : *positions)
      sum += position;
    center = (sum / static_cast<double>(positions->size())).cast<float>();
  } else {
    Vector3f minimum, maximum;
    if (visitor.bounds(minimum, maximum))
      center = 0.5f * (minimum + maximum);
  }
  visitor.setOffset(center);
  visitor.setScale(kExportScale);

  DeviceBuf buffer(file);
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
