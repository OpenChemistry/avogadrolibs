/******************************************************************************

   This source file is part of the Avogadro project.

   Copyright 2020 Kitware, Inc.

   This source code is released under the New BSD License, (the "License").

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SVG_H
#define AVOGADRO_QTPLUGINS_SVG_H

#include <Eigen/Geometry>
#include <QPainter>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {
class SVG : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit SVG(QObject* parent_ = 0);
  ~SVG() override;
  QString name() const override { return tr("SVG"); }

  QString description() const override
  {
    return tr("Render the scene in a SVG file.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setScene(Rendering::Scene* scene) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void render();

private:
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
  int m_width, m_height;
  Eigen::Vector3f m_min, m_max;

  static const float RADIUS;
  static const float PEN_WIDTH_MOL, PEN_WIDTH_BOND, OFF_SET_PARALEL;

  bool defaultChecks();
  Eigen::Vector3f possToImage(const Vector3f& mol, float r);
  void paintSVG(QPainter& painter);
};
} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SVG_H
