/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_RESETVIEW_H
#define AVOGADRO_QTPLUGINS_RESETVIEW_H

#include <avogadro/qtgui/extensionplugin.h>
#include <Eigen/Geometry>

namespace Avogadro {
namespace QtPlugins {

class ResetView : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ResetView(QObject* parent_ = 0);
  ~ResetView() override;

  QString name() const override { return tr("Reset view"); }
  QString description() const override
    { return tr("Manipulate the view camera."); }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;
public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void centerView();
  void alignToAxes();

private:
  QtGui::Molecule *m_molecule;
  Rendering::Camera *m_camera;
  QAction *m_centerAction;
  QAction *m_viewToAxesAction;

  bool defaultChecks();
  void animationCamera(Eigen::Affine3f* goal, bool animate = true);

};

} // namespace QtPlugins
} // namespace Avogadro

#endif
