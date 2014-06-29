/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_POVRAY_H
#define AVOGADRO_QTPLUGINS_POVRAY_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The POVRay class performs POVRay operations on demand.
 */
class POVRay : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit POVRay(QObject *p = 0);
  ~POVRay() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("POVRay"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Render the scene using POV-Ray.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *action) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE;
  void setScene(Rendering::Scene *scene) AVO_OVERRIDE;
  void setCamera(Rendering::Camera *camera) AVO_OVERRIDE;

private slots:
  void render();

private:
  QtGui::Molecule *m_molecule;
  Rendering::Scene *m_scene;
  Rendering::Camera *m_camera;

  QAction *m_action;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_POVRAY_H
