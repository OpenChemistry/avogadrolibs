/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2017 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VRML_H
#define AVOGADRO_QTPLUGINS_VRML_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The VRML class performs VRML operations
 */
class VRML : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit VRML(QObject* p = nullptr);
  ~VRML() override;

  QString name() const override { return tr("VRML"); }

  QString description() const override
  {
    return tr("Render the scene using VRML.");
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
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VRML_H
