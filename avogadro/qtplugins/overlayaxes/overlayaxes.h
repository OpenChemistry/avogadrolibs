/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OVERLAYAXES_H
#define AVOGADRO_QTPLUGINS_OVERLAYAXES_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/rendering/groupnode.h>

#include <map>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render reference axes in the corner of the display.
 */
class OverlayAxes : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit OverlayAxes(QObject* parent = nullptr);
  ~OverlayAxes() override;

  QString name() const override { return tr("Reference Axes Overlay"); }
  QString description() const override
  {
    return tr("Render reference axes in the corner of the display.");
  }

  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* molecule) override;
  void setScene(Rendering::Scene* scene) override;
  void setActiveWidget(QWidget* widget) override;

private slots:
  void procesAxis();

private:
  void process(const Core::Molecule& molecule, Rendering::GroupNode& node);

  bool m_enabled;

  class RenderImpl;
  RenderImpl* const m_render;
  std::map<QWidget*, Rendering::GroupNode*> m_widgetToNode;
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  QWidget* m_glWidget;
  QAction* m_axesAction;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OVERLAYAXES_H
