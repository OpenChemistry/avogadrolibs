/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LABELS_H
#define AVOGADRO_QTPLUGINS_LABELS_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Display label for each atom (Element symbol as of now)
 */
class Labels : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Labels(QObject* parent = 0);
  ~Labels() override;

  void process(const Core::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Labels"); }

  QString description() const override
  {
    return tr("Display labels on ball and stick style.");
  }

  bool isEnabled() const override;

  void setEnabled(bool enable) override;

  QWidget* setupWidget() override;

private slots:
  void showHydrogens(bool show);

private:
  bool m_enabled;

  Rendering::GroupNode* m_group;

  QWidget* m_setupWidget;
  bool m_showHydrogens;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LABELS_H
