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

#ifndef AVOGADRO_QTGUI_SCENEPLUGIN_H
#define AVOGADRO_QTGUI_SCENEPLUGIN_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtplugins/pluginfactory.h>

#include <QtCore/QObject>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Rendering {
class GroupNode;
}

namespace QtGui {

class RWMolecule;

/**
 * @class ScenePluginFactory sceneplugin.h <avogadro/qtgui/sceneplugin.h>
 * @brief The base class for scene plugin factories in Avogadro.
 * @author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ScenePlugin : public QObject
{
  Q_OBJECT

public:
  explicit ScenePlugin(QObject* parent = nullptr);
  ~ScenePlugin() override;

  /**
   * Process the supplied atom, and add the necessary primitives to the scene.
   */
  virtual void process(const Core::Molecule& molecule,
                       Rendering::GroupNode& node) = 0;

  virtual void processEditable(const RWMolecule& molecule,
                               Rendering::GroupNode& node);

  /**
   * The name of the scene plugin, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /**
   * A description of the scene plugin, may be displayed in the user interface.
   */
  virtual QString description() const = 0;

  /**
   * Returns true if the scene plugin has been enabled and is active.
   */
  virtual bool isEnabled() const = 0;

  /**
   * Set the enabled state of the plugin (default should be false).
   */
  virtual void setEnabled(bool enable) = 0;

  virtual QWidget* setupWidget();

signals:
  void drawablesChanged();
};

/**
 * @class ScenePluginFactory sceneplugin.h <avogadro/qtgui/sceneplugin.h>
 * @brief The base class for scene plugin factories in Avogadro.
 * @author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ScenePluginFactory
  : public Avogadro::QtPlugins::PluginFactory<ScenePlugin>
{
public:
  ~ScenePluginFactory() override {}
};

} // End QtGui namespace
} // End Avogadro namespace

Q_DECLARE_INTERFACE(Avogadro::QtGui::ScenePluginFactory,
                    "org.openchemistry.avogadro.ScenePluginFactory")

#endif // AVOGADRO_QTGUI_SCENEPLUGIN_H
