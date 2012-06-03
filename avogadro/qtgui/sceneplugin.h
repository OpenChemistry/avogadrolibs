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

#include <QtCore/QObject>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Rendering {
class Scene;
}

namespace QtGui {

/*!
 * \class ScenePluginFactory sceneplugin.h <avogadro/qtgui/sceneplugin.h>
 * \brief The base class for scene plugin factories in Avogadro.
 * \author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ScenePlugin : public QObject
{
  Q_OBJECT

public:
  explicit ScenePlugin(QObject *parent = 0);
  ~ScenePlugin();

  /*!
   * Process the supplied atom, and add the necessary primitives to the scene.
   */
  virtual void process(const Core::Molecule &molecule, Rendering::Scene &scene) = 0;

  /*!
   * The name of the scene plugin, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /*!
   * A description of the scene plugin, may be displayed in the user interface.
   */
  virtual QString description() const = 0;
};

/*!
 * \class ScenePluginFactory sceneplugin.h <avogadro/qtgui/sceneplugin.h>
 * \brief The base class for scene plugin factories in Avogadro.
 * \author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ScenePluginFactory
{
public:
  virtual ~ScenePluginFactory();

  virtual ScenePlugin * createSceneInstance() = 0;
};

} // End QtGui namespace
} // End Avogadro namespace

Q_DECLARE_INTERFACE(Avogadro::QtGui::ScenePluginFactory,
                    "net.openchemistry.avogadro.scenepluginfactory/2.0")

#endif // AVOGADRO_QTGUI_SCENEPLUGIN_H
