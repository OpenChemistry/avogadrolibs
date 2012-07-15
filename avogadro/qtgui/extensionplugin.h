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

#ifndef AVOGADRO_QTGUI_EXTENSIONPLUGIN_H
#define AVOGADRO_QTGUI_EXTENSIONPLUGIN_H

#include "avogadroqtguiexport.h"

#include <QtCore/QObject>

class QAction;

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Rendering {
class Scene;
}

namespace QtGui {

/*!
 * \class ExtensionPlugin extensionplugin.h <avogadro/qtgui/extensionplugin.h>
 * \brief The base class for scene plugin factories in Avogadro.
 * \author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ExtensionPlugin : public QObject
{
  Q_OBJECT

public:
  explicit ExtensionPlugin(QObject *parent = 0);
  ~ExtensionPlugin();

  /*!
   * The name of the scene plugin, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /*!
   * A description of the scene plugin, may be displayed in the user interface.
   */
  virtual QString description() const = 0;

  /*!
   * \return The QActions for this extension (should be at least one).
   */
  virtual QList<QAction *> actions() const = 0;

  /*!
   * \return The menu path of the supplied action. This can be empty if the
   * action was not recognized, or contain two or more strings (top level, plus
   * name, e.g. File, &Open).
   */
  virtual QStringList menuPath(QAction *action = 0) const = 0;
};

/*!
 * \class ExtensionPluginFactory extensionplugin.h <avogadro/qtgui/extensionplugin.h>
 * \brief The base class for extension plugin factories in Avogadro.
 * \author Marcus D. Hanwell
 */
class AVOGADROQTGUI_EXPORT ExtensionPluginFactory
{
public:
  virtual ~ExtensionPluginFactory();

  virtual ExtensionPlugin * createExtensionInstance() = 0;
  virtual QString identifier() const = 0;
};

#define EXTENSION_PLUGIN_FACTORY(className, id) \
public: \
  Avogadro::QtGui::ExtensionPlugin * createExtensionInstance() \
  { \
    return new className; \
  } \
  QString identifier() const { return id; }

} // End QtGui namespace
} // End Avogadro namespace

Q_DECLARE_INTERFACE(Avogadro::QtGui::ExtensionPluginFactory,
                    "net.openchemistry.avogadro.extensionpluginfactory/2.0")

#endif // AVOGADRO_QTGUI_EXTENSIONPLUGIN_H
