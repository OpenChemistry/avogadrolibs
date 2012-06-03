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
namespace QtGui {


class AVOGADROQTGUI_EXPORT ScenePlugin : public QObject
{
  Q_OBJECT

public:
  ScenePlugin(QObject *parent = 0);
  ~ScenePlugin();
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
