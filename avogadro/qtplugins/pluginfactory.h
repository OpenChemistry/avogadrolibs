/******************************************************************************

 This source file is part of the MoleQueue project.

 Copyright 2013 Kitware, Inc.

 This source code is released under the New BSD License, (the "License").

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

 ******************************************************************************/

#ifndef PLUGINFACTORY_H_
#define PLUGINFACTORY_H_

#include <QtCore/QString>
#include <QtCore/QObject>

namespace Avogadro {
namespace QtPlugins {

/**
 * @class PluginFactory pluginfactory.h <avogadro/qtplugins/pluginfactory.h>
 * @brief The base class for plugin factories in Avogadro.
 */
template<typename T>
class PluginFactory
{
public:
  virtual ~PluginFactory() {};

  virtual T * createInstance() = 0;
  virtual QString identifier() const = 0;
  virtual QString description() const = 0;
};

} /* namespace QtPlugins */
} /* namespace Avogadro */

#endif /* PLUGINFACTORY_H_ */
