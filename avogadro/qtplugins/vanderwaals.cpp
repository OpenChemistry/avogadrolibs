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

#include "vanderwaals.h"

#include <QtCore/QtPlugin>

namespace Avogadro {
namespace QtPlugins {

VanDerWaals::VanDerWaals(QObject *p) : ScenePlugin(p)
{
}

VanDerWaals::~VanDerWaals()
{
}

}
}

Q_EXPORT_PLUGIN2(vanderwaals, Avogadro::QtPlugins::VanDerWaalsFactory)
