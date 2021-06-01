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

#ifndef AVOGADRO_QTGUI_UTILITIES_H
#define AVOGADRO_QTGUI_UTILITIES_H

#include "avogadroqtguiexport.h"

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtGui {
namespace Utilities {

AVOGADROQTGUI_EXPORT QString libraryDirectory();
AVOGADROQTGUI_EXPORT QString dataDirectory();

} // namespace Utilities
} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_UTILITIES_H
