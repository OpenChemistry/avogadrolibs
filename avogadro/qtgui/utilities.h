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

#include <QtGui/QIcon>

namespace Avogadro {
namespace QtGui {

/**
 * Helper function for loading a freedesktop QIcon in a cross-platform way.
 * @param name The freedesktop name of the icon. See
 * http://standards.freedesktop.org/icon-naming-spec/icon-naming-spec-latest.html
 * @note The icons in avogadrolibs/qtgui/icons/fallback/ are used if the
 * current platform doesn't support icon themes.
 */
AVOGADROQTGUI_EXPORT QIcon standardIcon(const QString &name);

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_UTILITIES_H
