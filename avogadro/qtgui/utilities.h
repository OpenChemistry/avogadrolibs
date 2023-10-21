/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_UTILITIES_H
#define AVOGADRO_QTGUI_UTILITIES_H

#include <qstring.h>
#include <QtCore/QString>

#include "avogadroqtguiexport.h"

namespace Avogadro {
namespace QtGui {
namespace Utilities {

AVOGADROQTGUI_EXPORT QString libraryDirectory();
AVOGADROQTGUI_EXPORT QString dataDirectory();
//! \return a fully-qualified path for a program or an empty string if not found
AVOGADROQTGUI_EXPORT QString findExecutablePath(QString program);

} // namespace Utilities
} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_UTILITIES_H
