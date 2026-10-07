/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_UTILITIES_H
#define AVOGADRO_QTGUI_UTILITIES_H

#include "avogadroqtguiexport.h"

#include <QtCore/QString>

namespace Avogadro {
namespace QtGui {
namespace Utilities {

AVOGADROQTGUI_EXPORT QString libraryDirectory();
AVOGADROQTGUI_EXPORT QString dataDirectory();
//! \return the Open Babel data directory shipped alongside the application
//! (suitable for BABEL_DATADIR), or an empty string if it cannot be found
AVOGADROQTGUI_EXPORT QString openBabelDataDirectory();
//! \return the Open Babel plugin directory shipped alongside the application
//! (suitable for BABEL_LIBDIR), or an empty string if it cannot be found
AVOGADROQTGUI_EXPORT QString openBabelLibraryDirectory();
//! \return a fully-qualified path for a program or an empty string if not found
AVOGADROQTGUI_EXPORT QString findExecutablePath(QString program);
//! \return a list of all fully-qualified paths for programs that are found
AVOGADROQTGUI_EXPORT QStringList findExecutablePaths(QStringList programs);

//! \return true if the application runs without a user to answer questions
//! (a scripted or RPC session, "--skip-dialogs"). Plugins must not open modal
//! dialogs, or anything else that waits for an answer, while this is true.
//! It is false if there is no QCoreApplication.
//! \sa setDialogsSkipped()
AVOGADROQTGUI_EXPORT bool dialogsSkipped();
//! Record whether the application runs without a user. The application sets
//! this once at startup for scripted and RPC sessions. It is kept in the
//! application property "avogadro.skipDialogs", which is also what
//! avogadroapp sets directly. Does nothing without a QCoreApplication.
//! \sa dialogsSkipped()
AVOGADROQTGUI_EXPORT void setDialogsSkipped(bool skipped);

} // namespace Utilities
} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_UTILITIES_H
