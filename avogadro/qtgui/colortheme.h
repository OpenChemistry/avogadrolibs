/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_COLORTHEME_H
#define AVOGADRO_QTGUI_COLORTHEME_H

#include "avogadroqtguiexport.h"

class QColor;
class QPalette;
class QString;

namespace Avogadro::QtGui {

/** Whether the user interface uses a light or a dark color scheme. */
enum class ColorTheme
{
  Light,
  Dark
};

/**
 * @return The theme of the running application. Uses the Qt style hints
 * (Qt 6.5+) when they report a definite scheme, otherwise the application
 * palette.
 */
AVOGADROQTGUI_EXPORT ColorTheme colorTheme();

/**
 * @return Dark if the text color of @p palette is lighter than its window
 * color, Light otherwise.
 */
AVOGADROQTGUI_EXPORT ColorTheme colorTheme(const QPalette& palette);

/**
 * @return A syntax-highlighting color for @p name tuned for @p theme. Known
 * names are red, orange, yellow, green, cyan, blue, purple, pink, white and
 * gray. An unknown name returns the "white" entry (the default foreground).
 */
AVOGADROQTGUI_EXPORT QColor highlightColor(const QString& name,
                                           ColorTheme theme);

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_COLORTHEME_H
