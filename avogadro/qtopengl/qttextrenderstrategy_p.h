/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_QTTEXTRENDERSTRATEGY_P_H
#define AVOGADRO_QTOPENGL_QTTEXTRENDERSTRATEGY_P_H

#include "avogadroqtopenglexport.h"

#include <avogadro/rendering/textproperties.h>

#include <QtGui/QFont>

#include <cstddef>

namespace Avogadro::QtOpenGL::Detail {

/** Private: exported only so the unit tests can reach it. */

/** The scaled font for @p prop without consulting the font cache. */
AVOGADROQTOPENGL_EXPORT QFont
scaledFontUncached(const Rendering::TextProperties& prop);

/** The scaled font for @p prop, served from the bounded font cache. */
AVOGADROQTOPENGL_EXPORT QFont
scaledFontCached(const Rendering::TextProperties& prop);

AVOGADROQTOPENGL_EXPORT void clearFontCache();
AVOGADROQTOPENGL_EXPORT size_t fontCacheSize();
AVOGADROQTOPENGL_EXPORT size_t fontCacheLimit();

} // namespace Avogadro::QtOpenGL::Detail

#endif
