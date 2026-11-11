/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "colortheme.h"

#include <QtCore/QString>
#include <QtCore/QtGlobal>
#include <QtGui/QColor>
#include <QtGui/QGuiApplication>
#include <QtGui/QPalette>
#include <QtGui/QStyleHints>

#include <map>
#include <string>

namespace Avogadro::QtGui {

ColorTheme colorTheme(const QPalette& palette)
{
  // is the text lighter than the window color?
  return palette.color(QPalette::WindowText).lightness() >
             palette.color(QPalette::Window).lightness()
           ? ColorTheme::Dark
           : ColorTheme::Light;
}

ColorTheme colorTheme()
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
  if (qGuiApp != nullptr) {
    const Qt::ColorScheme scheme = qGuiApp->styleHints()->colorScheme();
    if (scheme == Qt::ColorScheme::Dark)
      return ColorTheme::Dark;
    if (scheme == Qt::ColorScheme::Light)
      return ColorTheme::Light;
  }
#endif
  if (qGuiApp != nullptr)
    return colorTheme(QGuiApplication::palette());
  return colorTheme(QPalette());
}

// Dark-mode palette: brighter / higher-value colors for contrast on dark
// backgrounds.
static const std::map<std::string, QColor> darkModeColors = {
  { "red", QColorConstants::Svg::crimson },         // #DC143C
  { "orange", QColorConstants::Svg::coral },        // #FF7F50
  { "yellow", QColorConstants::Svg::goldenrod },    // #DAA520
  { "green", QColorConstants::Svg::springgreen },   // #00FF7F
  { "cyan", QColorConstants::Svg::cyan },           // #00FFFF
  { "blue", QColorConstants::Svg::dodgerblue },     // #1E90FF
  { "purple", QColorConstants::Svg::mediumpurple }, // #9370DB
  { "pink", QColorConstants::Svg::orchid },         // #DA70D6
  { "white", QColorConstants::Svg::whitesmoke },    // #F5F5F5
  { "gray", QColorConstants::Svg::darkgray },       // #A9A9A9
};

// Light-mode palette: deeper / more saturated colors for contrast on light
// backgrounds.
static const std::map<std::string, QColor> lightModeColors = {
  { "red", QColorConstants::Svg::maroon },        // #800000
  { "orange", QColorConstants::Svg::coral },      // #FF7F50
  { "yellow", QColorConstants::Svg::goldenrod },  // #DAA520
  { "green", QColorConstants::Svg::limegreen },   // #32CD32
  { "cyan", QColorConstants::Svg::deepskyblue },  // #00BFFF
  { "blue", QColorConstants::Svg::blue },         // #0000FF
  { "purple", QColorConstants::Svg::blueviolet }, // #8A2BE2
  { "pink", QColorConstants::Svg::fuchsia },      // #FF00FF
  { "white", QColorConstants::Svg::black },       // #000000
  { "gray", QColorConstants::Svg::dimgray },      // #696969
};

QColor highlightColor(const QString& name, ColorTheme theme)
{
  const auto& table =
    theme == ColorTheme::Dark ? darkModeColors : lightModeColors;
  auto it = table.find(name.toStdString());
  if (it == table.end())
    it = table.find("white"); // default foreground
  if (it == table.end())
    return QColor();
  return it->second;
}

} // namespace Avogadro::QtGui
