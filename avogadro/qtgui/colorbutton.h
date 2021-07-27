/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Adapted from Avogadro 1.0 by Geoffrey Hutchison
// Contributed to Avogadro 2.0 by Geoffrey Hutchison

#ifndef AVOGADRO_QTGUI_COLORBUTTON_H
#define AVOGADRO_QTGUI_COLORBUTTON_H

#include "avogadroqtguiexport.h"

#include <QAbstractButton>
#include <QColor>

namespace Avogadro {
namespace QtGui {

/**
 * @class ColorButton colorbutton.h <avogadro/colorbutton.h>
 * @author Geoffrey Hutchison
 * @brief A button to show the current color and bring up the QColorDialog.
 *
 * This class implements a QAbstractButton to display a colored rectangle.
 * When clicked by the user, it brings up a color picker to select a new
 * color.
 *
 * The widget has a default minimium size of 35x20 pixels.
 */

class AVOGADROQTGUI_EXPORT ColorButton : public QAbstractButton
{
  Q_OBJECT

public:
  ColorButton(QWidget* parent = 0);
  explicit ColorButton(const QColor& initial, QWidget* parent = 0);

  /**
   *  Redraw the widget (i.e., refresh the colored rectange)
   */
  void paintEvent(QPaintEvent*);

  /**
   * @param color the new color to be used
   */
  void setColor(const QColor& color);

  /**
   * @param custom title for color choice dialog
   */
  void setDialogTitle(const QString title = "");

  /**
   * @return the current color
   */
  QColor color() const;

Q_SIGNALS:
  /**
   *  emit any time the color is changed, either by a user or by setColor()
   */
  void colorChanged(const QColor &);

public Q_SLOTS:
  /**
   * Call for a change in the current color
   */
  void changeColor();

protected:
  /**
   * Generic event handler, currently defaults to calling parent class
   * (included for future compatibility)
   */
  bool event(QEvent* e);

  QColor m_color;  //!< The current color
  QString m_title; //!< The current dialog title
};

} // namespace QtGui
} // namespace Avogadro

#endif
