/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Adapted from Avogadro 1.0 by Geoffrey Hutchison
// Contributed to Avogadro 2.0 by Geoffrey Hutchison

#include "colorbutton.h"

#include <QColorDialog>
#include <QPainter>

namespace Avogadro {
namespace QtGui {

ColorButton::ColorButton(QWidget* parent)
  : QAbstractButton(parent), m_color(Qt::white), m_title("")
{
  setMinimumSize(35, 20);

  connect(this, SIGNAL(clicked()), this, SLOT(changeColor()));
}

ColorButton::ColorButton(const QColor& initial, QWidget* parent)
  : QAbstractButton(parent), m_color(initial)
{
  setMinimumSize(35, 20);

  connect(this, SIGNAL(clicked()), this, SLOT(changeColor()));
}

void ColorButton::changeColor()
{
  // This could be an ifdef for KColorDialog if KDE is present
  if (m_title == "")
    m_color = QColorDialog::getColor(m_color, this);
  else
    m_color = QColorDialog::getColor(m_color, this, m_title);
  update();

  emit colorChanged(m_color);
}

void ColorButton::setColor(const QColor& color)
{
  m_color = color;
  update();

  emit colorChanged(m_color);
}

void ColorButton::setDialogTitle(const QString title)
{
  m_title = title;
}

QColor ColorButton::color() const
{
  return m_color;
}

void ColorButton::paintEvent(QPaintEvent*)
{
  // TODO: If we go to RGBA colors, we should really show two pieces
  // e.g.  -----------
  //       |        /|
  //       | non   / |
  //       | alpha/  |
  //       |     /   |
  //       |    /alpha
  //       |   /     |
  //       -----------

  QPainter painter(this);

  // outer border
  painter.drawRect(0, 0, width(), height());
  // inner color
  painter.setBrush(m_color);
  painter.drawRect(4, 4, width() - 8, height() - 8);
}

bool ColorButton::event(QEvent* e)
{
  return QAbstractButton::event(e);
}

} // namespace QtGui
} // namespace Avogadro