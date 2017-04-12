/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2007-2009 by Marcus D. Hanwell
  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "elementitem_p.h"
#include "elementtranslator.h"

#include <avogadro/core/elements.h>

#include <QtGui/QFont>
#include <QtGui/QFontMetrics>
#include <QtGui/QPainter>
#include <QtWidgets/QGraphicsSceneMouseEvent>
#include <QtWidgets/QStyleOption>

namespace Avogadro {
namespace QtGui {

using Core::Elements;

ElementItem::ElementItem(int elementNumber)
  : m_valid(false), m_color(Qt::white), m_width(26), m_height(26),
    m_element(elementNumber)
{
  // Want these items to be selectable
  setFlags(QGraphicsItem::ItemIsSelectable);

  m_symbol = Elements::symbol(static_cast<unsigned char>(m_element));
  if (!m_symbol.isEmpty())
    m_valid = true;
  const unsigned char* color =
    Elements::color(static_cast<unsigned char>(m_element));
  if (color) {
    m_color.setRgb(static_cast<int>(color[0]), static_cast<int>(color[1]),
                   static_cast<int>(color[2]));
  }
  // Set some custom data to make it easy to figure out which element we are
  setData(0, m_element);
}

ElementItem::~ElementItem()
{
}

QRectF ElementItem::boundingRect() const
{
  return QRectF(-m_width / 2, -m_height / 2, m_width, m_height);
}

QPainterPath ElementItem::shape() const
{
  QPainterPath path;
  path.addRect(-m_width / 2, -m_height / 2, m_width, m_height);
  return path;
}

void ElementItem::paint(QPainter* painter, const QStyleOptionGraphicsItem*,
                        QWidget*)
{
  if (!m_valid)
    return;

  // Fill the rectangle with the element colour
  QColor bgColor;
  QPen pen;
  if (isSelected()) {
    bgColor = QColor(m_color).lighter(150);
    pen.setColor(QColor(m_color).darker(150));
    pen.setWidth(4);
  } else {
    bgColor = QColor(m_color);
  }
  painter->setPen(pen);
  painter->setBrush(bgColor);
  QRectF rect(-m_width / 2, -m_height / 2, m_width, m_height);
  painter->drawRect(rect);
  // Handle the case where the item is selected
  if (bgColor.value() < 150)
    pen.setColor(Qt::white);
  else
    pen.setColor(Qt::black);
  painter->setPen(pen);
  painter->drawText(rect, Qt::AlignCenter, m_symbol);
}

} // End namespace QtGui
} // End namespace Avogadro
