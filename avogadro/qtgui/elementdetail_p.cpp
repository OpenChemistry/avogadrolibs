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

#include "elementdetail_p.h"
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

ElementDetail::ElementDetail(int elementNumber)
  : m_width(100)
  , m_height(70)
  , m_element(elementNumber)
{}

QRectF ElementDetail::boundingRect() const
{
  return QRectF(-m_width / 2, -m_height / 2, m_width, m_height);
}

QPainterPath ElementDetail::shape() const
{
  QPainterPath path;
  path.addRect(-m_width / 2, -m_height / 2, m_width, m_height);
  return path;
}

void ElementDetail::paint(QPainter* painter, const QStyleOptionGraphicsItem*,
                          QWidget*)
{
  // Set up a font object and get its height
  QFont font(QStringLiteral("sans-serif"));
  font.setPixelSize(12);
  painter->setFont(font);
  QFontMetrics fm(font);
  int pixelHeight = fm.height();

  QString symbol = Elements::symbol(static_cast<unsigned char>(m_element));
  QString name(ElementTranslator::name(m_element));
  QString mass = QStringLiteral("%L1").arg(
    Elements::mass(static_cast<unsigned char>(m_element)), 0, 'f', 3);

  const unsigned char* colorTmp =
    Elements::color(static_cast<unsigned char>(m_element));
  QColor color(Qt::white);
  if (colorTmp) {
    color.setRgb(static_cast<int>(colorTmp[0]), static_cast<int>(colorTmp[1]),
                 static_cast<int>(colorTmp[2]));
  }

  // Draw the element detail border and fill with the element colour
  painter->setBrush(color);
  painter->setPen(Qt::black);
  QRectF rect(-m_width / 2, -m_height / 2, m_width, m_height);
  painter->drawRect(rect);

  // Draw the element symbol bigger than everything else
  font.setPixelSize(24);
  QFontMetrics fm2(font);
  pixelHeight = fm2.height();
  int pixelWidth = fm2.width(symbol);
  painter->setFont(font);
  QRectF symbolRect(-10, -m_height / 2 + 8, pixelWidth, pixelHeight);
  painter->drawText(symbolRect, Qt::AlignCenter, symbol);

  // Reduce the font size to draw the other parts
  font.setPixelSize(12);
  int pixelHeight2 = fm.height();
  painter->setFont(font);

// I don't seem to be able to get a nice, cross platform layout working here
// I would really like to figure out how to make this more portable - ideas?
#ifdef Q_OS_MAC
  // Draw the proton number
  QRectF protonNumberRect(-m_width / 2 - 10, -m_height / 2 + 8, m_width / 2,
                          pixelHeight2);
  painter->drawText(protonNumberRect, Qt::AlignRight,
                    QString::number(m_element));

  // Draw the mass
  QRectF massNumberRect(-m_width / 2, -m_height / 2 + 8 + pixelHeight * 1.1,
                        m_width, pixelHeight2);
  painter->drawText(massNumberRect, Qt::AlignCenter, mass);

  // Finally the full element name
  QRectF nameRect(-m_width / 2,
                  -m_height / 2 + 4 + pixelHeight * 1.1 + pixelHeight2, m_width,
                  pixelHeight);
  painter->drawText(nameRect, Qt::AlignCenter, name);
#else
  // Draw the proton number
  QRectF protonNumberRect(-m_width / 2 - 10, -m_height / 2 + 16, m_width / 2,
                          pixelHeight2);
  painter->drawText(protonNumberRect, Qt::AlignRight,
                    QString::number(m_element));

  // Draw the mass
  QRectF massNumberRect(-m_width / 2, -m_height / 2 + 4 + pixelHeight, m_width,
                        pixelHeight2);
  painter->drawText(massNumberRect, Qt::AlignCenter, mass);

  // Finally the full element name
  QRectF nameRect(-m_width / 2,
                  -m_height / 2 + pixelHeight + 0.8 * pixelHeight2, m_width,
                  pixelHeight);
  painter->drawText(nameRect, Qt::AlignCenter, name);
#endif
}

void ElementDetail::setElement(int element)
{
  if (m_element != element) {
    m_element = element;
    update(boundingRect());
  }
}

} // End QtGui namespace
} // End Avogadro namespace
