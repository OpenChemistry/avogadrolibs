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

#include "qttextrenderstrategy.h"

#include <avogadro/rendering/textproperties.h>

#include <QtGui/QFont>
#include <QtGui/QFontMetrics>
#include <QtGui/QImage>
#include <QtGui/QMatrix>
#include <QtGui/QPainter>
#include <QtGui/QPolygonF>

#include <QtCore/QDebug>
#include <QtCore/QPoint>
#include <QtCore/QRectF>
#include <QtCore/QSysInfo>

#include <cmath>

// Testing
#include <iostream>

using Avogadro::Rendering::TextProperties;

namespace {

inline Qt::Alignment textPropertiesToAlignment(const TextProperties &prop)
{
  Qt::Alignment result = 0;

  switch (prop.hAlign()) {
  default:
  case TextProperties::HLeft:
    result |= Qt::AlignLeft;
    break;
  case TextProperties::HCenter:
    result |= Qt::AlignHCenter;
    break;
  case TextProperties::HRight:
    result |= Qt::AlignRight;
    break;
  }

  switch (prop.vAlign()) {
  default:
  case TextProperties::VTop:
    result |= Qt::AlignTop;
    break;
  case TextProperties::VCenter:
    result |= Qt::AlignVCenter;
    break;
  case TextProperties::VBottom:
    result |= Qt::AlignBottom;
    break;
  }

  return result;
}

inline QFont textPropertiesToQFont(const TextProperties &prop)
{
  QString family;
  switch (prop.fontFamily()) {
  default:
    qWarning() << "Unknown font family id: " << prop.fontFamily()
               << "Defaulting to SansSerif.";
  case TextProperties::SansSerif:
    family = "sans";
    break;
  case TextProperties::Serif:
    family = "serif";
    break;
  case TextProperties::Mono:
    family = "mono";
    break;
  }

  TextProperties::FontStyles style = prop.fontStyles();

  QFont result(family, prop.fontSize(),
               static_cast<bool>(style & TextProperties::Bold) ? QFont::Bold
                                                               : QFont::Normal,
               static_cast<bool>(style & TextProperties::Italic));

  result.setUnderline(static_cast<bool>(style & TextProperties::Underline));

  return result;
}

template <typename T>
inline T min4(const T &v1, const T &v2, const T &v3, const T &v4)
{
  using std::min;
  return min(min(v1, v2), min(v3, v4));
}

} // end anon namespace

namespace Avogadro {
namespace QtGui {

QtTextRenderStrategy::QtTextRenderStrategy()
{
}

QtTextRenderStrategy::~QtTextRenderStrategy()
{
}

Rendering::TextRenderStrategy *QtTextRenderStrategy::newInstance() const
{
  return new QtTextRenderStrategy;
}

void QtTextRenderStrategy::boundingBox(
    const std::string &string, const Rendering::TextProperties &tprop,
    int bbox[]) const
{
  QRect rect;
  const QFont font(textPropertiesToQFont(tprop));
  const Qt::Alignment align(textPropertiesToAlignment(tprop));
  rect = QFontMetrics(font).boundingRect(rect, align,
                                         QString::fromStdString(string));
  // Rotate if needed
  if (tprop.rotationDegreesCW() != 0.f) {
    // Build transformation
    QMatrix transform;
    transform.rotate(static_cast<qreal>(-tprop.rotationDegreesCW()));

    // Transform a floating point representation of the bbox
    QRectF tmpRect(rect);
    tmpRect = transform.mapRect(tmpRect);

    // Update the bbox, rounding values to give the largest containing bbox
    rect.setLeft(std::floor(tmpRect.left()));
    rect.setRight(std::floor(tmpRect.right()));
    rect.setTop(std::ceil(tmpRect.top()));
    rect.setBottom(std::floor(tmpRect.bottom()));
  }

  bbox[0] = rect.left();
  bbox[1] = rect.right();
  bbox[2] = rect.top();
  bbox[3] = rect.bottom();
}

void QtTextRenderStrategy::render(const std::string &string,
                                  const Rendering::TextProperties &tprop,
                                  unsigned char *buffer, size_t dims[2]) const
{
  size_t width = dims[0];
  size_t height = dims[1];
  int origin[2] = {0, 0};
  QString str = QString::fromStdString(string);
  Qt::Alignment flags = textPropertiesToAlignment(tprop);
  QFont font = textPropertiesToQFont(tprop);

  QImage target(buffer, width, height, QImage::Format_ARGB32_Premultiplied);
  QPainter painter(&target);
  painter.setFont(font);
  painter.setPen(QColor(tprop.red(), tprop.green(),
                        tprop.blue(), tprop.alpha()));
  // Adjust the origin if the text is to be rotated
  float rot(tprop.rotationDegreesCW());
  if (rot != 0.f) {
    // Get a tight bbox for the unrotated text as a polygon:
    QRectF textRect(painter.boundingRect(QRectF(), flags, str));
    QPolygonF textCorners(textRect);

    // Rotate the painter:
    painter.rotate(static_cast<qreal>(tprop.rotationDegreesCW()));

    // Map the polygon through the rotated painter:
    textCorners = painter.transform().map(textCorners);

    // Find the new origin in the rotated space:
    QPointF newOrigin(-min4(textCorners[0].x(), textCorners[1].x(),
                            textCorners[2].x(), textCorners[3].x()),
                      -min4(textCorners[0].y(), textCorners[1].y(),
                            textCorners[2].y(), textCorners[3].y()));

    // Rotate the point back (drawText will reapply the rotation)
    newOrigin = painter.transform().inverted().map(newOrigin);
    origin[0] = newOrigin.x();
    origin[1] = newOrigin.y();

    // Update the width and height to use the tight unrotated text bbox:
    width = std::ceil(textRect.width());
    height = std::ceil(textRect.height());
  }

  painter.drawText(origin[0], origin[1], width, height, flags, str);
  painter.end();
  target.save("/tmp/t.png");

  // Convert the buffer from ARGB --> RGBA for openGL.
  argbToRgba(buffer, dims[0] * dims[1]);
}

template <int ByteOrder> inline
void argbToRgbaWorker(quint32 in, quint32 &out)
{
  Q_UNUSED(in)
  Q_UNUSED(out)
  qWarning("QtTextRenderStrategy::argbToRgba: Invalid byte order.");
}

template < > inline
void argbToRgbaWorker<QSysInfo::BigEndian>(quint32 in, quint32 &out)
{
  out = ((in >> 24) & 0xff) | (in << 8);
}

template < > inline
void argbToRgbaWorker<QSysInfo::LittleEndian>(quint32 in, quint32 &out)
{
  out = ((in << 16) & 0xff0000) | ((in >> 16) & 0xff) | (in & 0xff00ff00);
}

void QtTextRenderStrategy::argbToRgba(unsigned char *buffer, size_t pixels)
{
  // Adapted from QGLWidget::convertToGLFormat.
  // input:  0xAARRGGBB
  // output: 0xRRGGBBAA (big endian)
  // output: 0xAABBGGRR (little endian)

  quint32 *cur = reinterpret_cast<quint32*>(buffer);
  quint32 *end = cur + pixels;

  while (cur < end) {
    // Skip empty pixels
    while (*cur == 0 && cur < end)
      ++cur;
    argbToRgbaWorker<QSysInfo::ByteOrder>(*cur, *cur);
    ++cur;
  }
}

} // namespace QtGui
} // namespace Avogadro
