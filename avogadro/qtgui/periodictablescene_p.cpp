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

#include "periodictablescene_p.h"
#include "elementdetail_p.h"
#include "elementitem_p.h"
#include "elementtranslator.h"

#include <QtGui/QFont>
#include <QtGui/QFontMetrics>
#include <QtGui/QPainter>
#include <QtWidgets/QGraphicsSceneMouseEvent>
#include <QtWidgets/QStyleOption>

namespace Avogadro {
namespace QtGui {

PeriodicTableScene::PeriodicTableScene(QObject* parent_)
  : QGraphicsScene(parent_)
{
  int width_ = 26;
  int height_ = 26;

  m_detail = new ElementDetail(1);
  m_detail->setPos(6.5 * width_, 0.75 * height_);
  addItem(m_detail);

  ElementItem* item = new ElementItem(1);
  item->setPos(0 * width_, 0 * height_);
  addItem(item);

  item = new ElementItem(2);
  item->setPos(17 * width_, 0 * height_);
  addItem(item);

  item = new ElementItem(3);
  item->setPos(0 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(4);
  item->setPos(1 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(5);
  item->setPos(12 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(6);
  item->setPos(13 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(7);
  item->setPos(14 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(8);
  item->setPos(15 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(9);
  item->setPos(16 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(10);
  item->setPos(17 * width_, 1 * height_);
  addItem(item);

  item = new ElementItem(11);
  item->setPos(0 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(12);
  item->setPos(1 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(13);
  item->setPos(12 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(14);
  item->setPos(13 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(15);
  item->setPos(14 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(16);
  item->setPos(15 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(17);
  item->setPos(16 * width_, 2 * height_);
  addItem(item);

  item = new ElementItem(18);
  item->setPos(17 * width_, 2 * height_);
  addItem(item);

  int element = 19;
  for (int i = 3; i < 5; ++i) {
    for (int j = 0; j < 18; ++j) {
      item = new ElementItem(element++);
      item->setPos(j * width_, i * height_);
      addItem(item);
    }
  }

  item = new ElementItem(element++);
  item->setPos(0 * width_, 5 * height_);
  addItem(item);

  item = new ElementItem(element++);
  item->setPos(1 * width_, 5 * height_);
  addItem(item);

  element = 71;

  for (int i = 2; i < 18; ++i) {
    item = new ElementItem(element++);
    item->setPos(i * width_, 5 * height_);
    addItem(item);
  }

  item = new ElementItem(element++);
  item->setPos(0 * width_, 6 * height_);
  addItem(item);

  item = new ElementItem(element++);
  item->setPos(1 * width_, 6 * height_);
  addItem(item);

  element = 103;
  // Goes up to element 118
  for (int i = 2; i < 18; ++i) {
    item = new ElementItem(element++);
    item->setPos(i * width_, 6 * height_);
    addItem(item);
  }

  // Now for the weird ones at the bottom...
  element = 57;
  for (int i = 2; i < 16; ++i) {
    item = new ElementItem(element++);
    item->setPos(i * width_, 7.5 * height_);
    addItem(item);
  }
  element = 89;
  for (int i = 2; i < 16; ++i) {
    item = new ElementItem(element++);
    item->setPos(i * width_, 8.5 * height_);
    addItem(item);
  }
}

void PeriodicTableScene::mousePressEvent(QGraphicsSceneMouseEvent* event_)
{
  if (event_->button() != Qt::LeftButton)
    return;

  QGraphicsItem* item =
    QGraphicsScene::itemAt(event_->scenePos(), QTransform());
  if (item->data(0).toInt() > 0 && item->data(0).toInt() < 119) {
    emit(elementChanged(item->data(0).toInt()));
    m_detail->setElement(item->data(0).toInt());
  }

  QGraphicsScene::mousePressEvent(event_);
}

void PeriodicTableScene::changeElement(int element)
{
  // Find the item to select
  foreach (QGraphicsItem* item, items()) {
    if (item->data(0).toInt() == element)
      item->setSelected(true);
    else
      item->setSelected(false);
  }

  // Emit a signal the element changed, and update the detail item.
  emit(elementChanged(element));
  m_detail->setElement(element);
}

} // End namespace QtGui
} // End namespace Avogadro
