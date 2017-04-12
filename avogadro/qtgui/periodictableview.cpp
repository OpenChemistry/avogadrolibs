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

#include "periodictableview.h"
#include "periodictablescene_p.h"
#include <avogadro/core/elements.h>

#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>

namespace Avogadro {
namespace QtGui {

using Core::Elements;

PeriodicTableView::PeriodicTableView(QWidget* parent_)
  : QGraphicsView(parent_), m_element(6) // Everyone loves carbon.
{
  // Make the periodic table view a standard dialog.
  setWindowFlags(Qt::Dialog);

  PeriodicTableScene* table = new PeriodicTableScene;
  table->setSceneRect(-20, -20, 480, 260);
  table->setItemIndexMethod(QGraphicsScene::NoIndex);
  table->setBackgroundBrush(Qt::white);
  table->changeElement(m_element);

  setScene(table);
  setRenderHint(QPainter::Antialiasing);
  setWindowTitle(tr("Periodic Table"));
  resize(490, 270);
  connect(table, SIGNAL(elementChanged(int)), this, SLOT(elementClicked(int)));
}

PeriodicTableView::~PeriodicTableView()
{
  delete scene();
}

void PeriodicTableView::setElement(int element_)
{
  m_element = element_;
  PeriodicTableScene* table = qobject_cast<PeriodicTableScene*>(scene());
  if (table)
    table->changeElement(element_);
}

void PeriodicTableView::elementClicked(int id)
{
  m_element = id;
  emit(elementChanged(id));
}

void PeriodicTableView::mouseDoubleClickEvent(QMouseEvent*)
{
  close();
}

void PeriodicTableView::clearKeyPressBuffer()
{
  m_keyPressBuffer.clear();
}

void PeriodicTableView::keyPressEvent(QKeyEvent* event_)
{
  if (m_keyPressBuffer.isEmpty()) {
    // This is the first character typed.
    // Qait for 2 seconds, then clear the buffer,
    // this ensures we can get multi-character elements.
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));
  }

  m_keyPressBuffer.append(event_->text());
  // Try setting an element symbol from this string.
  int elem = m_keyPressBuffer.toInt();
  if (elem <= 0 || elem > 119) {
    // Not a valid number, have we tried 2- and 3-character symbols?
    if (m_keyPressBuffer.length() > 3) {
      clearKeyPressBuffer();
    } else {
      // try parsing as a symbol
      elem = static_cast<int>(
        Elements::atomicNumberFromSymbol(m_keyPressBuffer.toLatin1().data()));
    }
  }

  // got a valid symbol
  if (elem > 0 && elem < 119)
    setElement(elem);

  QGraphicsView::keyPressEvent(event_);
}

void PeriodicTableView::resizeEvent(QResizeEvent* e)
{
  double scale_(double(e->size().width()) / 500.0);
  QTransform scaleTransform(QTransform::fromScale(scale_, scale_));
  setTransform(scaleTransform);
}

} // End QtGui namespace
} // End Avogadro namespace
