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

PeriodicTableView::PeriodicTableView(QWidget *parent_) : QGraphicsView(parent_)
{
  // Use a small title bar (Qt::Tool) with no minimize or maximise buttons
  setWindowFlags(Qt::Dialog | Qt::Tool);

  PeriodicTableScene *table = new PeriodicTableScene;
  table->setSceneRect(-20, -20, 480, 260);
  table->setItemIndexMethod(QGraphicsScene::NoIndex);
  table->setBackgroundBrush(Qt::white);

  setScene(table);
  setRenderHint(QPainter::Antialiasing);
  setWindowTitle(tr("Periodic Table"));
  resize(490, 270);
  setFixedSize(490, 270);
  connect(table, SIGNAL(elementChanged(int)),
          this, SLOT(elementClicked(int)));
}

PeriodicTableView::~PeriodicTableView()
{
  delete scene();
}

void PeriodicTableView::elementClicked(int id)
{
  emit(elementChanged(id));
}

void PeriodicTableView::mouseDoubleClickEvent(QMouseEvent *)
{
  close();
}

void PeriodicTableView::clearKeyPressBuffer()
{
  m_keyPressBuffer.clear();
}

void PeriodicTableView::keyPressEvent(QKeyEvent *event_)
{
  if (m_keyPressBuffer.isEmpty()) {
    // This is the first character typed.
    // Qait for 2 seconds, then clear the buffer,
    // this ensures we can get multi-character elements.
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));
  }

  m_keyPressBuffer.append(event_->text());
  // Try setting an element symbol from this string.
  int element = m_keyPressBuffer.toInt();
  if (element <= 0 || element > 119) {
    // Not a valid number, have we tried 2- and 3-character symbols?
    if (m_keyPressBuffer.length() > 3) {
      clearKeyPressBuffer();
    }
    else {
      // try parsing as a symbol
      element = Elements::atomicNumberFromSymbol(m_keyPressBuffer.toAscii().data());
    }
  }

  if (element > 0 && element < 119) { // got a valid symbol
    // Notify the scene
    PeriodicTableScene *table = qobject_cast<PeriodicTableScene *>(scene());
    if (table)
      table->changeElement(element);
  }

  QGraphicsView::keyPressEvent(event_);
}

} // End QtGui namespace
} // End Avogadro namespace
