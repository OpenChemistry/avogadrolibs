/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "periodictableview.h"
#include "periodictablescene_p.h"
#include <avogadro/core/elements.h>

#include <QtCore/QTimer>
#include <QtGui/QKeyEvent>

namespace Avogadro::QtGui {

using Core::Elements;

PeriodicTableView::PeriodicTableView(QWidget* parent_)
  : QGraphicsView(parent_), m_element(6) // Everyone loves carbon.
{
  // Make the periodic table view a standard dialog.
  setWindowFlags(Qt::Dialog);

  auto* table = new PeriodicTableScene;
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
  auto* table = qobject_cast<PeriodicTableScene*>(scene());
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
    // Wait for 2 seconds, then clear the buffer,
    // this ensures we can get multi-character elements.
    QTimer::singleShot(2000, this, SLOT(clearKeyPressBuffer()));
  }

  if (event_->key() == Qt::Key_Escape || event_->key() == Qt::Key_Return ||
      event_->key() == Qt::Key_Enter) {
    close();
    return;
  }

  // check for arrow keys
  int elem = m_element;
  if (event_->key() == Qt::Key_Left) {
    elem -= 1;
  } else if (event_->key() == Qt::Key_Right) {
    elem += 1;
  } else if (event_->key() == Qt::Key_Up) {

    // What row are we?
    if (elem == 3) { // ignore other 2nd row
      elem = 1;
    } else if (elem >= 10 && elem <= 20) {
      elem -= 8;
    } else if (elem >= 21 && elem <= 30) {
      // nothing to do, top row of transition metals
    } else if (elem >= 31 && elem <= 56) {
      elem -= 18; // go up a row
    } else if (elem >= 57 && elem <= 70) {
      // nothing to do, top row of lanthanides
    } else if (elem >= 71 && elem <= 118) {
      elem -= 32; // go up a row
    }
  } else if (event_->key() == Qt::Key_Down) {
    // What row are we?
    if (elem == 1) {
      elem = 3;
    } else if (elem == 2) {
      elem = 10;
    } else if (elem >= 3 && elem <= 12) {
      elem += 8; // down one row
    } else if (elem >= 13 && elem <= 38) {
      elem += 18; // down one row
    } else if (elem >= 39 && elem <= 86) {
      elem += 32; // down one row
    } else if (elem >= 87 && elem <= 118) {
      // last row, nothing to do
    }
  } else {
    // This is a normal character.
    m_keyPressBuffer += event_->text();
    // Try setting an element symbol from this string.
    elem = m_keyPressBuffer.toInt();
    if (elem <= 0 || elem > 119) {
      // Not a valid number, have we tried 2- and 3-character symbols?
      if (m_keyPressBuffer.length() > 3) {
        clearKeyPressBuffer();
      } else {
        // try parsing as a symbol .. first character should be uppercase
        m_keyPressBuffer[0] = m_keyPressBuffer[0].toUpper();

        elem = static_cast<int>(
          Elements::atomicNumberFromSymbol(m_keyPressBuffer.toLatin1().data()));
      }
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

} // namespace Avogadro
