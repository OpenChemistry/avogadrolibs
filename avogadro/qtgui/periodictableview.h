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

#ifndef AVOGADRO_QTGUI_PERIODICTABLEVIEW_H
#define AVOGADRO_QTGUI_PERIODICTABLEVIEW_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QGraphicsView>

namespace Avogadro {
namespace QtGui {

/**
 * @class PeriodicTableView periodictableview.h
 * <avogadro/qtgui/periodictableview.h>
 * @author Marcus D. Hanwell
 * @brief This class implements the view of the periodic table showing all
 * elements.
 *
 * This is the class that actually draws the widget onto screen. This is
 * the class that should normally be instantiated in order to display a
 * Periodic Table.
 */
class AVOGADROQTGUI_EXPORT PeriodicTableView : public QGraphicsView
{
  Q_OBJECT

public:
  /**
   * Constructor - constructs a new PeriodicTableView with an internal instance
   * of PeriodicTableScene.
   */
  explicit PeriodicTableView(QWidget* parent_ = nullptr);
  ~PeriodicTableView() override;

  /**
   * @return The currently selected element.
   */
  int element() const { return m_element; }

public slots:
  /**
   * @param element_ The currently selected element.
   */
  void setElement(int element_);

  /**
   * This slot is called to clear the key buffer (e.g. after a delay in typing).
   */
  void clearKeyPressBuffer();

private slots:
  /**
   * Use this slot to change the active element.
   */
  void elementClicked(int element);

signals:
  /**
   * Signal emitted when the active element in the PeriodicTableView changes.
   */
  void elementChanged(int element);

protected:
  /**
   * Double click event - select an element and hide the PeriodicTableView.
   */
  void mouseDoubleClickEvent(QMouseEvent* event) override;

  /**
   * Handles the keyboard events to change the active element.
   */
  void keyPressEvent(QKeyEvent* event_) override;

  /**
   * Handle resize events.
   */
  void resizeEvent(QResizeEvent* event) override;

private:
  /**
   * Proton number of the active element.
   */
  int m_element;

  QString m_keyPressBuffer;
};

} // End of QtGui namespace
} // End of Avogadro namespace

#endif
