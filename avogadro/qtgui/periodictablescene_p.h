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

#ifndef AVOGADRO_QTGUI_PERIODICTABLESCENE_P_H
#define AVOGADRO_QTGUI_PERIODICTABLESCENE_P_H

#include <QtWidgets/QGraphicsScene>

namespace Avogadro {
namespace QtGui {

class ElementDetail;

/**
 * @class PeriodicTableScene
 * @internal
 * @author Marcus D. Hanwell
 * @brief This class encapsulates the scene, all items are contained in it.
 *
 * This class implements a QGraphicsScene that holds all of the element items.
 * Any items owned by this class are automatically deleted by it.
 */
class PeriodicTableScene : public QGraphicsScene
{
  Q_OBJECT

public:
  /** Constructor. */
  explicit PeriodicTableScene(QObject* parent = nullptr);

signals:
  /**
   * This signal is emitted when an element item is clicked.
   */
  void elementChanged(int element);

public slots:
  /**
   * This slot is called when an element is changed (e.g., by keyboard or code).
   */
  void changeElement(int element);

protected:
  /**
   * Handles the mouse press events to change the active element.
   */
  void mousePressEvent(QGraphicsSceneMouseEvent* event) override;

private:
  ElementDetail* m_detail;
};

} // End namespace QtGui
} // End namespace Avogadro

#endif // AVOGADRO_QTGUI_PERIODICTABLESCENE_P_H
