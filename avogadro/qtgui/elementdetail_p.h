/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ELEMENTDETAIL_P_H
#define AVOGADRO_QTGUI_ELEMENTDETAIL_P_H

#include <QtWidgets/QGraphicsItem>

namespace Avogadro {
namespace QtGui {

/**
 * @class ElementDetail
 * @internal
 * @author Marcus D. Hanwell
 * @brief An item box displaying more detailed information on the element.
 *
 * This class implements a QGraphicsItem for displaying a larger box that
 * gives greater detail about the selected element such as its full name,
 * proton number and average atomic mass.
 */
class ElementDetail : public QGraphicsItem
{
public:
  /**
   * Constructor. Should be called with the element number for this item.
   */
  explicit ElementDetail(int elementNumber = 0);

  /**
   * @return the bounding rectangle of the element item.
   */
  QRectF boundingRect() const override;

  /**
   * @return the painter path which is also a rectangle in this case.
   */
  QPainterPath shape() const override;

  /**
   * This is where most of the action takes place. The element box is drawn
   * along with its symbol, proton number, mass and full name.
   */
  void paint(QPainter* painter, const QStyleOptionGraphicsItem* option,
             QWidget* widget) override;

  /**
   * Change the element displayed in the detail object.
   */
  void setElement(int element);

private:
  /**
   * Width and height of the item.
   */
  int m_width, m_height;

  /**
   * The proton number of the item - all other attributes are derived from this.
   */
  int m_element;
};

} // End namespace QtGui
} // End namespace Avogadro

#endif // AVOGADRO_QTGUI_ELEMENTDETAIL_P_H
