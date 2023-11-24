/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ELEMENTITEM_P_H
#define AVOGADRO_QTGUI_ELEMENTITEM_P_H

#include <QtWidgets/QGraphicsItem>

namespace Avogadro {
namespace QtGui {

/**
 * @class ElementItem
 * @internal
 * @author Marcus D. Hanwell
 * @brief An element item, intended to display a single element.
 *
 * This class implements a QGraphicsItem for displaying single elements in a
 * periodic table. It currently allows the setting of the proton number and
 * gets all other information from OpenBabel.
 */
class ElementItem : public QGraphicsItem
{
public:
  /**
   * Constructor. Should be called with the element number for this item. The
   * constructor uses setData to set the element number using the key 0. This
   * is then used by PeriodicTable to figure out which element was clicked on.
   */
  ElementItem(int elementNumber = 0);
  ~ElementItem() override;

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
   * along with its symbol.
   */
  void paint(QPainter* painter, const QStyleOptionGraphicsItem* option,
             QWidget* widget) override;

private:
  /** Indicates if element is well-formed (e.g., has non-empty symbol). */
  bool m_valid;

  /** The element numbers symbol. */
  QString m_symbol;

  /**
   * The color of the element which will also be used as the background color
   * for the item box.
   */
  QColor m_color;

  /**
   * Width and height of the elements.
   */
  int m_width, m_height;

  /**
   * The proton number of the item - all other attributes are derived from this.
   */
  int m_element;
};

} // End namespace QtGui
} // End namespace Avogadro

#endif // AVOGADRO_QTGUI_ELEMENTITEM_P_H
