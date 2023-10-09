/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_MULTIVIEWWIDGET_H
#define AVOGADRO_QTGUI_MULTIVIEWWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtGui {

class ContainerWidget;
class ViewFactory;
class ActiveWidgetFilter;

/**
 * @class MultiViewWidget multiviewwidget.h <avogadro/qtgui/multiviewwidget.h>
 * @brief A widget that contains other views, taking on responsibility for
 * defining the active view, the layout of the subviews and ownership of the
 * widgets.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT MultiViewWidget : public QWidget
{
  Q_OBJECT

public:
  explicit MultiViewWidget(QWidget* parent = nullptr,
                           Qt::WindowFlags f = Qt::WindowFlags());
  ~MultiViewWidget() override;

  void addWidget(QWidget* widget);

  /**
   * @brief Get the currently active widget.
   * @return The active widget.
   */
  QWidget* activeWidget();
  void setActiveWidget(QWidget* widget);

  void setFactory(ViewFactory* factory) { m_factory = factory; }
  void setDefaultView(const QString& viewName) { m_defaultView = viewName; }

signals:
  void activeWidgetChanged(QWidget* widget);

public slots:
  void splitHorizontal();
  void splitVertical();
  void createView();
  void removeView();

private:
  QList<ContainerWidget*> m_children;
  ViewFactory* m_factory;
  QString m_defaultView;
  QWidget* m_activeWidget;
  ActiveWidgetFilter* m_activeFilter;

  ContainerWidget* createContainer(QWidget* widget = nullptr);

  void splitView(Qt::Orientation orient, ContainerWidget* container);
};

} // End QtGui namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTGUI_MULTIVIEWWIDGET_H
