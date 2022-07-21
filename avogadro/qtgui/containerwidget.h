/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CONTAINERWIDGET_H
#define AVOGADRO_QTGUI_CONTAINERWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QWidget>

class QLabel;

namespace Avogadro {
namespace QtGui {

/**
 * @class ContainerWidget containerwidget.h <avogadro/qtgui/containerwidget.h>
 * @brief A widget that contains a single view widget, along with standard
 * buttons for splitting, maximizing, closing.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT ContainerWidget : public QWidget
{
  Q_OBJECT

public:
  explicit ContainerWidget(QWidget* parent = nullptr, Qt::WindowFlags f = 0);
  ~ContainerWidget() override;

  void setViewWidget(QWidget* widget);
  QWidget* viewWidget();

  void setActive(bool active);
  bool isActive() const { return m_active; }

signals:
  void splitVertical();
  void splitHorizontal();
  void closeView();

private:
  QWidget* m_viewWidget;
  QLabel* m_label;
  bool m_active;
};

} // End QtGui namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTGUI_CONTAINERWIDGET_H
