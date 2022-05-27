/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H
#define AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H

#include <QtWidgets/QWidget>

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class SelectionToolWidget;
}

class SelectionToolWidget : public QWidget
{
  Q_OBJECT

public:
  explicit SelectionToolWidget(QWidget* parent = nullptr);
  ~SelectionToolWidget();

  void setDropDown(size_t current, size_t max);

signals:
  void colorApplied(Vector3ub color);
  void changeLayer(int layer);

private slots:
  void userClickedColor();

private:
  Ui::SelectionToolWidget* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SELECTIONTOOLWIDGET_H
