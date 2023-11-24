/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_EDITORTOOLWIDGET_H
#define AVOGADRO_QTPLUGINS_EDITORTOOLWIDGET_H

#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtGui {
class PeriodicTableView;
}

namespace QtPlugins {

namespace Ui {
class EditorToolWidget;
}

class EditorToolWidget : public QWidget
{
  Q_OBJECT

public:
  explicit EditorToolWidget(QWidget* parent_ = nullptr);
  ~EditorToolWidget() override;

  void setAtomicNumber(unsigned char atomicNum);
  unsigned char atomicNumber() const;

  void setBondOrder(unsigned char order);
  unsigned char bondOrder() const;

  bool adjustHydrogens() const;

private slots:
  void elementChanged(int index);
  void updateElementCombo();
  void addUserElement(unsigned char element);
  void elementSelectedFromTable(int element);
  void selectElement(unsigned char element);

private:
  void buildElements();
  void buildBondOrders();
  void saveElements();

  Ui::EditorToolWidget* m_ui;
  QtGui::PeriodicTableView* m_elementSelector;
  QList<unsigned char> m_defaultElements;
  QList<unsigned char> m_userElements;
  unsigned char m_currentElement;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_EDITORTOOLWIDGET_H
