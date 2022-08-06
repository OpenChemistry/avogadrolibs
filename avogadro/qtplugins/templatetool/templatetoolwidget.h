/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H
#define AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H

#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtGui {
class PeriodicTableView;
}

namespace QtPlugins {

namespace Ui {
class TemplateToolWidget;
}

class TemplateToolWidget : public QWidget
{
  Q_OBJECT

public:
  explicit TemplateToolWidget(QWidget *parent_ = 0);
  ~TemplateToolWidget();

  void setAtomicNumber(unsigned char atomicNum);
  unsigned char atomicNumber() const;

  void setCoordination(unsigned char order);
  unsigned char coordination() const;
  QString coordinationString() const;

  unsigned char ligand() const;
  QString ligandString() const;

private slots:
  void elementChanged(int index);
  void updateElementCombo();
  void addUserElement(unsigned char element);
  void elementSelectedFromTable(int element);
  void selectElement(unsigned char element);
  
  void coordinationChanged(int index);

private:
  void buildElements();
  void buildBondOrders();
  void saveElements();

  Ui::TemplateToolWidget *m_ui;
  QtGui::PeriodicTableView *m_elementSelector;
  QList<unsigned char> m_defaultElements;
  QList<unsigned char> m_userElements;
  unsigned char m_currentElement;
  QStringList m_centers;
  QStringList m_ligands;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H
