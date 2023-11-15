/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H
#define AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H

#include <qlist.h>
#include <qobjectdefs.h>
#include <qstring.h>
#include <qstringlist.h>
#include <qwidget.h>
#include <stddef.h>
#include <QtWidgets/QWidget>
#include <vector>

class QObject;

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

  signed char formalCharge() const;

  void setCoordination(unsigned char order);
  unsigned char coordination() const;
  QString coordinationString() const;

  unsigned char ligand() const;
  QString ligandString() const;
  
  int denticity() const;
  std::vector<size_t> &selectedUIDs();

private slots:
  void elementChanged(int index);
  void updateElementCombo();
  void addUserElement(unsigned char element);
  void elementSelectedFromTable(int element);
  void selectElement(unsigned char element);
  
  void coordinationChanged(int index);
  
  void typeChanged(int index);
  void ligandChanged(int index);

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
  
  int m_denticity;
  std::vector<size_t> m_selectedUIDs;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H
