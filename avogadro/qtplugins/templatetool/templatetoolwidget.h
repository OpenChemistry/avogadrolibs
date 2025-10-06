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
class InsertFragmentDialog;
} // namespace QtGui

namespace QtPlugins {

namespace Ui {
class TemplateToolWidget;
}

class TemplateToolWidget : public QWidget
{
  Q_OBJECT

public:
  explicit TemplateToolWidget(QWidget* parent_ = 0);
  ~TemplateToolWidget() override;

  void setAtomicNumber(unsigned char atomicNum);
  unsigned char atomicNumber() const;

  void setFormalCharge(int charge);
  signed char formalCharge() const;

  void setCoordination(unsigned char geometry);
  unsigned char coordination() const;
  QString coordinationString() const;

  unsigned char ligand() const;
  QString ligandString() const;

  int denticity() const;
  std::vector<size_t>& selectedUIDs();

  int currentTab() const;
  void setCurrentTab(int index);

private slots:
  void elementChanged(int index);
  void updateElementCombo();
  void addUserElement(unsigned char element);
  void elementSelectedFromTable(int element);
  void selectElement(unsigned char element);

  void coordinationChanged(int index);

  void typeChanged(int index);
  void ligandChanged(int index);
  void groupChanged(int index);

  void otherLigandInsert(const QString& fileName, bool crystal);

private:
  void buildElements();
  void buildBondOrders();
  void saveElements();

  Ui::TemplateToolWidget* m_ui;
  QtGui::InsertFragmentDialog* m_fragmentDialog;
  QtGui::PeriodicTableView* m_elementSelector;
  QList<unsigned char> m_defaultElements;
  QList<unsigned char> m_userElements;
  unsigned char m_currentElement;
  QStringList m_centers;
  QStringList m_ligands;
  QStringList m_groups;
  QString m_ligandPath;

  int m_denticity;
  std::vector<size_t> m_selectedUIDs;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_TEMPLATETOOLWIDGET_H
