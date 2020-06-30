#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#include "constraintsmodel.h"
#include <QDialog>
#include <QButtonGroup>
#include <QModelIndex>
#include <QTableView>
#include <QString>
#include <avogadro/qtgui/molecule.h>
#include <string>

namespace Avogadro {
  namespace QtPlugins {
    namespace Ui {
      class ConstraintsDialog;
    }
    class ConstraintsDialog : public QDialog
    {
      Q_OBJECT

    public:
      explicit ConstraintsDialog(QWidget* parent_=0, Qt::WindowFlags f = 0);
      ~ConstraintsDialog() override;
      void setModel(ConstraintsModel *model);
      //void setMolecule(Molecule* m_molecule);
      
    public slots:
      void acceptConstraints();
      void addConstraint();
      void deleteConstraint();
      void deleteAllConstraints();
      /*
      void comboTypeChanged(int);
      */
    private:
      Ui::ConstraintsDialog* ui;
      ConstraintsModel *m_constraints;
      //Molecule* m_molecule;
    };
  }
}
#endif //AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
