#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"

#include <QPushButton>
#include <QButtonGroup>
#include <QDebug>
#include <QTextStream>

using Avogadro::QtGui::Molecule;

//#include <QFileDialog>
//#include <QFile>
//#include <QString>
//#include <QMessageBox>
//#include <string>

namespace Avogadro {
  namespace QtPlugins {
    ConstraintsDialog::ConstraintsDialog(ConstraintsExtension* plugin,
                                         QWidget* parent_,
                                         Qt::WindowFlags f)
      : QDialog(parent_,f)
      , m_plugin(plugin)
      , ui(new Ui::ConstraintsDialog)
    {
      ui->setupUi(this);
      connect( ui->ConstraintsOK, SIGNAL( clicked() ), this, SLOT( acceptConstraints() ));
      connect( ui->ConstraintsAdd, SIGNAL( clicked() ), this, SLOT( addConstraint() ));
      connect( ui->ConstraintsDelete, SIGNAL( clicked() ), this, SLOT( deleteConstraint() ));
      connect( ui->ConstraintsDeleteAll, SIGNAL( clicked() ), this, SLOT( deleteAllConstraints() ));
      //      connect( ui->HighlightButton, SIGNAL( clicked() ), this, SLOT( highlightSelected()));
      connect( ui->checkHighlight, SIGNAL( stateChanged(int)), this, SLOT( connectHighlight(int)));
    }

    ConstraintsDialog::~ConstraintsDialog()
    {
      delete ui;
    }

    void ConstraintsDialog::connectHighlight(int state)
    {
      if (state)
        {
          connect(ui->ConstraintsTableView->selectionModel(),
                  SIGNAL( selectionChanged(QItemSelection, QItemSelection)),
                  this, SLOT (highlightSelected()));
        }
      else
        {
          disconnect(ui->ConstraintsTableView->selectionModel(),
                     SIGNAL( selectionChanged(QItemSelection, QItemSelection)),
                     this, SLOT (highlightSelected()));
        }
    }

    void ConstraintsDialog::highlightSelected()
    {// check if highlighting requestd
      if (ui->checkHighlight->checkState())
        {//clear all previous selections
          for (int i = 0; i < m_plugin->m_molecule->atomCount(); ++i)
            {
              m_plugin->m_molecule->atom(i).setSelected(false);
            }
          // get currently selected constraint
          QModelIndex idx = ui->ConstraintsTableView->selectionModel()->currentIndex();
          // extract constraint from ConstraintModel
          QtPlugins::Constraint* c = &m_plugin->m_molecule->constraints->ConstraintsList[idx.row()];
          // iterate over involved uniqueAtomIDs
          for (int i = 0; i < c->Atoms.size(); i++)
            {
              // get atom by uniqueID and set selected
              m_plugin->m_molecule->atomByUniqueId(c->Atoms[i]).setSelected(true);
              qDebug() << "Set selected";
            }
          m_plugin->m_molecule->emitChanged(Molecule::Atoms);
        }
    }

    void ConstraintsDialog::setModel()
    {
      ui->ConstraintsTableView->setModel(m_plugin->m_molecule->constraints);
      connect( m_plugin->m_molecule, SIGNAL( changed(unsigned int)),
               m_plugin->m_molecule->constraints, SLOT (emitDataChanged()));
      /*
      connect( ui->ConstraintsTableView, SIGNAL( selectionChanged(const QItemSelection &selected,
                                                                  const QItemSelection &deselected)),
               this, SLOT(highlightSelected()));
      */
    }

    void ConstraintsDialog::acceptConstraints()
    {
      hide();
    }

    void ConstraintsDialog::deleteConstraint()
    {
      m_plugin->
        m_molecule->
        constraints->
        deleteConstraint(ui->ConstraintsTableView->currentIndex().row());
    }

    void ConstraintsDialog::addConstraint()
    {
      //Parsing user inptu
      int type = ui->comboType->currentIndex();
      double value = ui->editValue->value();
      int AtomIdA = ui->editA->value();
      int AtomIdB = ui->editB->value();
      int AtomIdC = ui->editC->value();
      int AtomIdD = ui->editD->value();

      //adding the constraint to the molecule's CosntraintsModel
      m_plugin->m_molecule->constraints->addConstraint(type,
                                                       AtomIdA,
                                                       AtomIdB,
                                                       AtomIdC,
                                                       AtomIdD,
                                                       value);
    }

    void ConstraintsDialog::deleteAllConstraints()
    {
      m_plugin->m_molecule->constraints->clear();
      this->update();
    }

  }
}
