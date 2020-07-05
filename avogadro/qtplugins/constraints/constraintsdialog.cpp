#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"
#include <QPushButton>
#include <QButtonGroup>
#include <QDebug>
#include <QTextStream>

//#include <QFileDialog>
//#include <QFile>
//#include <QString>
//#include <QMessageBox>
//#include <string>

namespace Avogadro {
  //  namespace QtGui{
  //              class Molecule;
  //  }
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

    }

    ConstraintsDialog::~ConstraintsDialog()
    {
      delete ui;
    }

    void ConstraintsDialog::setModel()
    {
      ui->ConstraintsTableView->setModel(m_plugin->m_molecule->constraints);
      connect( m_plugin->m_molecule, SIGNAL( changed(unsigned int)),
               m_plugin->m_molecule->constraints, SLOT (emitDataChanged()));
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
      int type = ui->comboType->currentIndex();
      double value = ui->editValue->value();
      int AtomIdA = ui->editA->value();
      int AtomIdB = ui->editB->value();
      int AtomIdC = ui->editC->value();
      int AtomIdD = ui->editD->value();

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
