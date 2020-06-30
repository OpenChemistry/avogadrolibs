#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"
#include <QPushButton>
#include <QButtonGroup>
#include <QDebug>
#include <QTextStream>

#include <QFileDialog>
#include <QFile>
#include <QString>
#include <QMessageBox>
#include <string>

namespace Avogadro {
  namespace QtPlugins {
    ConstraintsDialog::ConstraintsDialog(QWidget* parent_, Qt::WindowFlags f) : QDialog(parent_,f), ui(new Ui::ConstraintsDialog)//, m_constraints(new QtPlugins::ConstraintsModel)
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
    void ConstraintsDialog::setModel(ConstraintsModel *model)
    {
      m_constraints = model; // new QtPlugins::ConstraintsModel();
      ui->ConstraintsTableView->setModel(m_constraints);
    }
    void ConstraintsDialog::acceptConstraints()
    {
      hide();
    }
    void ConstraintsDialog::deleteConstraint()
    {
      m_constraints->deleteConstraint(ui->ConstraintsTableView->currentIndex().row());
    }
    void ConstraintsDialog::addConstraint()
    {
      int type = ui->comboType->currentIndex();
      double value = ui->editValue->value();
      int AtomIdA = ui->editA->value();
      int AtomIdB = ui->editB->value();
      int AtomIdC = ui->editC->value();
      int AtomIdD = ui->editD->value();

      m_constraints->addConstraint(type,
                                   AtomIdA,
                                   AtomIdB,
                                   AtomIdC,
                                   AtomIdD,
                                   value);
    }
    void ConstraintsDialog::deleteAllConstraints()
    {
      m_constraints->clear();
      this->update();
    }
  }
}
