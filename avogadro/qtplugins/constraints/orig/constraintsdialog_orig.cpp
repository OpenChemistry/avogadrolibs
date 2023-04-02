#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"
#include <QPushButton>
#include <QButtonGroup>
#include <QDebug>

#include <QFileDialog>
#include <QFile>

#include <QMessageBox>

namespace Avogadro {
  namespace QtPlugins {
    ConstraintsDialog::ConstraintsDialog(QWidget* parent_) : QDialog(parent_), ui(new Ui::ConstraintsDialog)
    {
      ui->setupUi(this);
    }
    ConstraintsDialog::~ConstraintsDialog()
    {
      delete ui;
    }
    void ConstraintsDialog::whow()
    {
      this->show();
    }
  }
}
