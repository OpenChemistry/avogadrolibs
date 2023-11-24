/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <iostream>

#include "apbsoutputdialog.h"
#include "opendxreader.h"
#include "ui_apbsoutputdialog.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>

namespace Avogadro::QtPlugins {

ApbsOutputDialog::ApbsOutputDialog(QWidget* parent_)
  : QDialog(parent_), m_ui(new Ui::ApbsOutputDialog)
{
  m_ui->setupUi(this);
}

ApbsOutputDialog::~ApbsOutputDialog()
{
}

bool ApbsOutputDialog::loadStructureFile() const
{
  return m_ui->loadStructureCheckBox->isChecked();
}

bool ApbsOutputDialog::loadCubeFile() const
{
  return m_ui->loadCubeCheckBox->isChecked();
}
}
