/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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

namespace Avogadro {
namespace QtPlugins {

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
}
