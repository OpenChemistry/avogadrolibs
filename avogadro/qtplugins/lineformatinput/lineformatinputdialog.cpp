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

#include "lineformatinputdialog.h"
#include "ui_lineformatinputdialog.h"

#include <QtCore/QSettings>

namespace Avogadro {
namespace QtPlugins {

LineFormatInputDialog::LineFormatInputDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::LineFormatInputDialog)
{
  m_ui->setupUi(this);
}

LineFormatInputDialog::~LineFormatInputDialog()
{
  delete m_ui;
}

void LineFormatInputDialog::setFormats(const QStringList& indents)
{
  m_ui->formats->clear();
  m_ui->formats->addItems(indents);

  QSettings settings;
  QString lastUsed = settings.value("lineformatinput/lastUsed").toString();
  int index = m_ui->formats->findText(lastUsed);
  if (index >= 0)
    m_ui->formats->setCurrentIndex(index);
}

QString LineFormatInputDialog::format() const
{
  return m_ui->formats->currentText();
}

void LineFormatInputDialog::setCurrentFormat(const QString& format)
{
  int index = m_ui->formats->findText(format);
  if (index >= 0)
    m_ui->formats->setCurrentIndex(index);
}

QString LineFormatInputDialog::descriptor() const
{
  return m_ui->descriptor->text();
}

void LineFormatInputDialog::accept()
{
  QSettings settings;
  settings.setValue("lineformatinput/lastUsed", format());
  QDialog::accept();
}

} // namespace QtPlugins
} // namespace Avogadro
