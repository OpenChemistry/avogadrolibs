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

#include "filebrowsewidget.h"

#include <QtGui/QCompleter>
#include <QtGui/QFileDialog>
#include <QtGui/QFileSystemModel>
#include <QtGui/QHBoxLayout>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>

#include <QtCore/QFileInfo>

namespace Avogadro {
namespace QtGui {

FileBrowseWidget::FileBrowseWidget(QWidget *theParent) :
  QWidget(theParent),
  m_button(new QPushButton(tr("Browse"))),
  m_edit(new QLineEdit)
{
  QHBoxLayout *hbox = new QHBoxLayout;
  hbox->addWidget(m_edit);
  hbox->addWidget(m_button);
  this->setLayout(hbox);

  // Setup completion
  QFileSystemModel *fsModel = new QFileSystemModel(this);
  fsModel->setFilter(QDir::Files | QDir::Dirs | QDir::NoDot);
  fsModel->setRootPath(QDir::rootPath());
  QCompleter *fsCompleter = new QCompleter(fsModel, this);
  m_edit->setCompleter(fsCompleter);

  // Connections:
  connect(m_button, SIGNAL(clicked()), SLOT(browse()));
  connect(m_edit, SIGNAL(textChanged(QString)), SLOT(testFileName()));
}

FileBrowseWidget::~FileBrowseWidget()
{
}

QString FileBrowseWidget::fileName() const
{
  return m_edit->text();
}

QPushButton *FileBrowseWidget::browseButton() const
{
  return m_button;
}

QLineEdit *FileBrowseWidget::lineEdit() const
{
  return m_edit;
}

void FileBrowseWidget::setFileName(const QString &fname)
{
  m_edit->setText(fname);
}

void FileBrowseWidget::browse()
{
  QString fname = fileName();
  QFileInfo info(fname);
  QString initialPath = !fname.isEmpty() ? info.absolutePath()
                                         : QDir::homePath();

  initialPath += "/" + info.fileName();

  QString newFilePath = QFileDialog::getOpenFileName(
        this, tr("Select file"), initialPath);

  if (!newFilePath.isEmpty())
    setFileName(newFilePath);
}

void FileBrowseWidget::testFileName()
{
  QFileInfo info(fileName());
  if (info.exists())
    fileNameMatch();
  else
    fileNameNoMatch();
}

void FileBrowseWidget::fileNameMatch()
{
  QPalette pal;
  pal.setColor(QPalette::Text, Qt::black);
  m_edit->setPalette(pal);
}

void FileBrowseWidget::fileNameNoMatch()
{
  QPalette pal;
  pal.setColor(QPalette::Text, Qt::red);
  m_edit->setPalette(pal);
}

} // namespace QtGui
} // namespace Avogadro
