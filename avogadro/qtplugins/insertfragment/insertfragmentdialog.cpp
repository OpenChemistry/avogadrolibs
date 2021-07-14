/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2020 Geoffrey R. Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "insertfragmentdialog.h"
#include "ui_insertfragmentdialog.h"

#include "sortfiltertreeproxymodel.h"

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QSettings>

#include <QtCore/QDir>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStandardPaths>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFileSystemModel>
#include <QtWidgets/QMessageBox>

#include <QCloseEvent>

#include <QtCore/QDebug>

namespace Avogadro {
namespace QtPlugins {

class InsertFragmentDialog::Private
{
public:
  QFileSystemModel* model;
  SortFilterTreeProxyModel* proxy;
  QModelIndex proxyRoot;

  QString currentFileName;
  bool crystalFiles; // are we inserting crystals (i.e., don't center)

  ~Private()
  {
    if (model)
      delete model; // proxy is handled through the model
  }
};

InsertFragmentDialog::InsertFragmentDialog(QWidget* aParent, QString directory,
                                           Qt::WindowFlags)
  : QDialog(aParent), m_ui(new Ui::InsertFragmentDialog),
    m_implementation(new Private)
{
  setWindowFlags(Qt::Dialog | Qt::Tool);
  m_ui->setupUi(this);

  m_implementation->currentFileName.clear();
  if (directory.contains(QLatin1String("crystals")))
    m_implementation->crystalFiles = true;
  else
    m_implementation->crystalFiles = false;

  // we check for the downloaded version first
  QStringList dirs;
  QStringList stdPaths =
    QStandardPaths::standardLocations(QStandardPaths::AppLocalDataLocation);
  foreach (const QString& dirStr, stdPaths) {
    QString path = dirStr + "/data";
    dirs << path; // we'll check if these exist below
  }

  // add in paths relative to the binary (e.g. for development)
  dirs << QCoreApplication::applicationDirPath() + "/../" +
            QtGui::Utilities::dataDirectory() + "/avogadro2";

#ifdef Q_WS_X11
  dirs << QString(INSTALL_PREFIX) + "/share/avogadro2/";
#else
  // Mac and Windows use relative path from application location
  dirs << QCoreApplication::applicationDirPath() + "/../share/avogadro2";
#endif

  QString m_directory;
  QDir dir;

  foreach (const QString& dirStr, dirs) {
    qDebug() << "Checking for " << directory << " data in" << dirStr;
    QDir dir(dirStr + '/' + directory);
    if (dir.exists() && dir.isReadable()) {
      m_directory = dir.absolutePath();
      break;
    }
  }

  if (m_directory.isEmpty()) {
    // Can't really do anything!
    m_ui->directoryTreeView->setEnabled(false);
    m_ui->insertFragmentButton->setEnabled(false);
    m_ui->filterLineEdit->setEnabled(false);

    return;
  }

  m_implementation->model = new QFileSystemModel(this);
  m_implementation->model->setReadOnly(true);
  QModelIndex rootIndex = m_implementation->model->setRootPath(m_directory);

  m_implementation->proxy = new SortFilterTreeProxyModel(this);
  m_implementation->proxy->setSourceModel(m_implementation->model);
  m_implementation->proxy->setSortLocaleAware(true); // important for files
  // map from the root path to the proxy index
  m_implementation->proxyRoot =
    m_implementation->proxy->mapFromSource(rootIndex);
  // Our custom class needs this to prevent becoming rootless
  m_implementation->proxy->setSourceRoot(rootIndex);

  m_ui->directoryTreeView->setModel(m_implementation->proxy);
  // remember to map from the source to the proxy index
  m_ui->directoryTreeView->setRootIndex(m_implementation->proxyRoot);

  // hide everything but the filename
  for (int i = 1; i < m_implementation->model->columnCount(); ++i)
    m_ui->directoryTreeView->hideColumn(i);

  m_ui->directoryTreeView->setSelectionMode(QAbstractItemView::SingleSelection);
  m_ui->directoryTreeView->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->directoryTreeView->setUniformRowHeights(true);

  connect(m_ui->insertFragmentButton, SIGNAL(clicked(bool)), this,
          SLOT(activated()));

  connect(m_ui->directoryTreeView, SIGNAL(doubleClicked(const QModelIndex)),
          this, SLOT(activated()));

  connect(m_ui->directoryTreeView, SIGNAL(activated(const QModelIndex)), this,
          SLOT(activated()));

  connect(m_ui->filterLineEdit, SIGNAL(textChanged(const QString&)), this,
          SLOT(filterTextChanged(const QString&)));
}

InsertFragmentDialog::~InsertFragmentDialog()
{
  delete m_ui;
  delete m_implementation;
}

const QString InsertFragmentDialog::fileName()
{
  if (m_implementation == nullptr || m_implementation->model == nullptr)
    return QString();

  // The selected model index is in the proxy
  QModelIndexList selected =
    m_ui->directoryTreeView->selectionModel()->selectedIndexes();

  if (selected.isEmpty()) {
    return QString();
  }

  // Remember to map to the source model
  return selected.first().data(QFileSystemModel::FilePathRole).toString();
}

void InsertFragmentDialog::refresh()
{
  m_ui->directoryTreeView->update();
}

void InsertFragmentDialog::filterTextChanged(const QString& newFilter)
{
  if (!m_implementation || !m_implementation->proxy)
    return; // no dialog or proxy model to set

  // Allow things like "ti" to match "Ti" etc.
  QRegExp reg(newFilter, Qt::CaseInsensitive, QRegExp::WildcardUnix);
  m_implementation->proxy->setFilterRegExp(reg);

  if (!newFilter.isEmpty()) {
    // user interface niceness -- show any file match
    m_ui->directoryTreeView->expandToDepth(2);
  }
}

void InsertFragmentDialog::activated()
{
  QString currentFileName = fileName();

  // check to see if it's an actual file and not a directory
  if (currentFileName.isEmpty() || !QFileInfo(currentFileName).isFile()) {
    return;
  }

  emit performInsert(currentFileName, m_implementation->crystalFiles);
}

} // namespace QtPlugins
} // namespace Avogadro
