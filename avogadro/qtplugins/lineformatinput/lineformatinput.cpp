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

#include "lineformatinput.h"

#include "lineformatinputdialog.h"

#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using Avogadro::QtGui::FileFormatDialog;

namespace Avogadro {
namespace QtPlugins {

LineFormatInput::LineFormatInput(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_reader(NULL)
{
  QAction *action = new QAction(tr("Paste Molecule Descriptor..."), this);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  // These are the line formats that we can load -- key is a user-friendly name,
  // value is the file extension used to identify the file format.
  m_formats.insert(tr("InChI"), std::string("inchi"));
  m_formats.insert(tr("SMILES"), std::string("smi"));
}

LineFormatInput::~LineFormatInput()
{
  delete m_reader;
}

QList<QAction *> LineFormatInput::actions() const
{
  return m_actions;
}

QStringList LineFormatInput::menuPath(QAction *) const
{
  return QStringList() << tr("&Edit");
}

bool LineFormatInput::readMolecule(QtGui::Molecule &mol)
{
  QWidget *parentAsWidget = qobject_cast<QWidget*>(parent());
  if (!m_reader) {
    QMessageBox::warning(parentAsWidget, tr("Paste Molecule Descriptor"),
                         tr("An internal error occurred."), QMessageBox::Ok);
    return false;
  }

  QProgressDialog dlg(parentAsWidget);
  dlg.setModal(true);
  dlg.setWindowTitle(tr("Paste Molecule Descriptor"));
  dlg.setLabelText(tr("Generating 3D molecule..."));
  dlg.setRange(0, 0);
  dlg.setValue(0);
  dlg.show();
  bool success = m_reader->readString(m_descriptor, mol);
  dlg.hide();

  if (!success && !dlg.wasCanceled()) {
    QMessageBox::warning(parentAsWidget, tr("Paste Molecule Descriptor"),
                         tr("Error parsing descriptor:\n'%1'\nDescriptor: '%2'")
                         .arg(QString::fromStdString(m_reader->error()))
                         .arg(QString::fromStdString(m_descriptor)),
                         QMessageBox::Ok);
  }

  m_descriptor.clear();
  delete m_reader;
  m_reader = NULL;

  return success && !dlg.wasCanceled();
}

void LineFormatInput::showDialog()
{
  QWidget *parentAsWidget = qobject_cast<QWidget*>(parent());

  // Create a list of file formats that we can read:
  QStringList availableFormats;
  FileFormatManager &ffm = FileFormatManager::instance();
  const FileFormat::Operations ops = FileFormat::Read | FileFormat::String;
  foreach (const QString &ident, m_formats.keys()) {
    const std::string &ext = m_formats[ident];
    if (!ffm.fileFormatsFromFileExtension(ext, ops).empty())
      availableFormats.push_back(ident);
  }

  if (availableFormats.empty()) {
    QMessageBox::information(parentAsWidget, tr("No descriptors found!"),
                             tr("No line format readers found!"),
                             QMessageBox::Ok);
    return;
  }

  // Prompt user for input:
  LineFormatInputDialog dlg;
  dlg.setFormats(availableFormats);
  dlg.exec();

  // Resolve any format conflicts:
  const std::string &ext = m_formats[dlg.format()];

  const FileFormat *fmt = FileFormatDialog::findFileFormat(
        parentAsWidget, tr("Paste Molecular Descriptor"),
        QString("file.%1").arg(QString::fromStdString(ext)), ops);

  if (fmt == NULL) {
    QMessageBox::information(parentAsWidget, tr("No descriptors found!"),
                             tr("Unable to load requested format reader."),
                             QMessageBox::Ok);
    return;
  }

  // Let the application know that we're ready.
  m_reader = fmt->newInstance();
  m_descriptor = dlg.descriptor().toStdString();
  emit moleculeReady(1);
}

} // namespace QtPlugins
} // namespace Avogadro
