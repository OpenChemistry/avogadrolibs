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
#include <avogadro/qtgui/rwmolecule.h>

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

LineFormatInput::LineFormatInput(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_reader(nullptr),
    m_molecule(nullptr)
{
  QAction* action = new QAction(tr("SMILES..."), this);
  action->setData("SMILES");
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(tr("InChI..."), this);
  action->setData("InChI");
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

QList<QAction*> LineFormatInput::actions() const
{
  return m_actions;
}

QStringList LineFormatInput::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("&Insert");
}

void LineFormatInput::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void LineFormatInput::showDialog()
{
  if (!m_molecule)
    return;

  QWidget* parentAsWidget = qobject_cast<QWidget*>(parent());
  QAction* theSender = qobject_cast<QAction*>(sender());

  // Create a list of file formats that we can read:
  QStringList availableFormats;
  FileFormatManager& ffm = FileFormatManager::instance();
  const FileFormat::Operations ops = FileFormat::Read | FileFormat::String;
  foreach (const QString& ident, m_formats.keys()) {
    const std::string& ext = m_formats[ident];
    if (!ffm.fileFormatsFromFileExtension(ext, ops).empty())
      availableFormats.push_back(ident);
  }

  if (availableFormats.empty()) {
    QMessageBox::warning(parentAsWidget, tr("No descriptors found!"),
                         tr("No line format readers found!"), QMessageBox::Ok);
    return;
  }

  // Prompt user for input:
  LineFormatInputDialog dlg;
  dlg.setFormats(availableFormats);
  if (theSender != nullptr)
    dlg.setCurrentFormat(theSender->data().toString());
  dlg.exec();

  // check if the reply is empty
  if (dlg.descriptor().isEmpty())
    return; // nothing to do

  // Resolve any format conflicts:
  const std::string& ext = m_formats[dlg.format()];

  const FileFormat* fmt = FileFormatDialog::findFileFormat(
    parentAsWidget, tr("Insert Molecule..."),
    QString("file.%1").arg(QString::fromStdString(ext)), ops);

  if (fmt == nullptr) {
    QMessageBox::warning(parentAsWidget, tr("No descriptors found!"),
                         tr("Unable to load requested format reader."),
                         QMessageBox::Ok);
    return;
  }

  m_reader = fmt->newInstance();
  m_descriptor = dlg.descriptor().toStdString();

  QProgressDialog progDlg(parentAsWidget);
  progDlg.setModal(true);
  progDlg.setWindowTitle(tr("Insert Molecule..."));
  progDlg.setLabelText(tr("Generating 3D molecule..."));
  progDlg.setRange(0, 0);
  progDlg.setValue(0);
  progDlg.show();

  QtGui::Molecule newMol;
  bool success = m_reader->readString(m_descriptor, newMol);
  m_molecule->undoMolecule()->appendMolecule(newMol, "Insert Molecule");
  emit requestActiveTool("Manipulator");
  dlg.hide();

  m_descriptor.clear();
  delete m_reader;
  m_reader = nullptr;
}

} // namespace QtPlugins
} // namespace Avogadro
