/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "importcrystaldialog.h"
#include "ui_importcrystaldialog.h"

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <QDebug>

#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>

#include <QtGui/QClipboard>

using std::string;

namespace Avogadro::QtPlugins {

ImportCrystalDialog::ImportCrystalDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::ImportCrystalDialog)
{
  m_ui->setupUi(this);
}

ImportCrystalDialog::~ImportCrystalDialog()
{
  delete m_ui;
}

bool ImportCrystalDialog::importCrystalClipboard(Avogadro::Core::Molecule& mol)
{
  QString text = QApplication::clipboard()->text();
  m_ui->edit_text->setText(text);
  // If the user rejected, just return false
  if (this->exec() == QDialog::Rejected)
    return false;

  // Use POSCAR format by default. If the extension was set, use that instead
  std::string ext = m_ui->edit_extension->text().toStdString();
  if (ext.empty())
    ext = "POSCAR";

  // Update the text
  text = m_ui->edit_text->toPlainText();
  std::stringstream s(text.toStdString());

  if (Io::FileFormatManager::instance().readString(mol, s.str(), ext))
    return true;

  // Print out the error messages from the read if we failed
  if (!Io::FileFormatManager::instance().error().empty()) {
    qDebug() << "FileFormatManager error message:"
             << QString::fromStdString(
                  Io::FileFormatManager::instance().error());
  }

  displayInvalidFormatMessage();
  return false;
}

void ImportCrystalDialog::displayInvalidFormatMessage()
{
  QMessageBox::critical(
    this, tr("Cannot Parse Text"),
    tr("Failed to read the data with the supplied format."));
  reject();
  close();
}

} // namespace Avogadro::QtPlugins
