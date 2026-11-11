/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "copyasdialog.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro::QtPlugins {

namespace {
const Io::FileFormat::Operations stringWriter =
  Io::FileFormat::Write | Io::FileFormat::String;
}

CopyAsDialog::CopyAsDialog(const std::vector<CopyAsFormat>& formats,
                           const QString& preselect, QWidget* parent_)
  : QDialog(parent_), m_list(new QListWidget(this))
{
  setWindowTitle(tr("Copy As"));

  auto* layout = new QVBoxLayout(this);
  auto* label = new QLabel(tr("Copy the molecule (or the selected atoms) to "
                              "the clipboard as text in this format:"),
                           this);
  label->setWordWrap(true);
  label->setBuddy(m_list);
  layout->addWidget(label);

  m_list->setAccessibleName(tr("Clipboard format"));
  int current = 0;
  for (size_t i = 0; i < formats.size(); ++i) {
    m_list->addItem(formats[i].label);
    if (formats[i].label == preselect)
      current = static_cast<int>(i);
  }
  if (m_list->count() > 0)
    m_list->setCurrentRow(current);
  layout->addWidget(m_list);

  auto* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  connect(m_list, &QListWidget::itemDoubleClicked, this, &QDialog::accept);
  layout->addWidget(buttons);
}

int CopyAsDialog::selectedIndex() const
{
  return m_list->currentRow();
}

std::unique_ptr<Io::FileFormat> CopyAsDialog::createFormat(
  const CopyAsFormat& format)
{
  const Io::FileFormatManager& manager = Io::FileFormatManager::instance();
  std::unique_ptr<Io::FileFormat> result;
  if (!format.identifier.empty())
    result.reset(
      manager.newFormatFromIdentifier(format.identifier, stringWriter));
  if (!result && !format.extension.empty())
    result.reset(
      manager.newFormatFromFileExtension(format.extension, stringWriter));
  return result;
}

std::vector<CopyAsFormat> CopyAsDialog::availableFormats()
{
  // Names are format names, so they are not translated. PDB has no built-in
  // writer: it comes from Open Babel when that is installed, and InChI always
  // does, hence the extension fallbacks.
  const std::vector<CopyAsFormat> candidates = {
    { "MDL MOL (V2000)", "Avogadro: MDL", "" },
    { "MDL MOL (V3000)", "Avogadro: MDL V3000", "" },
    { "SDF (V2000)", "Avogadro: SDF", "" },
    { "SDF (V3000)", "Avogadro: SDF V3000", "" },
    { "CML", "Avogadro: CML", "cml" },
    { "CJSON", "Avogadro: CJSON", "cjson" },
    { "PDB", "Avogadro: PDB", "pdb" },
    { "XYZ", "Avogadro: XYZ", "xyz" },
    { "SMILES", "Avogadro: SMILES", "smi" },
    { "InChI", "", "inchi" },
  };

  std::vector<CopyAsFormat> result;
  for (const CopyAsFormat& candidate : candidates)
    if (createFormat(candidate))
      result.push_back(candidate);
  return result;
}

} // namespace Avogadro::QtPlugins
