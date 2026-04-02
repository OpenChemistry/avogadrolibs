/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTPOLYMERDIALOG_H
#define AVOGADRO_QTPLUGINS_INSERTPOLYMERDIALOG_H

#include <QtWidgets/QDialog>

class QSortFilterProxyModel;
class QFileSystemModel;

namespace Ui {
class InsertPolymerDialog;
}

namespace Avogadro {
namespace QtPlugins {

class InsertPolymerDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InsertPolymerDialog(QWidget* parent = nullptr);
  ~InsertPolymerDialog() override;

signals:
  void buildPolymer(const QString& smiles);

private slots:
  void chooseMonomerA();
  void chooseMonomerB();
  void chooseMonomerC();
  void validateMonomerRepeats();
  void build();

private:
  // Resolve the path to fragments/polymers/ data directory
  QString resolvePolymerDirectory() const;

  // Open a monomer chooser dialog and return the selected file path
  QString chooseMonomerFile();

  // Load a monomer from a .smi file, updating name/smiles/graphic widgets
  void loadMonomer(const QString& filePath, int slot);

  // Assemble the full polymer SMILES from monomer SMILES and settings
  QString assemblePolymerSmiles() const;

  // Clean trailing bond characters from a concatenation-style SMILES
  static QString cleanSmiles(const QString& smiles);

  // Check if a monomer SMILES uses * attachment points
  static bool usesAttachmentPoints(const QString& smiles);

  // Get the monomer SMILES for a given slot (0=A, 1=B, 2=C)
  QString monomerSmiles(int slot) const;

  ::Ui::InsertPolymerDialog* m_ui;
  QString m_polymerDirectory;
  QString m_smilesA;
  QString m_smilesB;
  QString m_smilesC;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INSERTPOLYMERDIALOG_H
