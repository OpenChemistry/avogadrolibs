/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTPEPTIDE_H
#define AVOGADRO_QTPLUGINS_INSERTPEPTIDE_H

#include <avogadro/core/internalcoordinates.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace QtPlugins {

class InsertPeptideDialog;

// Used to store the amino acids as they are built
struct AminoAcid
{
  std::vector<unsigned char> atomicNumbers;
  std::vector<std::string> atomNames;
  std::vector<Avogadro::Core::InternalCoordinate> internalCoords;
};

/**
 * @brief Insert oligopeptide sequences
 */
class InsertPeptide : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit InsertPeptide(QObject* parent_ = nullptr);
  ~InsertPeptide() override;

  QString name() const override { return tr("InsertPeptide"); }
  QString description() const override
  {
    return tr("Insert oligopeptide sequences.");
  }
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule*) override;

private slots:
  void showDialog();
  void performInsert();
  void updateText();
  void setStructureType(int);

private:
  AminoAcid readAminoAcid(const QString& threeLetterCode);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  InsertPeptideDialog* m_dialog;
  QString m_directory; // directory to amino acid fragments
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INSERTPEPTIDE_H
