/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTDNA_H
#define AVOGADRO_QTPLUGINS_INSERTDNA_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>

#include <string>

namespace Avogadro {
namespace Io {
class FileFormat;
}
namespace QtPlugins {

class InsertDNADialog;

/**
 * @brief Load single-line molecule descriptors through an input dialog.
 */
class InsertDna : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit InsertDna(QObject* parent_ = nullptr);
  ~InsertDna() override;

  QString name() const override { return tr("InsertDNA"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule*) override;

private slots:
  void showDialog();

  void performInsert();
  void updateText();
  void updateBPTurns(int type);
  void changeNucleicType(int type);

  void dialogDestroyed();

private:
  QList<QAction*> m_actions;

  QtGui::Molecule* m_molecule;
  Io::FileFormat* m_reader;
  InsertDNADialog *m_dialog;

  void constructDialog();
};

inline QString InsertDna::description() const
{
  return tr("Insert DNA / RNA fragments through a dialog.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INSERTDNA_H
