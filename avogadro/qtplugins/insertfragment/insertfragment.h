/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_INSERTFRAGMENT_H
#define AVOGADRO_QTPLUGINS_INSERTFRAGMENT_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>

#include <string>

namespace Avogadro {
namespace Io {
class FileFormat;
}
namespace QtGui {
class InsertFragmentDialog;
}

namespace QtPlugins {

/**
 * @brief Load molecules through a tree browser.
 */
class InsertFragment : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit InsertFragment(QObject* parent_ = nullptr);
  ~InsertFragment() override;

  QString name() const override { return tr("InsertFragment"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule*) override;

private slots:
  void showDialog();
  void performInsert(const QString& fileName, bool crystal);

private:
  QList<QAction*> m_actions;
  QtGui::InsertFragmentDialog* m_moleculeDialog;
  QtGui::InsertFragmentDialog* m_crystalDialog;
  /// Maps identifier to extension:
  QMap<QString, std::string> m_formats;

  QtGui::Molecule* m_molecule;
  Io::FileFormat* m_reader;
};

inline QString InsertFragment::description() const
{
  return tr("Insert molecular fragments for building larger molecules.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_INSERTFRAGMENT_H
