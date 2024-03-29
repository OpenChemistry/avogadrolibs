/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LINEFORMATINPUT_H
#define AVOGADRO_QTPLUGINS_LINEFORMATINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>

#include <string>

namespace Avogadro {
namespace Io {
class FileFormat;
}
namespace QtPlugins {

/**
 * @brief Load single-line molecule descriptors through an input dialog.
 */
class LineFormatInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit LineFormatInput(QObject* parent_ = nullptr);
  ~LineFormatInput() override;

  QString name() const override { return tr("LineFormatInput"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule*) override;

private slots:
  void showDialog();

private:
  QList<QAction*> m_actions;
  /// Maps identifier to extension:
  QMap<QString, std::string> m_formats;

  QtGui::Molecule* m_molecule;
  Io::FileFormat* m_reader;
  std::string m_descriptor;
};

inline QString LineFormatInput::description() const
{
  return tr("Load single-line molecule descriptors through an input dialog.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LINEFORMATINPUT_H
