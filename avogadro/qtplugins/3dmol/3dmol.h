#ifndef AVOGADRO_QTPLUGINS_ThreeDMOL_H
#define AVOGADRO_QTPLUGINS_ThreeDMOL_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {
class ThreeDMolDialog;

/**
 * @brief The ThreeDMol class is an extension to launch
 * a ThreeDMolDialog.
 */
class ThreeDMol : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ThreeDMol(QObject *parent_ = 0);
  ~ThreeDMol();

  QString name() const { return tr("ThreeDMol"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction *) const;

public slots:
  void setMolecule(QtGui::Molecule *mol);

private slots:
  void showDialog();

private:
  QAction *m_action;
  ThreeDMolDialog *m_dialog;
  QtGui::Molecule *m_molecule;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ThreeDMOLEXTENSION_H
