/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_QTPLUGINS_COLOROPACITYMAP_H
#define AVOGADRO_QTPLUGINS_COLOROPACITYMAP_H

#include <avogadro/qtgui/extensionplugin.h>

class QStringList;

namespace Avogadro {
class HistogramWidget;
namespace QtPlugins {
class ComDialog;
/**
 * @brief An interactive color opacity map editor with a value population
 * histogram.
 */
class ColorOpacityMap : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ColorOpacityMap(QObject* parent_ = nullptr);
  ~ColorOpacityMap();

  QString name() const { return tr("ColorOpacityMap"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void updateHistogram();

  void displayDialog();

  void render();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;

  ComDialog* m_comDialog = nullptr;
  HistogramWidget* m_histogramWidget = nullptr;
  QScopedPointer<QAction> m_displayDialogAction;

  QWidget* m_activeWidget = nullptr;
};

inline QString ColorOpacityMap::description() const
{
  return tr("Edit color opacity maps, primarily for volume rendering.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COLOROPACITYMAP_H
