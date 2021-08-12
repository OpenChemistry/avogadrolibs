/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_APPLYCOLORS_H
#define AVOGADRO_QTPLUGINS_APPLYCOLORS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtGui/QColor>

class QColorDialog;
namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The ApplyColors class is an extension to modify apply custom colors.
 */
class ApplyColors : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ApplyColors(QObject* parent_ = nullptr);
  ~ApplyColors() override;

  QString name() const override { return tr("ApplyColors"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void openColorDialog();
  void applyCustomColor(const QColor& color);
  void applyDistanceColors();
  void applyIndexColors();
  void resetColors();

  void openColorDialogResidue();
  void applyCustomColorResidue(const QColor& color);
  void applyAminoColors();
  void applyShapelyColors();
  void applySecondaryStructureColors();
  void resetColorsResidue();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  QColorDialog* m_dialog;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_APPLYCOLORS_H
