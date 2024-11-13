/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_APPLYCOLORS_H
#define AVOGADRO_QTPLUGINS_APPLYCOLORS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <tinycolormap.hpp>

#include <QtGui/QColor>

class QColorDialog;

namespace Avogadro::QtPlugins {

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

  void applyChargeColors();

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

  tinycolormap::ColormapType getColormapFromString(const QString& name) const;

};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_APPLYCOLORS_H
