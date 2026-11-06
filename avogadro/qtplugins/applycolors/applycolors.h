/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_APPLYCOLORS_H
#define AVOGADRO_QTPLUGINS_APPLYCOLORS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <tinycolormap.hpp>

#include <QtGui/QColor>

#include <string>

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

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  void registerCommands() override;

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
  /// Apply colormap to atoms by atomic index without GUI dialogs.
  void applyIndexColors(tinycolormap::ColormapType type);

  /// Apply colormap to atoms by 3D distance from first atom without GUI
  /// dialogs.
  void applyDistanceColors(tinycolormap::ColormapType type);

  /// Apply colormap to atoms by partial charge for the specified model without
  /// GUI dialogs. Returns false and sets error message if partial charges
  /// cannot be computed.
  bool applyChargeColors(const std::string& model,
                         tinycolormap::ColormapType type, QString& error);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  QColorDialog* m_dialog;

  tinycolormap::ColormapType getColormapFromString(const QString& name) const;

  /// Look up a colormap enum from its name (case-insensitive and normalized).
  /// If unmatched and suggestion is non-null, suggests the closest colormap
  /// name if within edit distance.
  static bool colormapFromString(const QString& name,
                                 tinycolormap::ColormapType& type,
                                 QString* suggestion = nullptr);
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_APPLYCOLORS_H
