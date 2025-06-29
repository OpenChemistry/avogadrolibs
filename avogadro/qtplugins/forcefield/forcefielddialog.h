/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FORCEFIELDDIALOG_H
#define AVOGADRO_QTPLUGINS_FORCEFIELDDIALOG_H

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class ForceFieldDialog;
}

/**
 * @brief The ForceFieldDialog class is used to prompt the user for parameters
 * to be used in a force field optimization.
 */
class ForceFieldDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * Construct a new dialog using the forcefields in @a forceFields.
   */
  explicit ForceFieldDialog(const QStringList& forceFields,
                            QWidget* parent_ = 0);
  ~ForceFieldDialog() override;

  /**
   * Construct a new dialog using the forcefields in @a forceFields and
   * initialize the options to those in @a startingOptions (see setOptions).
   * If the user chooses the recommended force field, @a recommendedForceField_
   * will be set. This is useful for preferring a specific force field for a
   * particular molecule.
   * When the user closes the dialog, the options they selected are returned. If
   * the user cancels the dialog, an empty list is returned.
   */
  static QVariantMap prompt(QWidget* parent_, const QStringList& forceFields,
                            const QVariantMap& startingOptions,
                            const QString& recommendedForceField_ = QString());

  /**
   * Get/set the options displayed in the dialog.
   */
  QVariantMap options() const;
  void setOptions(const QVariantMap& opts);

  /**
   * Get/set the recommended forcefield for the current molecule. If an empty
   * string, the user will not be shown an option to use the recommended
   * forcefield.
   * If the string is non-empty (and in the forceFields list passed in the
   * constructor), the user will have the option of setting the forcefield to
   * this value.
   *
   * @{
   */
  QString recommendedForceField() const { return m_recommendedForceField; }
  void setRecommendedForceField(const QString& rff);
  /**@}*/

private slots:
  void useRecommendedForceFieldToggled(bool state);

private:
  void updateRecommendedForceField();

  Ui::ForceFieldDialog* ui;
  QString m_recommendedForceField;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_FORCEFIELDDIALOG_H
