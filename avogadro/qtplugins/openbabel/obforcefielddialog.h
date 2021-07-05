/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H
#define AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class OBForceFieldDialog;
}

/**
 * @brief The OBForceFieldDialog class is used to prompt the user for parameters
 * to be used in an OpenBabel force field optimization.
 */
class OBForceFieldDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * Construct a new dialog using the forcefields in @a forceFields.
   */
  explicit OBForceFieldDialog(const QStringList& forceFields,
                              QWidget* parent_ = nullptr);
  ~OBForceFieldDialog() override;

  /**
   * Construct a new dialog using the forcefields in @a forceFields and
   * initialize the options to those in @a startingOptions (see setOptions).
   * If the user chooses the recommended force field, @a recommendedForceField_
   * will be set. This is useful for preferring a specific force field for a
   * particular molecule.
   * When the user closes the dialog, the options they selected are returned. If
   * the user cancels the dialog, an empty list is returned.
   */
  static QStringList prompt(QWidget* parent_, const QStringList& forceFields,
                            const QStringList& startingOptions,
                            const QString& recommendedForceField_ = QString());

  /**
   * Get/set the options displayed in the dialog. The option format is a list of
   * strings that may be used directly as arguments in a call to
   * QProcess::start, with the exception of the `-i<input format>`,
   * `-o<output format>` and `--minimize` options, which are not used by this
   * class. See `obabel -L minimize` for a complete listing of available
   * options.
   *
   * Each option (and argument, if applicable) must be a separate string in the
   * list. For instance, to refer to the options in the call:
@code
obabel -icml -ocml --minimize --log --crit 1e-05 --ff Ghemical --sd"
@endcode
   *
   * The option list should contain, in order:
   * - `--crit`
   * - `1e-05`
   * - `--ff`
   * - `Ghemical`
   * - `--sd`
   *
   * @note The `--log` option is always added in the list returned by
   * options, and is ignored by the setOptions method.
   *
   * @{
   */
  QStringList options() const;
  void setOptions(const QStringList& opts);
  /**@}*/

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

  Ui::OBForceFieldDialog* ui;
  QString m_recommendedForceField;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H
