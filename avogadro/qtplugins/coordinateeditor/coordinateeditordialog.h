/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_COORDINATEEDITORDIALOG_H
#define AVOGADRO_QTPLUGINS_COORDINATEEDITORDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class CoordinateEditorDialog;
}

/**
 * @brief The CoordinateEditorDialog class implements a free-text coordinate
 * editor.
 */
class CoordinateEditorDialog : public QDialog
{
  Q_OBJECT
public:
  explicit CoordinateEditorDialog(QWidget* parent_ = nullptr);
  ~CoordinateEditorDialog() override;

  void setMolecule(QtGui::Molecule* mol);

signals:
  void validationFinished(bool valid);
  void pastedMolecule();

private slots:
  void moleculeChanged(uint);
  void presetChanged(int);
  void specChanged();
  void specEdited();
  void updateText();

  void helpClicked();

  void validateInput();
  void validateInputWorker();

  void cutClicked();
  void copyClicked();
  void pasteClicked();
  void revertClicked();
  void clearClicked();

  void applyClicked();
  void applyFinish(bool valid);

  void textModified(bool modified);

private:
  void buildPresets();

  // Enable/disable input validation when the text edit is modified.
  void listenForTextEditChanges(bool enable);

  QString detectInputFormat() const;

  Ui::CoordinateEditorDialog* m_ui;
  QtGui::Molecule* m_molecule;

  // State storage for validateInput methods. PIMPL'd for organization.
  class ValidateStorage;
  ValidateStorage* m_validate;

  QString m_defaultSpec;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_COORDINATEEDITORDIALOG_H
