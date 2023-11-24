/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H
#define AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H

#include <QtWidgets/QDialog>

// Forward declarations
class QAbstractButton;
class QKeyEvent;
class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class MolecularPropertiesDialog;
}

/**
 * @class MolecularPropertiesDialog molecularpropertiesdialog.h
 * <avogadrolibs/qtgui/molecularpropertiesdialog.h>
 * @brief The MolecularPropertiesDialog class provides a dialog which displays
 * basic molecular properties.
 * @author Allison Vacanti
 *
 */
class MolecularPropertiesDialog : public QDialog
{
  Q_OBJECT

public:
  explicit MolecularPropertiesDialog(QtGui::Molecule* mol,
                                     QWidget* parent_ = nullptr);
  ~MolecularPropertiesDialog() override;

  QtGui::Molecule* molecule() { return m_molecule; }

protected:
  void keyPressEvent(QKeyEvent *event) override;

public slots:
  void setMolecule(QtGui::Molecule* mol);
  void buttonClicked(QAbstractButton *button);

private slots:
  void updateName();
  void updateLabels();
  void updateMassLabel();
  void updateFormulaLabel();
  void moleculeDestroyed();
  void replyFinished(QNetworkReply*);
  void copy();

private:
  QtGui::Molecule* m_molecule;
  Ui::MolecularPropertiesDialog* m_ui;

  QString m_name;
  QNetworkAccessManager *m_network;
  bool m_nameRequestPending;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H
