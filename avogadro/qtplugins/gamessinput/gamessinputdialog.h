/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef GAMESSINPUTDIALOG_H
#define GAMESSINPUTDIALOG_H

#include <QButtonGroup>
#include <QDialog>
#include <QModelIndex>

#include "ui_gamessinputdialog.h"

#include <QtCore/QSettings>

class QJsonObject;

namespace Avogadro {
namespace MoleQueue {
class JobObject;
}
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
class GamessHighlighter;

class GamessInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit GamessInputDialog(QWidget* parent_ = nullptr,
                             Qt::WindowFlags f = {});
  ~GamessInputDialog() override;

  void setMolecule(QtGui::Molecule* mol);

signals:
  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const Avogadro::MoleQueue::JobObject& job);

protected:
  void showEvent(QShowEvent* e) override;

private slots:
  void updatePreviewText();

  void defaultsClicked();
  void resetClicked();
  void generateClicked();
  void computeClicked();

  void updateTitlePlaceholder();

private:
  void connectBasic();
  void connectPreview();
  void connectButtons();

  void buildOptions();
  void updateOptionCache();
  void restoreOptionCache();

  void buildCalculateOptions();
  void buildTheoryOptions();
  void buildBasisOptions();
  void buildStateOptions();
  void buildDispersionCorrectionOptions();
  void buildMultiplicityOptions();
  void buildChargeOptions();

  void setBasicDefaults();

  QString generateJobTitle() const;

  Ui::GamessInputDialog ui;
  QtGui::Molecule* m_molecule;
  GamessHighlighter* m_highlighter;

  bool m_updatePending;
  QMap<QComboBox*, int> m_optionCache;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // GAMESSINPUTDIALOG_H
