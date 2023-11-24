/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_APBS_APBSOUTPUTDIALOG_H
#define AVOGADRO_QTPLUGINS_APBS_APBSOUTPUTDIALOG_H

#include <QDialog>

namespace Ui {
class ApbsOutputDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Dialog indicating a successful run of APBS.
 *
 * The ApbsOutputDialog class is used to tell the user that the run of APBS
 * was successful. It allows the user to select which of the input and output
 * files to load.
 */
class ApbsOutputDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * Constructor for ApbsOutputDialog.
   */
  ApbsOutputDialog(QWidget* parent_ = nullptr);

  /**
   * Destructor for ApbsOutputDialog.
   */
  ~ApbsOutputDialog() override;

  /**
   * Returns true if the user checked the 'Load Structure' check box.
   */
  bool loadStructureFile() const;

  /**
   * Returns true if the user checked the 'Load Cube' check box.
   */
  bool loadCubeFile() const;

private:
  Ui::ApbsOutputDialog* m_ui;
};
}
}

#endif // AVOGADRO_QTPLUGINS_APBS_APBSOUTPUTDIALOG_H
