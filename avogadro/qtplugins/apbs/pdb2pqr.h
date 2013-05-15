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

#ifndef AVOGADRO_QTPLUGINS_APBS_PDB2PQR_H
#define AVOGADRO_QTPLUGINS_APBS_PDB2PQR_H

#include <QDialog>

namespace Ui {
class Pdb2Pqr;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @class Pdb2Pqr pdb2pqr.h <avogadro/qtplugins/apbs/pdb2pqr.h>
 * @brief GUI for running pdb2pqr input generator for APBS.
 */
class Pdb2Pqr : public QDialog
{
  Q_OBJECT

public:
  /**
   * Constructor for Pdb2Pqr.
   */
  Pdb2Pqr(QWidget *parent_ = 0);

  /**
   * Destructor for Pdb2Pqr.
   */
  ~Pdb2Pqr();

  /**
   * @return String describing the last error that occured.
   */
  QString errorString() const;

private slots:
  /**
   * Called when the user clicks run. This propts for an output
   * file name and then calls pdb2pqr through QProcess.
   */
  void onRunClicked();

  /**
   * Called when the user clicks on the button next to the input
   * file name line edit. Prompts the user for an input file name.
   */
  void onOpenInputFile();

private:
  Ui::Pdb2Pqr *m_ui;
  QString m_errorString;
};

}
}

#endif
