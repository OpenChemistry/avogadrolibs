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

#ifndef AVOGADRO_QTPLUGINS_SPACEGROUPDIALOG_H
#define AVOGADRO_QTPLUGINS_SPACEGROUPDIALOG_H

#include <QtWidgets/QDialog>
#include <QStandardItemModel>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/unitcell.h>

class QPlainTextEdit;

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SpaceGroupDialog;
//class SpaceGroupModel;
}

/**
 * @brief The SpaceGroupDialog class provides a dialog for editing a molecule's
 * unit cell.
 */
class SpaceGroupDialog : public QDialog
{
  Q_OBJECT

public:

  explicit SpaceGroupDialog(QWidget *parent = 0);
  ~SpaceGroupDialog() AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *molecule);

public slots:
  void moleculeChanged(unsigned int changes);

  void apply();
  void revert();

private:
  bool isCrystal() const;


  void enableApply(bool e);
  void enableRevert(bool e);


private:
  Ui::SpaceGroupDialog *m_ui;
  QtGui::Molecule *m_molecule;
  Core::UnitCell m_tempCell;
  QStandardItemModel* setSpaceGroups(QObject* parent);
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SPACEGROUPDIALOG_H
