/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPACEGROUP_H
#define AVOGADRO_QTPLUGINS_SPACEGROUP_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Space group features for crystals.
 */
class SpaceGroup : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit SpaceGroup(QObject* parent_ = nullptr);
  ~SpaceGroup() override;

  QString name() const override { return tr("SpaceGroup"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  void registerCommands() override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void perceiveSpaceGroup();
  void reduceToPrimitive();
  void conventionalizeCell();
  void symmetrize();
  void fillUnitCell();
  void fillTranslationalCell();
  void reduceToAsymmetricUnit();
  void setTolerance();

private:
  // Where a request to fill the cell comes from. Only a menu action, or an
  // automatic fill when a user is there to answer, may ask questions; a
  // command, and an automatic fill in a scripted session, must not block on a
  // dialog.
  enum class FillSource
  {
    Menu,      // the user chose the action
    Heuristic, // automatically, after a crystal was loaded
    Command    // a script or RPC command
  };

  // Fill the cell using the given Hall number, or the one of the molecule if
  // it is 0. Returns false if nothing was done; for commands, errorMessage
  // then says why.
  bool performFill(bool allCopies, FillSource source,
                   unsigned short requestedHall = 0,
                   QString* errorMessage = nullptr);

  // Pop up a dialog box and ask the user to select a space group.
  // Returns the hall number for the selected space group.
  // Returns 0 if the user canceled.
  // If the international table number is known (but not the setting), only
  // the settings of that number are shown at first.
  unsigned short selectSpaceGroup(unsigned short internationalNumber = 0);

  // Check if the cell appears to be primitive but the space group expects
  // a centered cell. Warns the user and optionally conventionalizes.
  // Returns true if we should proceed with filling, false if user canceled.
  // Asks the user only if @p mayPrompt. Without one, a command goes ahead
  // and an automatic fill does not.
  bool checkPrimitiveCell(unsigned short hallNumber, bool mayPrompt,
                          FillSource source);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  double m_spgTol;

  QAction* m_perceiveSpaceGroupAction;
  QAction* m_reduceToPrimitiveAction;
  QAction* m_conventionalizeCellAction;
  QAction* m_symmetrizeAction;
  QAction* m_fillUnitCellAction;
  QAction* m_fillTranslationalCellAction;
  QAction* m_reduceToAsymmetricUnitAction;
  QAction* m_setToleranceAction;

  bool m_blockFillHeuristic = false;

  const QString crystalSystem(unsigned short hallNumber);
  const QString toleranceToString();
  const QString symbolToString(unsigned short hallNumber,
                               bool replaceOverlines = false);
  const QString hallSymbolToString(unsigned short hallNumber);

  void fillHeuristic();
};

inline QString SpaceGroup::description() const
{
  return tr("Space group features for crystals.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SPACEGROUP_H
