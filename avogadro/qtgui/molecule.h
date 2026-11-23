/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_MOLECULE_H
#define AVOGADRO_QTGUI_MOLECULE_H

#include "avogadroqtguiexport.h"

#include "persistentatom.h"
#include "persistentbond.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/molecule.h>

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <list>
#include <vector>

namespace Avogadro::QtGui {

class Mesh;
class RWMolecule;

/**
 * @class Molecule molecule.h <avogadro/qtgui/molecule.h>
 * @brief A QObject derived molecule object with signals/slots.
 */

class AVOGADROQTGUI_EXPORT Molecule : public QObject, public Core::Molecule
{
  Q_OBJECT

public:
  /** Typedef for Atom class. */
  using AtomType = Core::Molecule::AtomType;

  /** Typedef for PersistentAtom class. */
  using PersistentAtomType = PersistentAtom<Molecule>;

  /** Typedef for Bond class. */
  using BondType = Core::Molecule::BondType;

  /** Typedef for PersistentBond class. */
  using PersistentBondType = PersistentBond<Molecule>;

  Molecule(QObject* parent_ = nullptr);
  ~Molecule() override;
  /** copy constructor */
  Molecule(const Molecule& other);

  /** copy constructor to copy data from base instance */
  Molecule(const Core::Molecule& other);

  /** Assignment operator */
  Molecule& operator=(const Molecule& other);

  /** Assignment operator to copy data from base instance */
  Molecule& operator=(const Core::Molecule& other);

  /**
   * \enum MoleculeChange
   *Enumeration of change types that can be given.
   */
  enum MoleculeChange
  {
    /** Useful for initializing MoleculeChange variables. */
    NoChange = 0,
    /** Object types that can be changed. */
    Atoms = 1,
    Bonds = 2,
    UnitCell = 4,
    Selection = 8,
    Layers = 16,
    Properties = 32,
    Constraints = 64,
    Residues = 128,
    /** Indicates a new crystal structure (triggers space group fill). */
    NewCrystal = 256,
    /**
     * Indicates the active conformer / coordinate set changed (e.g.,
     * setCoordinate3d(int)) or the set of conformers was modified. Switching
     * the active conformer is view-state: pair with Moved (not Modified) so
     * derived data (vibrations, orbitals, meshes) survives; changing the
     * number of coordinate sets should pair with Modified.
     */
    Conformer = 512,
    /** Operations that can affect the above types. */
    Added = 1024,
    Removed = 2048,
    Modified = 4096,
    Moved = 8192,
    /**
     * Indicates atom indices were permuted (see RWMolecule::reorderAtoms).
     * Same atoms, same bonds, same counts -- only the numbering changed, so
     * listeners that detect structural change by comparing counts will miss
     * it unless they check for this flag.
     */
    Reordered = 16384,
    /**
     * Indicates the molecule's contents were replaced wholesale by a molecule
     * built elsewhere (see RWMolecule::modifyMolecule). The derived data now
     * present (vibrations, spectra, cubes, meshes, basis set, partial
     * charges) came with the replacement, so emitChanged() keeps it. Cached
     * pointers into that data are still stale: invalidatesDerivedData()
     * remains true.
     */
    Replaced = 32768
  };
  Q_DECLARE_FLAGS(MoleculeChanges, MoleculeChange)

  /**
   * @return True if @p changes leaves the cubes, meshes, basis set,
   * vibration data and partial charges derived from this molecule stale:
   * emitChanged() discards them, unless @p changes includes Replaced, in
   * which case it keeps the replacement's own data but the objects are still
   * new ones. Consumers that cache raw pointers to any of that must refresh
   * them in step with this, rather than re-deriving the rule from the flags.
   */
  static bool invalidatesDerivedData(unsigned int changes);

  /**
   * Add an atom with @p atomicNumber to the molecule.
   * @return The atom created.
   */
  AtomType addAtom(unsigned char atomicNumber) override;

  /**
   * Add an atom with @p atomicNumber and @p uniqueId to the molecule.
   * @return The atom created. This can be invalid if the unique ID was already
   * in use.
   */
  virtual AtomType addAtom(unsigned char atomicNumber, Index uniqueId);

  AtomType addAtom(unsigned char number, Vector3 position3d,
                   Index uniqueId = MaxIndex);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param index The index of the atom to be removed.
   * @return True on success, false if the atom was not found.
   */
  bool removeAtom(Index index) override;

  /**
   * @brief Remove the specified atom from the molecule.
   * @param atom The atom to be removed.
   * @return True on success, false if the atom was not found.
   * @overload
   */
  bool removeAtom(const AtomType& atom) override;

  /**
   * @brief Undo removeAtom(@p atomId), given the snapshot taken just before
   * (Core::Molecule::atomSnapshot()), and give the atom back @p uniqueId, the
   * unique id it had. The unique id of the atom that the removal moved into
   * @p atomId is moved back too.
   *
   * Use this and not the Core::Molecule overload, which leaves the unique ids
   * stale.
   * @return true on success. false, changing nothing, if the core restoration
   * refuses (see Core::Molecule::restoreAtomSnapshot()), if @p uniqueId is not
   * free (as for addAtom(), one past the last unique id is a fresh one), or if
   * the snapshot holds bonds: their unique ids are not part of it, and
   * RWMolecule removes an atom's bonds with commands of their own first.
   */
  bool restoreAtomSnapshot(Index atomId, const Core::AtomSnapshot& snapshot,
                           Index uniqueId);

  /**
   * The Core::Molecule overload, which does not know about unique ids and so
   * leaves them stale: for a molecule that is not used with RWMolecule.
   */
  using Core::Molecule::restoreAtomSnapshot;

  /**
   * @brief Get the atom referenced by the @p uniqueId, the isValid method
   * should be queried to ensure the id still referenced a valid atom.
   * @param uniqueId The unique identifier for the atom.
   * @return An Atom object, check it is valid before using it.
   */
  AtomType atomByUniqueId(Index uniqueId);

  /**
   * @brief Get the unique ID of the atom, this will uniquely reference the atom
   * as long as it exists.
   * @param atom The atom to obtain the unique ID of.
   * @return The unique identifier for the atom, MaxIndex if the atom is invalid
   * or does not belong to this molecule.
   * @{
   */
  Index atomUniqueId(const AtomType& atom) const;
  Index atomUniqueId(Index atom) const;
  /** @} */

  Core::Array<Index>& atomUniqueIds() { return m_atomUniqueIds; }

  /**
   * @brief Add a bond between the specified atoms.
   * @param a The first atom in the bond.
   * @param b The second atom in the bond.
   * @param bondOrder The order of the bond.
   * @return The bond created.
   */
  BondType addBond(const AtomType& a, const AtomType& b,
                   unsigned char bondOrder = 1) override;

  /**
   * @brief Add a bond between the specified atoms.
   * @param atomId1 The index of the first atom in the bond.
   * @param atomId2 The index of the second atom in the bond.
   * @param bondOrder The order of the bond.
   * @return The bond created.
   */
  BondType addBond(Index atomId1, Index atomId2,
                   unsigned char bondOrder = 1) override;

  void addBonds(const Core::Array<std::pair<Index, Index>>& bonds,
                const Core::Array<unsigned char>& orders);
  /**
   * @brief Add a bond between the specified atoms.
   * @param a The first atom in the bond.
   * @param b The second atom in the bond.
   * @param bondOrder The order of the bond.
   * @param uniqueId The unique ID to use for the bond.
   * @return The bond created. This can be invalid if the unique ID was already
   * in use.
   */
  virtual BondType addBond(const AtomType& a, const AtomType& b,
                           unsigned char bondOrder, Index uniqueId);

  /**
   * @brief Add a bond between the specified atoms.
   * @param atomId1 The index of the first atom in the bond.
   * @param atomId2 The index of the second atom in the bond.
   * @param bondOrder The order of the bond.
   * @param uniqueId The unique ID to use for the bond.
   * @return The bond created. This can be invalid if the unique ID was already
   * in use.
   */
  virtual BondType addBond(Index atomId1, Index atomId2,
                           unsigned char bondOrder, Index uniqueId);

  /**
   * @brief Undo removeBond(@p bondId), given the snapshot taken just before
   * (Core::Molecule::bondSnapshot()), and give the bond back @p uniqueId, the
   * unique id it had. The unique id of the bond that the removal moved into
   * @p bondId is moved back too.
   *
   * Use this and not the Core::Molecule overload, which leaves the unique ids
   * stale.
   * @return true on success. false, changing nothing, if the core restoration
   * refuses (see Core::Molecule::restoreBondSnapshot()) or if @p uniqueId is
   * not free.
   */
  bool restoreBondSnapshot(Index bondId, const Core::BondSnapshot& snapshot,
                           Index uniqueId);

  /**
   * The Core::Molecule overload, which does not know about unique ids and so
   * leaves them stale: for a molecule that is not used with RWMolecule.
   */
  using Core::Molecule::restoreBondSnapshot;

  /**
   * @brief Remove the specified bond.
   * @param index The index of the bond to be removed.
   * @return True on success, false if the bond was not found.
   */
  bool removeBond(Index index) override;

  /**
   * @brief Remove the specified bond.
   * @param bond The bond to be removed.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  bool removeBond(const BondType& bond) override;

  /**
   * @brief Remove the specified bond.
   * @param atom1 One atom in the bond.
   * @param atom2 The other atom in the bond.
   * @return True on success, false if the bond was not found.
   * @overload
   * @{
   */
  bool removeBond(const AtomType& atom1, const AtomType& atom2) override;
  bool removeBond(Index atom1, Index atom2) override;
  /** @} */

  /**
   * @brief Get the bond referenced by the @p uniqueId, the isValid method
   * should be queried to ensure the id still referenced a valid bond.
   * @param uniqueId The unique identifier for the bond.
   * @return A Bond object, check it is valid before using it.
   */
  BondType bondByUniqueId(Index uniqueId);

  /**
   * @brief Get the unique ID of the bond, this will uniquely reference the bond
   * as long as it exists.
   * @param bond The bond to obtain the unique ID of.
   * @return The unique identifier for the bond, MaxIndex if the bond is invalid
   * or does not belong to this molecule.
   * @{
   */
  Index bondUniqueId(const BondType& bond) const;
  Index bondUniqueId(Index bond) const;
  /** @} */

  Core::Array<Index>& bondUniqueIds() { return m_bondUniqueIds; }

  Index findAtomUniqueId(Index index) const;
  Index findBondUniqueId(Index index) const;

  RWMolecule* undoMolecule();

  /**
   * @brief Get the formatted chemical formula for the molecule.
   * @return The formatted chemical formula in HTML format.
   * This will include subscripts for atom counts and superscripts for charge
   * and spin multiplicity.
   */
  QString formattedFormula() const;

  bool isInteractive() const;

  void swapBond(Index a, Index b);
  void swapAtom(Index a, Index b);

  /**
   * @name Animation frames
   * A view-only set of named coordinate sequences (for example a vibration
   * cycle) that the Animation tool can step through or record. They are not
   * saved, not part of undo, and not copied with the molecule. They are
   * dropped when the structure changes (see invalidatesDerivedData()), but
   * survive plain Atoms | Moved changes.
   * @{
   */

  /**
   * Publish @p frames under @p id, replacing any earlier set with that id.
   * An empty @p frames array removes the set. The id "trajectory" is
   * reserved by the Animation tool for the molecule's own coordinate sets.
   */
  void setAnimationFrames(const QString& id, const QString& label,
                          const Core::Array<Core::Array<Vector3>>& frames);

  /** Remove the set @p id. Does nothing (and emits nothing) if unknown. */
  void removeAnimationFrames(const QString& id);

  /** @return The ids of the published sets, in the order first published. */
  QStringList animationFrameIds() const;

  /** @return The label of set @p id, or an empty string if unknown. */
  QString animationFrameLabel(const QString& id) const;

  /** @return The frames of set @p id, or an empty array if unknown. */
  Core::Array<Core::Array<Vector3>> animationFrames(const QString& id) const;

  /** @return The number of frames in set @p id, 0 if unknown. */
  size_t animationFrameCount(const QString& id) const;

  /**
   * @return Frame @p index of set @p id, without copying the whole set. Empty
   * if the set is unknown or @p index is out of range.
   */
  Core::Array<Vector3> animationFrame(const QString& id, size_t index) const;

  /**
   * Announce that @p owner is about to display its own animation frames.
   * Other animators should stop; emits animationPlaybackClaimed().
   */
  void claimAnimationPlayback(QObject* owner);

  /**
   * Put frame @p index of set @p id on screen. The first call saves the
   * current atomPositions3d() as the rest positions; then the frame replaces
   * the positions and Atoms | Moved is emitted. Nothing changes and false is
   * returned if the set is unknown, @p index is out of range, or the frame
   * does not have atomCount() positions.
   *
   * The molecule keeps this display consistent: republishing the shown set
   * re-shows the same (clamped) index, removing it restores the rest
   * positions, and a conformer change, a structural change or an edit of the
   * atoms by anyone else drops the display and leaves the new positions
   * alone. Like the frame sets, the display is not copied or saved.
   */
  bool showAnimationFrame(const QString& id, size_t index);

  /** Restore the rest positions and stop showing a frame, if one is shown. */
  void clearAnimationDisplay();

  bool isShowingAnimationFrame() const { return m_shownAnimationIndex >= 0; }

  /** @return The id of the set being shown, empty if none. */
  QString shownAnimationId() const { return m_shownAnimationId; }

  /** @return The index being shown, -1 if none. */
  int shownAnimationFrame() const { return m_shownAnimationIndex; }

  /**
   * @return The positions saved when the display started while a frame is
   * shown, otherwise atomPositions3d().
   */
  Core::Array<Vector3> restPositions3d() const;
  /** @} */

public slots:
  /**
   * @brief Force the molecule to emit the changed() signal.
   * @param change See changed().
   */
  void emitChanged(unsigned int change);

  /**
   * @brief Request an update through the update() signal
   */
  void emitUpdate() const;

signals:
  /**
   * @brief Indicates that the molecule has changed.
   * @param change Use the MoleculeChange enum to check what has changed.
   *
   * The @p change variable indicates what has changed, i.e. if
   * change & Atoms == true then atoms were changed in some way, and if
   * change & Removed == true then one or more atoms were removed.
   */
  void changed(unsigned int change) const;

  /**
   * @brief Request an update of the molecule.
   * (e.g., re-compute properties)
   */
  void update() const;

  /** The set of published animation frames changed. */
  void animationFramesChanged();

  /** @p owner started animating; other animators should stop. */
  void animationPlaybackClaimed(QObject* owner);

  /**
   * A frame started or stopped being shown, was dropped (conformer change,
   * edit), or the shown index changed.
   */
  void animationDisplayChanged();

private:
  struct AnimationFrameSet
  {
    QString id;
    QString label;
    Core::Array<Core::Array<Vector3>> frames;
  };
  // Deliberately omitted from every copy and assignment.
  std::vector<AnimationFrameSet> m_animationFrameSets;

  void clearAnimationFrames();

  // The frame being shown, if any. Deliberately omitted from every copy.
  QString m_shownAnimationId;
  int m_shownAnimationIndex = -1;
  Core::Array<Vector3> m_animationRestPositions;

  /** Forget the display without touching the positions. */
  void dropAnimationDisplay();
  /** Re-show the shown index from a freshly published set. */
  void refreshShownFrame(const AnimationFrameSet& set);
  AnimationFrameSet* findFrameSet(const QString& id);
  const AnimationFrameSet* findFrameSet(const QString& id) const;

  Core::Array<Index> m_atomUniqueIds;
  Core::Array<Index> m_bondUniqueIds;

  friend class RWMolecule;

  // Every constructor sets this; the initializer is a backstop so that one
  // that forgets leaves a pointer isInteractive() can test rather than a
  // wild one it would dereference.
  RWMolecule* m_undoMolecule = nullptr;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Molecule::MoleculeChanges)

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_MOLECULE_H
