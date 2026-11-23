/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecule.h"

#include "gaussiansetconcurrent.h"
#include "meshgenerator.h"
#include "slatersetconcurrent.h"
#include "rwmolecule.h"

#include <algorithm>
#include <iostream>

#include <avogadro/core/basisset.h>

// for HTML-formatted formulas
#include <QtCore/QRegularExpression>
#include <QtCore/QString>

namespace Avogadro::QtGui {

using std::swap;

namespace {

// Can @p uniqueId go to a new entry? As addAtom() and addBond() take it: a
// slot that is free, or the fresh id one past the end.
bool uniqueIdIsFree(const Core::Array<Index>& ids, Index uniqueId)
{
  const auto count = static_cast<Index>(ids.size());
  return uniqueId == count || (uniqueId < count && ids[uniqueId] == MaxIndex);
}

} // namespace

Molecule::Molecule(QObject* p)
  : QObject(p), m_undoMolecule(new RWMolecule(*this, this))
{
  m_undoMolecule->setInteractive(false);
}

Molecule::Molecule(const Molecule& other)
  : Core::Molecule(other), m_undoMolecule(new RWMolecule(*this, this))
{
  m_undoMolecule->setInteractive(false);
  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule::Molecule(const Core::Molecule& other)
  : Core::Molecule(other), m_undoMolecule(new RWMolecule(*this, this))
{
  // As in the two constructors above: without this the undo molecule was
  // left uninitialized, so undoMolecule() handed back a wild pointer and the
  // null check in isInteractive() never fired.
  m_undoMolecule->setInteractive(false);

  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule& Molecule::operator=(const Molecule& other)
{
  // Call the base classes assignment operator
  Core::Molecule::operator=(other);
  dropAnimationDisplay();
  clearAnimationFrames();

  // Copy over the unique ids
  m_atomUniqueIds = other.m_atomUniqueIds;
  m_bondUniqueIds = other.m_bondUniqueIds;

  return *this;
}

Molecule& Molecule::operator=(const Core::Molecule& other)
{
  // Call the base classes assignment operator
  Core::Molecule::operator=(other);
  dropAnimationDisplay();
  clearAnimationFrames();

  // Reset the unique ids.
  m_atomUniqueIds.clear();
  for (Index i = 0; i < atomCount(); ++i)
    m_atomUniqueIds.push_back(i);

  m_bondUniqueIds.clear();
  for (Index i = 0; i < bondCount(); ++i)
    m_bondUniqueIds.push_back(i);

  return *this;
}

Molecule::~Molecule() {}

Molecule::AtomType Molecule::addAtom(unsigned char number)
{
  m_atomUniqueIds.push_back(atomCount());
  AtomType a = Core::Molecule::addAtom(number);
  return a;
}

Molecule::AtomType Molecule::addAtom(unsigned char number, Index uniqueId)
{
  // A unique id one past the end is the fresh id AddAtomCommand carries on its
  // first run, and addAtom() appends exactly that id. The overload taking a
  // position has always handled it this way; without it here,
  // RWMolecule::addAtom(number, /* usingPositions = */ false) added no atom at
  // all while reporting one, and the undo that followed removed whichever atom
  // had taken the index it recorded.
  if (uniqueId == static_cast<Index>(m_atomUniqueIds.size()))
    return addAtom(number);

  if (uniqueId > static_cast<Index>(m_atomUniqueIds.size()) ||
      m_atomUniqueIds[uniqueId] != MaxIndex) {
    return AtomType();
  }
  m_atomUniqueIds[uniqueId] = atomCount();
  AtomType a = Core::Molecule::addAtom(number);
  return a;
}

Molecule::AtomType Molecule::addAtom(unsigned char number, Vector3 position3d,
                                     Index uniqueId)
{
  // Store the position first, as Core::Molecule::addAtom() does, so the atom
  // is added to the coordinate sets with it.
  const bool covered = m_positions3d.size() == atomCount();
  if (covered)
    m_positions3d.push_back(position3d);

  // Add atom using our own addAtom (which handles unique IDs)
  auto atom = uniqueId >= static_cast<Index>(m_atomUniqueIds.size())
                ? Molecule::addAtom(number)
                : Molecule::addAtom(number, uniqueId);
  if (!atom.isValid()) {
    // A refused add leaves the molecule as it was.
    if (covered)
      m_positions3d.pop_back();
    return atom;
  }

  // Positions that did not cover the atoms yet are extended by this.
  atom.setPosition3d(position3d);
  return atom;
}

bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;
  Index uniqueId = findAtomUniqueId(index);
  if (uniqueId == MaxIndex)
    return false;

  // Unique ID of an atom that was removed:
  m_atomUniqueIds[uniqueId] = MaxIndex;
  auto newSize = static_cast<Index>(atomCount() - 1);

  // Before removing the atom we must first remove any bonds to it.
  Core::Molecule::removeAtom(index);

  if (index != newSize) {
    // movedAtomUID
    uniqueId = findAtomUniqueId(newSize);
    assert(uniqueId != MaxIndex);
    m_atomUniqueIds[uniqueId] = index;
  }
  return true;
}

bool Molecule::removeAtom(const AtomType& atom_)
{
  return removeAtom(atom_.index());
}

bool Molecule::restoreAtomSnapshot(Index atomId,
                                   const Core::AtomSnapshot& snapshot,
                                   Index uniqueId)
{
  // The unique ids of an atom's bonds are not in the snapshot. RWMolecule
  // removes the bonds with commands of their own first, so there are none.
  if (snapshot.hasBonds())
    return false;

  // As addAtom(): a free slot, or the fresh id one past the end.
  const auto uniqueCount = static_cast<Index>(m_atomUniqueIds.size());
  if (!uniqueIdIsFree(m_atomUniqueIds, uniqueId))
    return false;

  // The atom the removal moved into atomId is at atomId now and goes back to
  // the end. Find its unique id before the restoration puts another atom there.
  const Index lastAtom = atomCount(); // the last index after the restoration
  Index movedUniqueId = MaxIndex;
  if (atomId < lastAtom)
    movedUniqueId = findAtomUniqueId(atomId);

  if (!Core::Molecule::restoreAtomSnapshot(atomId, snapshot))
    return false;

  if (uniqueId == uniqueCount)
    m_atomUniqueIds.push_back(atomId);
  else
    m_atomUniqueIds[uniqueId] = atomId;
  if (movedUniqueId != MaxIndex)
    m_atomUniqueIds[movedUniqueId] = lastAtom;
  return true;
}

Molecule::AtomType Molecule::atomByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size()) ||
      m_atomUniqueIds[uniqueId] == MaxIndex) {
    return AtomType();
  } else {
    return AtomType(this, m_atomUniqueIds[uniqueId]);
  }
}

Index Molecule::atomUniqueId(const AtomType& a) const
{
  if (a.molecule() != this)
    return MaxIndex;
  return findAtomUniqueId(a.index());
}

Index Molecule::atomUniqueId(Index a) const
{
  return findAtomUniqueId(a);
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  return addBond(a.index(), b.index(), order);
}

Molecule::BondType Molecule::addBond(Avogadro::Index atomId1,
                                     Avogadro::Index atomId2,
                                     unsigned char order)
{
  const Index before = bondCount();
  BondType bond_ = Core::Molecule::addBond(atomId1, atomId2, order);

  // Only a bond that was actually created gets a unique id. Core::addBond()
  // refuses out-of-range atom indices, and for a pair that is already bonded
  // it updates the order and hands back the existing bond -- in both cases
  // bondCount() does not grow. A unique id pushed anyway would point at a bond
  // index that does not exist, and m_bondUniqueIds would stay one longer than
  // the bond list for the rest of the molecule's life: findBondUniqueId()
  // then answers with the stale id, and the undo command that stored it
  // swaps a bond index that is no longer a bond.
  if (bond_.isValid() && bondCount() > before)
    m_bondUniqueIds.push_back(bond_.index());

  return bond_;
}

void Molecule::addBonds(const Core::Array<std::pair<Index, Index>>& bonds,
                        const Core::Array<unsigned char>& orders)
{
  assert(orders.size() == bonds.size());
  for (Index i = 0; i < orders.size(); ++i) {
    addBond(bonds[i].first, bonds[i].second, orders[i]);
  }
}
void Molecule::swapBond(Index a, Index b)
{
  Index uniqueA = findBondUniqueId(a);
  Index uniqueB = findBondUniqueId(b);
  // A released build has no assert. An undo command can hold a bond index
  // that is no longer a bond, and findBondUniqueId() answers MaxIndex for it
  // -- indexing m_bondUniqueIds with that writes far outside the array, which
  // corrupts the heap rather than failing here.
  if (uniqueA == MaxIndex || uniqueB == MaxIndex)
    return;
  swap(m_bondUniqueIds[uniqueA], m_bondUniqueIds[uniqueB]);
  Core::Molecule::swapBond(a, b);
}

void Molecule::swapAtom(Index a, Index b)
{
  if (a == b) {
    return;
  }
  Index uniqueA = findAtomUniqueId(a);
  Index uniqueB = findAtomUniqueId(b);
  // See swapBond(): the assert is gone in a released build, and MaxIndex here
  // would be an out-of-bounds write into m_atomUniqueIds.
  if (uniqueA == MaxIndex || uniqueB == MaxIndex)
    return;
  swap(m_atomUniqueIds[uniqueA], m_atomUniqueIds[uniqueB]);
  Core::Molecule::swapAtom(a, b);
}

Molecule::BondType Molecule::addBond(Index a, Index b, unsigned char order,
                                     Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size()) ||
      m_bondUniqueIds[uniqueId] != MaxIndex) {
    return BondType();
  }

  // As in the overload above: claim the unique id only once the bond exists,
  // or a refused add leaves the id pointing at a bond index that is not one.
  const Index before = bondCount();
  BondType bond_ = Core::Molecule::addBond(a, b, order);
  if (bond_.isValid() && bondCount() > before)
    m_bondUniqueIds[uniqueId] = bond_.index();

  return bond_;
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order, Index uniqueId)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  return addBond(a.index(), b.index(), order, uniqueId);
}

bool Molecule::removeBond(Index index)
{
  if (index >= bondCount())
    return false;
  Index uniqueId = findBondUniqueId(index);
  if (uniqueId == MaxIndex)
    return false;

  m_bondUniqueIds[uniqueId] = MaxIndex; // Unique ID of a bond that was removed.

  auto newSize = static_cast<Index>(bondCount() - 1);
  if (index != newSize) {
    Index movedBondUID = findBondUniqueId(newSize);
    assert(movedBondUID != MaxIndex);
    m_bondUniqueIds[movedBondUID] = index;
  }
  Core::Molecule::removeBond(index);
  return true;
}

bool Molecule::removeBond(const BondType& bond_)
{
  return removeBond(bond_.index());
}

bool Molecule::restoreBondSnapshot(Index bondId,
                                   const Core::BondSnapshot& snapshot,
                                   Index uniqueId)
{
  const auto uniqueCount = static_cast<Index>(m_bondUniqueIds.size());
  if (!uniqueIdIsFree(m_bondUniqueIds, uniqueId))
    return false;

  // As for atoms: the bond that the removal moved into bondId goes back to
  // the end.
  const Index lastBond = bondCount();
  Index movedUniqueId = MaxIndex;
  if (bondId < lastBond)
    movedUniqueId = findBondUniqueId(bondId);

  if (!Core::Molecule::restoreBondSnapshot(bondId, snapshot))
    return false;

  if (uniqueId == uniqueCount)
    m_bondUniqueIds.push_back(bondId);
  else
    m_bondUniqueIds[uniqueId] = bondId;
  if (movedUniqueId != MaxIndex)
    m_bondUniqueIds[movedUniqueId] = lastBond;
  return true;
}

bool Molecule::removeBond(const AtomType& a, const AtomType& b)
{
  return removeBond(bond(a, b).index());
}

bool Molecule::removeBond(Index a, Index b)
{
  return removeBond(bond(a, b).index());
}

Molecule::BondType Molecule::bondByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size()) ||
      m_bondUniqueIds[uniqueId] == MaxIndex) {
    return BondType();
  } else {
    return BondType(this, static_cast<Index>(m_bondUniqueIds[uniqueId]));
  }
}

Index Molecule::bondUniqueId(const BondType& b) const
{
  if (b.molecule() != this)
    return MaxIndex;
  return findBondUniqueId(b.index());
}

Index Molecule::bondUniqueId(Index b) const
{
  return findBondUniqueId(b);
}

bool Molecule::invalidatesDerivedData(unsigned int changes)
{
  // Structural changes invalidate derived computational data. Moving atoms is
  // not structural: vibration animation, trajectory playback and interactive
  // optimization all move atoms on every frame, and the vibration modes and
  // orbitals being displayed have to survive that.
  const bool movedOnly =
    (changes & Moved) && !(changes & (Added | Removed | Modified));
  return (changes & (Atoms | Bonds)) && !movedOnly;
}

void Molecule::emitChanged(unsigned int change)
{
  if (change != NoChange) {
    if (isShowingAnimationFrame()) {
      if (change & Conformer) {
        // Whoever moved to another set meant to see it, not a frame built
        // from the old one. The caller's emit below covers the move.
        // With no stored set to move to, put the rest geometry back.
        const int active = coordinate3d();
        const Core::Array<Vector3> target =
          active >= 0 && active < static_cast<int>(coordinate3dCount())
            ? coordinate3d(static_cast<size_t>(active))
            : m_animationRestPositions;
        if (target.empty() || target.size() == atomCount())
          setAtomPositions3d(target);
        dropAnimationDisplay();
      } else if (invalidatesDerivedData(change)) {
        dropAnimationDisplay();
      } else if ((change & Atoms) &&
                 atomPositions3d() !=
                   animationFrame(m_shownAnimationId,
                                  static_cast<size_t>(m_shownAnimationIndex))) {
        // Someone else moved the atoms: the edit owns the positions now.
        dropAnimationDisplay();
      }
    }
    // A replacement carries its own derived data, so only an in-place edit
    // discards it. RWMolecule::modifyMolecule has already stopped the workers
    // that were using what the replacement swapped out.
    if (invalidatesDerivedData(change) && !(change & Replaced)) {
      // Worker threads may still be reading the basis set and writing into
      // the cubes and meshes that are about to be deleted.
      GaussianSetConcurrent::cancelAllCalculations();
      SlaterSetConcurrent::cancelAllCalculations();
      MeshGenerator::cancelAllCalculations();
      clearCubes();
      clearMeshes();
      m_basisSet.reset();
      m_spectra.clear();
      clearVibrations();
      // Charges computed or read for the old structure no longer describe it.
      for (const std::string& type : partialChargeTypes())
        removePartialCharges(type);
    }
    // Animation frames are per-atom positions of the old structure, so even a
    // replacement leaves them stale.
    if (invalidatesDerivedData(change))
      clearAnimationFrames();
    emit changed(change);
  }
}

void Molecule::dropAnimationDisplay()
{
  if (!isShowingAnimationFrame())
    return;
  m_shownAnimationId.clear();
  m_shownAnimationIndex = -1;
  m_animationRestPositions.clear();
  emit animationDisplayChanged();
}

bool Molecule::showAnimationFrame(const QString& id, size_t index)
{
  const AnimationFrameSet* set = findFrameSet(id);
  if (set == nullptr || index >= set->frames.size() ||
      set->frames[index].size() != atomCount())
    return false;

  const bool wasShowing = isShowingAnimationFrame();
  const bool sameFrame = wasShowing && m_shownAnimationId == id &&
                         m_shownAnimationIndex == static_cast<int>(index);
  if (!wasShowing)
    m_animationRestPositions = atomPositions3d();

  setAtomPositions3d(set->frames[index]);
  m_shownAnimationId = id;
  m_shownAnimationIndex = static_cast<int>(index);
  emitChanged(Atoms | Moved);
  if (!sameFrame)
    emit animationDisplayChanged();
  return true;
}

void Molecule::clearAnimationDisplay()
{
  if (!isShowingAnimationFrame())
    return;
  const Core::Array<Vector3> rest = m_animationRestPositions;
  m_shownAnimationId.clear();
  m_shownAnimationIndex = -1;
  m_animationRestPositions.clear();
  if (rest.empty() || rest.size() == atomCount())
    setAtomPositions3d(rest);
  emitChanged(Atoms | Moved);
  emit animationDisplayChanged();
}

Core::Array<Vector3> Molecule::restPositions3d() const
{
  return isShowingAnimationFrame() ? m_animationRestPositions
                                   : atomPositions3d();
}

void Molecule::refreshShownFrame(const AnimationFrameSet& set)
{
  const size_t index =
    std::min(static_cast<size_t>(m_shownAnimationIndex), set.frames.size() - 1);
  const Core::Array<Vector3>& frame = set.frames[index];
  if (frame.size() != atomCount()) {
    clearAnimationDisplay();
    return;
  }

  const bool indexChanged = static_cast<int>(index) != m_shownAnimationIndex;
  const bool moved = frame != atomPositions3d();
  m_shownAnimationIndex = static_cast<int>(index);
  if (moved) {
    setAtomPositions3d(frame);
    emitChanged(Atoms | Moved);
  }
  if (indexChanged)
    emit animationDisplayChanged();
}

void Molecule::clearAnimationFrames()
{
  if (m_animationFrameSets.empty())
    return;
  m_animationFrameSets.clear();
  emit animationFramesChanged();
}

Molecule::AnimationFrameSet* Molecule::findFrameSet(const QString& id)
{
  auto it =
    std::find_if(m_animationFrameSets.begin(), m_animationFrameSets.end(),
                 [&id](const AnimationFrameSet& set) { return set.id == id; });
  return it == m_animationFrameSets.end() ? nullptr : &*it;
}

const Molecule::AnimationFrameSet* Molecule::findFrameSet(
  const QString& id) const
{
  return const_cast<Molecule*>(this)->findFrameSet(id);
}

void Molecule::setAnimationFrames(
  const QString& id, const QString& label,
  const Core::Array<Core::Array<Vector3>>& frames)
{
  if (frames.empty()) {
    removeAnimationFrames(id);
    return;
  }
  if (AnimationFrameSet* set = findFrameSet(id)) {
    set->label = label;
    set->frames = frames;
    if (isShowingAnimationFrame() && m_shownAnimationId == id)
      refreshShownFrame(*set);
  } else {
    m_animationFrameSets.push_back({ id, label, frames });
  }
  emit animationFramesChanged();
}

void Molecule::removeAnimationFrames(const QString& id)
{
  const AnimationFrameSet* set = findFrameSet(id);
  if (set == nullptr)
    return;
  if (isShowingAnimationFrame() && m_shownAnimationId == id)
    clearAnimationDisplay();
  // The display emits to listeners that may publish; look the set up again.
  set = findFrameSet(id);
  if (set == nullptr)
    return;
  m_animationFrameSets.erase(m_animationFrameSets.begin() +
                             (set - m_animationFrameSets.data()));
  emit animationFramesChanged();
}

QStringList Molecule::animationFrameIds() const
{
  QStringList ids;
  for (const AnimationFrameSet& set : m_animationFrameSets)
    ids << set.id;
  return ids;
}

QString Molecule::animationFrameLabel(const QString& id) const
{
  const AnimationFrameSet* set = findFrameSet(id);
  return set ? set->label : QString();
}

Core::Array<Core::Array<Vector3>> Molecule::animationFrames(
  const QString& id) const
{
  const AnimationFrameSet* set = findFrameSet(id);
  return set ? set->frames : Core::Array<Core::Array<Vector3>>();
}

size_t Molecule::animationFrameCount(const QString& id) const
{
  const AnimationFrameSet* set = findFrameSet(id);
  return set ? set->frames.size() : 0;
}

Core::Array<Vector3> Molecule::animationFrame(const QString& id,
                                              size_t index) const
{
  const AnimationFrameSet* set = findFrameSet(id);
  return set != nullptr && index < set->frames.size() ? set->frames[index]
                                                      : Core::Array<Vector3>();
}

void Molecule::claimAnimationPlayback(QObject* owner)
{
  emit animationPlaybackClaimed(owner);
}

void Molecule::emitUpdate() const
{
  emit update();
}

Index Molecule::findAtomUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_atomUniqueIds.size()); ++i) {
    if (m_atomUniqueIds[i] == index)
      return i;
  }
  return MaxIndex;
}

Index Molecule::findBondUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_bondUniqueIds.size()); ++i)
    if (m_bondUniqueIds[i] == index)
      return i;
  return MaxIndex;
}

RWMolecule* Molecule::undoMolecule()
{
  return m_undoMolecule;
}

QString Molecule::formattedFormula() const
{
  // Get composition from core (handles isotopes and unit cell fractions)
  std::map<std::string, size_t> componentsCount = formulaComposition();

  QString formula;
  // loop through the components
  // if carbon is present, it goes first
  // if carbon is present, hydrogen is next
  // then alphabetical
  // and any components with a number in front get a superscript

  std::map<std::string, size_t>::iterator iter;
  iter = componentsCount.find("C");
  if (iter != componentsCount.end()) {
    formula += "C";
    if (iter->second > 1)
      formula += QString("<sub>%1</sub>").arg(iter->second);
    componentsCount.erase(iter);

    // hydrogen goes next if carbon is present
    iter = componentsCount.find("H");
    if (iter != componentsCount.end()) {
      formula += "H";
      if (iter->second > 1)
        formula += QString("<sub>%1</sub>").arg(iter->second);
      componentsCount.erase(iter);
    }
    // also deuterium and tritium
    iter = componentsCount.find("D");
    if (iter != componentsCount.end()) {
      formula += "D";
      if (iter->second > 1)
        formula += QString("<sub>%1</sub>").arg(iter->second);
      componentsCount.erase(iter);
    }
    iter = componentsCount.find("T");
    if (iter != componentsCount.end()) {
      formula += "T";
      if (iter->second > 1)
        formula += QString("<sub>%1</sub>").arg(iter->second);
      componentsCount.erase(iter);
    }
  }

  for (iter = componentsCount.begin(); iter != componentsCount.end(); ++iter) {
    // check if iter->first starts with a digit
    if (iter->first[0] >= '0' && iter->first[0] <= '9') {
      // get the digits for a superscript
      QString digits;
      for (unsigned int i = 0; i < iter->first.length(); ++i) {
        if (iter->first[i] >= '0' && iter->first[i] <= '9')
          digits += iter->first[i];
      }
      formula += QString("<sup>%1</sup>").arg(digits);
      // take the substring from the digit to the end
      formula += QString::fromStdString(iter->first.substr(digits.length()));
    } else
      formula += QString::fromStdString(iter->first);

    if (iter->second > 1)
      formula += QString("<sub>%1</sub>").arg(iter->second);
  }

  // add total charge as a superscript
  int charge = totalCharge();
  if (charge == -1)
    formula += QString("<sup>-</sup>");
  else if (charge < -1)
    formula += QString("<sup>%1</sup>").arg(charge);
  else if (charge == 1)
    formula += QString("<sup>+</sup>");
  else if (charge > 1)
    formula += QString("<sup>+%1</sup>").arg(charge);

  // add doublet or triplet for spin multiplicity as radical dot
  int spinMultiplicity = totalSpinMultiplicity();
  if (spinMultiplicity == 2)
    formula += "<sup>•</sup>";
  else if (spinMultiplicity == 3)
    formula += "<sup>••</sup>";

  return formula;
}

bool Molecule::isInteractive() const
{
  if (m_undoMolecule == nullptr)
    return false;

  return m_undoMolecule->isInteractive();
}

} // namespace Avogadro::QtGui
