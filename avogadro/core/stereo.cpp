/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "stereo.h"

#include "molecule.h"

namespace Avogadro::Core {

const char* StereoUnspecifiedProperty = "stereoUnspecified";

namespace {

bool unspecified(const PropertyMap& properties, Index index)
{
  const std::optional<int> value =
    properties.getInt(StereoUnspecifiedProperty, index);
  return value.has_value() && *value != 0;
}

} // namespace

bool atomStereoUnspecified(const Molecule& molecule, Index atom)
{
  return unspecified(molecule.atomProperties(), atom);
}

void setAtomStereoUnspecified(Molecule& molecule, Index atom, bool value)
{
  molecule.atomProperties().setInt(StereoUnspecifiedProperty, atom,
                                   value ? 1 : 0);
}

bool bondStereoUnspecified(const Molecule& molecule, Index bond)
{
  return unspecified(molecule.bondProperties(), bond);
}

void setBondStereoUnspecified(Molecule& molecule, Index bond, bool value)
{
  molecule.bondProperties().setInt(StereoUnspecifiedProperty, bond,
                                   value ? 1 : 0);
}

} // namespace Avogadro::Core
