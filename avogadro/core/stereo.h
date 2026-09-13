/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_STEREO_H
#define AVOGADRO_CORE_STEREO_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <string>

namespace Avogadro::Core {

class Molecule;

/**
 * @file stereo.h
 * @brief Marking stereochemistry as deliberately undefined.
 *
 * A molecule always has coordinates, so any stereocentre in it has some
 * geometry -- but that geometry is not always meaningful. A structure drawn in
 * two dimensions, or imported from a file whose author marked a centre
 * "unknown", has atoms placed somewhere without any claim about the
 * configuration. Reading such a placement as though it were real invents
 * stereochemistry the source never asserted.
 *
 * These mark the cases where that has happened, so consumers can tell "no
 * stereochemistry here" from "stereochemistry not stated". The configuration
 * itself is not stored: where it is meaningful, it is read from the
 * coordinates.
 *
 * The values live in Molecule::atomProperties() and bondProperties(), so they
 * follow atoms and bonds through insertion and deletion, and round-trip
 * through CJSON. They are *not* carried by CML, which does not serialize
 * custom properties.
 */

/**
 * Property column recording that an atom's configuration is undefined. Part of
 * the on-disk CJSON format, so it must stay stable.
 */
AVOGADROCORE_EXPORT extern const char* const StereoUnspecifiedProperty;

/** @return true if @a atom is marked as having an undefined configuration. */
AVOGADROCORE_EXPORT bool atomStereoUnspecified(const Molecule& molecule,
                                               Index atom);

/** Mark, or unmark, @a atom as having an undefined configuration. */
AVOGADROCORE_EXPORT void setAtomStereoUnspecified(Molecule& molecule,
                                                  Index atom,
                                                  bool unspecified = true);

/** @return true if @a bond is marked as having an undefined configuration. */
AVOGADROCORE_EXPORT bool bondStereoUnspecified(const Molecule& molecule,
                                               Index bond);

/** Mark, or unmark, @a bond as having an undefined configuration. */
AVOGADROCORE_EXPORT void setBondStereoUnspecified(Molecule& molecule,
                                                  Index bond,
                                                  bool unspecified = true);

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_STEREO_H
