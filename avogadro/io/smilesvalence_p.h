/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_SMILESVALENCE_P_H
#define AVOGADRO_IO_SMILESVALENCE_P_H

namespace Avogadro::Io {

/** Returned when an element has no bare form in the SMILES organic subset. */
const int SmilesNotOrganicSubset = -1;

/**
 * Number of hydrogens a SMILES parser will infer for a bare (unbracketed)
 * organic subset atom whose written bonds sum to @a bondOrderSum.
 *
 * The implied count is the smallest normal valence not less than the sum,
 * minus the sum; a sum beyond the largest normal valence implies no hydrogens.
 *
 * This is deliberately *not* Core::atomValence() from mdlvalence_p.h. That
 * function implements the MDL model: it takes a bond *count* rather than a
 * bond order sum, and it is charge aware. The two disagree in ordinary cases —
 * a neutral nitrogen with two double bonds has two bonds but a bond order sum
 * of four, for which the MDL model answers 3 (implying a negative hydrogen
 * count) where SMILES answers 5, implying one hydrogen. SMILES needs no charge
 * handling here because a charged atom is always bracketed.
 *
 * @param atomicNumber Atomic number of the atom.
 * @param bondOrderSum Sum of the orders of the bonds actually written.
 * @return The implied hydrogen count, or SmilesNotOrganicSubset.
 */
inline int smilesImpliedHydrogens(unsigned char atomicNumber,
                                  unsigned int bondOrderSum)
{
  // OpenSMILES 3.1.5, "organic subset" — the only elements with a bare form.
  static const unsigned int boron[] = { 3 };
  static const unsigned int carbon[] = { 4 };
  static const unsigned int nitrogen[] = { 3, 5 };
  static const unsigned int oxygen[] = { 2 };
  static const unsigned int phosphorus[] = { 3, 5 };
  static const unsigned int sulfur[] = { 2, 4, 6 };
  static const unsigned int halogen[] = { 1 };

  const unsigned int* valences = nullptr;
  unsigned int possibleValences = 0;

  switch (atomicNumber) {
    case 5: // B
      valences = boron;
      possibleValences = 1;
      break;
    case 6: // C
      valences = carbon;
      possibleValences = 1;
      break;
    case 7: // N
      valences = nitrogen;
      possibleValences = 2;
      break;
    case 8: // O
      valences = oxygen;
      possibleValences = 1;
      break;
    case 15: // P
      valences = phosphorus;
      possibleValences = 2;
      break;
    case 16: // S
      valences = sulfur;
      possibleValences = 3;
      break;
    case 9:  // F
    case 17: // Cl
    case 35: // Br
    case 53: // I
      valences = halogen;
      possibleValences = 1;
      break;
    default:
      // Astatine is excluded on purpose: it is not part of the subset.
      return SmilesNotOrganicSubset;
  }

  for (unsigned int i = 0; i < possibleValences; ++i) {
    if (bondOrderSum <= valences[i])
      return static_cast<int>(valences[i] - bondOrderSum);
  }

  return 0;
}

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_SMILESVALENCE_P_H
