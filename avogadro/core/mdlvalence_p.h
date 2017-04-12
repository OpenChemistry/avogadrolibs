/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc
  Copyright 2012 NextMove Software

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

namespace Avogadro {
namespace Core {

/**
 * Calculate the full valency (e.g. number of expected bonds) for a given atom.
 * This function is adapted from the MDL valence model to indicate when an atom
 * is overbonded.
 * @param atomicNumber Atomic number of atom.
 * @param charge Formal charge of atom.
 * @param numBonds Number of existing bonds to atom.
 * @return The total number of expected bonds to the atom to satisfy valency.
 * May be less than @a numBonds if atom is overbonded.
 */
static unsigned int atomValence(const unsigned char atomicNumber,
                                const int charge, const unsigned int numBonds)
{
  switch (atomicNumber) {
    case 1:  // H
    case 3:  // Li
    case 11: // Na
    case 19: // K
    case 37: // Rb
    case 55: // Cs
    case 87: // Fr
      if (charge == 0)
        return 1;
      break;

    case 4:  // Be
    case 12: // Mg
    case 20: // Ca
    case 38: // Sr
    case 56: // Ba
    case 88: // Ra
      switch (charge) {
        case 0:
          return 2;
        case 1:
          return 1;
      }
      break;

    case 5: // B
      switch (charge) {
        case -4:
          return 1;
        case -3:
          return 2;
        case -2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case -1:
          return 4;
        case 0:
          return 3;
        case 1:
          return 2;
        case 2:
          return 1;
      }
      break;

    case 6: // C
      switch (charge) {
        case -3:
          return 1;
        case -2:
          return 2;
        case -1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 0:
          return 4;
        case 1:
          return 3;
        case 2:
          return 2;
        case 3:
          return 1;
      }
      break;

    case 7: // N
      switch (charge) {
        case -2:
          return 1;
        case -1:
          return 2;
        case 0:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 1:
          return 4;
        case 2:
          return 3;
        case 3:
          return 2;
        case 4:
          return 1;
      }
      break;

    case 8: // O
      switch (charge) {
        case -1:
          return 1;
        case 0:
          return 2;
        case 1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 2:
          return 4;
        case 3:
          return 3;
        case 4:
          return 2;
        case 5:
          return 1;
      }
      break;

    case 9: // F
      switch (charge) {
        case 0:
          return 1;
        case 1:
          return 2;
        case 2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 3:
          return 4;
        case 4:
          return 3;
        case 5:
          return 2;
        case 6:
          return 1;
      }
      break;

    case 13: // Al
      switch (charge) {
        case -4:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -3:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case -1:
          return 4;
        case 0:
          return 3;
        case 1:
          return 2;
        case 2:
          return 1;
      }
      break;

    case 14: // Si
      switch (charge) {
        case -3:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -2:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 0:
          return 4;
        case 1:
          return 3;
        case 2:
          return 2;
        case 3:
          return 1;
      }
      break;

    case 15: // P
      switch (charge) {
        case -2:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 0:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 1:
          return 4;
        case 2:
          return 3;
        case 3:
          return 2;
        case 4:
          return 1;
      }
      break;

    case 16: // S
      switch (charge) {
        case -1:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 0:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 2:
          return 4;
        case 3:
          return 3;
        case 4:
          return 2;
        case 5:
          return 1;
      }
      break;

    case 17: // Cl
      switch (charge) {
        case 0:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 3:
          return 4;
        case 4:
          return 3;
        case 5:
          return 2;
        case 6:
          return 1;
      }
      break;

    case 31: // Ga
      switch (charge) {
        case -4:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -3:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case -1:
          return 4;
        case 0:
          return 3;
        case 2:
          return 1;
      }
      break;

    case 32: // Ge
      switch (charge) {
        case -3:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -2:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 0:
          return 4;
        case 1:
          return 3;
        case 3:
          return 1;
      }
      break;

    case 33: // As
      switch (charge) {
        case -2:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 0:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 1:
          return 4;
        case 2:
          return 3;
        case 4:
          return 1;
      }
      break;

    case 34: // Se
      switch (charge) {
        case -1:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 0:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 2:
          return 4;
        case 3:
          return 3;
        case 5:
          return 1;
      }
      break;

    case 35: // Br
      switch (charge) {
        case 0:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 3:
          return 4;
        case 4:
          return 3;
        case 6:
          return 1;
      }
      break;

    case 49: // In
      switch (charge) {
        case -4:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -3:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case -1:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 0:
          return 3;
        case 2:
          return 1;
      }
      break;

    case 50: // Sn
    case 82: // Pb
      switch (charge) {
        case -3:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -2:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 0:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 1:
          return 3;
        case 3:
          return 1;
      }
      break;

    case 51: // Sb
    case 83: // Bi
      switch (charge) {
        case -2:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 0:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 1:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 2:
          return 3;
        case 4:
          return 1;
      }
      break;

    case 52: // Te
    case 84: // Po
      switch (charge) {
        case -1:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 0:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 1:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 2:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 3:
          return 3;
        case 5:
          return 1;
      }
      break;

    case 53: // I
    case 85: // At
      switch (charge) {
        case 0:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case 1:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case 2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case 3:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 4:
          return 3;
        case 6:
          return 1;
      }
      break;

    case 81: // Tl
      switch (charge) {
        case -4:
          if (numBonds <= 1)
            return 1;
          if (numBonds <= 3)
            return 3;
          if (numBonds <= 5)
            return 5;
          return 7;
        case -3:
          if (numBonds <= 2)
            return 2;
          if (numBonds <= 4)
            return 4;
          return 6;
        case -2:
          if (numBonds <= 3)
            return 3;
          return 5;
        case -1:
          if (numBonds <= 2)
            return 2;
          return 4;
        case 0:
          if (numBonds <= 1)
            return 1;
          return 3;
      }
      break;
  }
  return numBonds;
}

// This method is removed as it is not used at the moment and emits warnings
// otherwise. It should be used when an MDL reader is added.
#if 0
/**
 * Calculate the full valency (e.g. number of expected bonds) for a given atom.
 * This function implements the MDL valence model.
 * @param atomicNumber Atomic number of atom.
 * @param charge Formal charge of atom.
 * @param numBonds Number of existing bonds to atom.
 * @return The total number of expected bonds to the atom to satisfy valency.
 * Return value will never be less than numBonds.
 */
static unsigned int mdlValence(const unsigned char atomicNumber,
                               const int charge,
                               const unsigned int numBonds)
{
  switch (atomicNumber) {
  case  1:  // H
  case  3:  // Li
  case 11:  // Na
  case 19:  // K
  case 37:  // Rb
  case 55:  // Cs
  case 87:  // Fr
    if (charge == 0 && numBonds <= 1)
      return 1;
    break;

  case  4:  // Be
  case 12:  // Mg
  case 20:  // Ca
  case 38:  // Sr
  case 56:  // Ba
  case 88:  // Ra
    switch (charge) {
    case 0:  if (numBonds <= 2) return 2;  break;
    case 1:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case  5:  // B
    switch (charge) {
    case -4:  if (numBonds <= 1) return 1;  break;
    case -3:  if (numBonds <= 2) return 2;  break;
    case -2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case -1:  if (numBonds <= 4) return 4;  break;
    case  0:  if (numBonds <= 3) return 3;  break;
    case  1:  if (numBonds <= 2) return 2;  break;
    case  2:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case  6:  // C
    switch (charge) {
    case -3:  if (numBonds <= 1) return 1;  break;
    case -2:  if (numBonds <= 2) return 2;  break;
    case -1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  0:  if (numBonds <= 4) return 4;  break;
    case  1:  if (numBonds <= 3) return 3;  break;
    case  2:  if (numBonds <= 2) return 2;  break;
    case  3:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case  7:  // N
    switch (charge) {
    case -2:  if (numBonds <= 1) return 1;  break;
    case -1:  if (numBonds <= 2) return 2;  break;
    case  0:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  1:  if (numBonds <= 4) return 4;  break;
    case  2:  if (numBonds <= 3) return 3;  break;
    case  3:  if (numBonds <= 2) return 2;  break;
    case  4:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case  8:  // O
    switch (charge) {
    case -1:  if (numBonds <= 1) return 1;  break;
    case  0:  if (numBonds <= 2) return 2;  break;
    case  1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  2:  if (numBonds <= 4) return 4;  break;
    case  3:  if (numBonds <= 3) return 3;  break;
    case  4:  if (numBonds <= 2) return 2;  break;
    case  5:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case  9:  // F
    switch (charge) {
    case  0:  if (numBonds <= 1) return 1;  break;
    case  1:  if (numBonds <= 2) return 2;  break;
    case  2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  3:  if (numBonds <= 4) return 4;  break;
    case  4:  if (numBonds <= 3) return 3;  break;
    case  5:  if (numBonds <= 2) return 2;  break;
    case  6:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 13:  // Al
    switch (charge) {
    case -4:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -3:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case -1:  if (numBonds <= 4) return 4;  break;
    case  0:  if (numBonds <= 3) return 3;  break;
    case  1:  if (numBonds <= 2) return 2;  break;
    case  2:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 14:  // Si
    switch (charge) {
    case -3:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -2:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  0:  if (numBonds <= 4) return 4;  break;
    case  1:  if (numBonds <= 3) return 3;  break;
    case  2:  if (numBonds <= 2) return 2;  break;
    case  3:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 15:  // P
    switch (charge) {
    case -2:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  0:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  1:  if (numBonds <= 4) return 4;  break;
    case  2:  if (numBonds <= 3) return 3;  break;
    case  3:  if (numBonds <= 2) return 2;  break;
    case  4:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 16:  // S
    switch (charge) {
    case -1:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  0:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  2:  if (numBonds <= 4) return 4;  break;
    case  3:  if (numBonds <= 3) return 3;  break;
    case  4:  if (numBonds <= 2) return 2;  break;
    case  5:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 17:  // Cl
    switch (charge) {
    case  0:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  3:  if (numBonds <= 4) return 4;  break;
    case  4:  if (numBonds <= 3) return 3;  break;
    case  5:  if (numBonds <= 2) return 2;  break;
    case  6:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 31:  // Ga
    switch (charge) {
    case -4:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -3:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case -1:  if (numBonds <= 4) return 4;  break;
    case  0:  if (numBonds <= 3) return 3;  break;
    case  2:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 32:  // Ge
    switch (charge) {
    case -3:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -2:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  0:  if (numBonds <= 4) return 4;  break;
    case  1:  if (numBonds <= 3) return 3;  break;
    case  3:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 33:  // As
    switch (charge) {
    case -2:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  0:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  1:  if (numBonds <= 4) return 4;  break;
    case  2:  if (numBonds <= 3) return 3;  break;
    case  4:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 34:  // Se
    switch (charge) {
    case -1:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  0:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  2:  if (numBonds <= 4) return 4;  break;
    case  3:  if (numBonds <= 3) return 3;  break;
    case  5:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 35:  // Br
    switch (charge) {
    case  0:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  3:  if (numBonds <= 4) return 4;  break;
    case  4:  if (numBonds <= 3) return 3;  break;
    case  6:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 49:  // In
    switch (charge) {
    case -4:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -3:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case -1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  0:  if (numBonds <= 3) return 3;  break;
    case  2:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 50:  // Sn
  case 82:  // Pb
    switch (charge) {
    case -3:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -2:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  0:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  1:  if (numBonds <= 3) return 3;  break;
    case  3:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 51:  // Sb
  case 83:  // Bi
    switch (charge) {
    case -2:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  0:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  2:  if (numBonds <= 3) return 3;  break;
    case  4:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 52:  // Te
  case 84:  // Po
    switch (charge) {
    case -1:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  0:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  1:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  2:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  3:  if (numBonds <= 3) return 3;  break;
    case  5:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 53:  // I
  case 85:  // At
    switch (charge) {
    case  0:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case  1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case  2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case  3:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  4:  if (numBonds <= 3) return 3;  break;
    case  6:  if (numBonds <= 1) return 1;  break;
    }
    break;

  case 81:  // Tl
    switch (charge) {
    case -4:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;
      if (numBonds <= 7) return 7;  break;
    case -3:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;
      if (numBonds <= 6) return 6;  break;
    case -2:
      if (numBonds <= 3) return 3;
      if (numBonds <= 5) return 5;  break;
    case -1:
      if (numBonds <= 2) return 2;
      if (numBonds <= 4) return 4;  break;
    case  0:
      if (numBonds <= 1) return 1;
      if (numBonds <= 3) return 3;  break;
    }
    break;

  }
  return numBonds;
}
#endif

} // end namespace Core
} // end namespace Avogadro
