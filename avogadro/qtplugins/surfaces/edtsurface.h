/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_EDTSURFACE_H
#define AVOGADRO_QTPLUGINS_EDTSURFACE_H

#include "surfaces.h"
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>
// for the enum

namespace Avogadro {
namespace Core {
class Cube;
class Molecule;
class Atom;
}
namespace QtGui {
class Molecule;
}

namespace QtPlugins {

typedef struct dataStruct
{
  Vector3 pTran;
  int boxLength;
  double probeRadius;
  double fixSf;
  double scaleFactor;
  Vector3 pMin, pMax;
  int pHeight, pWidth, pLength;
  int widXz[13];
  int* deptY[13];
  double cutRadius;
  int positIn, positOut, eliminate;
  int certificate;
  int totalSurfaceVox;
  int totalInnerVox;
  Vector3i *inArray, *outArray;
} dataStruct; // End struct dataStruct

class EDTSurface
{
public:
  // Constructor
  EDTSurface();

  // Destructor
  virtual ~EDTSurface();

  /*@brief Populates a cube with values generated by doing a Euclidean distance
   *transform on the molecule provided
   *@param mol A pointer to a the molecule from which the cube is to be
   *generated
   *@param surfType an enum class representing the type of surface (VdW, SES,
   *SAS)
   *@returns a pointer to the cube
   */

  Core::Cube* EDTCube(QtGui::Molecule* mol, Surfaces::Type surfType);

  // The copying over from array to Cube can and should be done in parallel

  /*@brief Populates a cube with values generated by doing a Euclidean distance
   *transform on the molecule provided
   *@param mol A pointer to a the molecule from which the cube is to be
   *generated
   *@param surfType an enum class representing the type of surface (VdW, SES,
   *SAS)
   *@param probeRadius a double representing the molecular radius of the solvent
   *@returns a pointer to the cube
   */

  Core::Cube* EDTCube(QtGui::Molecule* mol, Surfaces::Type surfType,
                      double probeRadius);
  // Takes a molecule, a surface type and a probeRadius and

  /*@brief Sets a pointer to the desired molecule
   *@param mol a pointer to the molecule to be set
   */

  void setMolecule(QtGui::Molecule* mol);

  /*@brief Sets the probe radius to a desired value (default is 1.4 - water)
   *@param probeRadius The molecular radius of the solvent
   */

  void setProbeRadius(double probeRadius);

private:
  /*
   *@brief Initializes the data members of the class
   *@param atomType
   *@param bType
   *@param surfaceType
   */

  void initPara(bool atomType, bool bType);

  /*
   *@brief For each atom in the molecule, fills the appropriate voxels
   *@param atomType
   */

  void fillVoxels(bool atomType);

  void fillAtom(int indx);

  void fillAtomWaals(int indx);

  void fillVoxelsWaals(bool atomType);

  void fastOneShell(int* inNum, int* allocOut, Vector3i*** boundPoint,
                    int* outNum, int* elimi);

  void fastDistanceMap();

  void buildBoundary();

  void boundBox(bool atomType);

  void boundingAtom(bool bType);

  /*
   *@brief Takes an array of integers and returns a Vector3i
   *@param array Array of integers
   *@returns A Vector3i
   */

  Vector3i vectorFromArray(int* array);

  /*
   *@brief Takes an atomic number and returns an index for rasRad
   *@param atomicNumber The atomic number of the atom in question
   *@returns An integer index for an array of atomic radii
   */

  int detail(unsigned char atomicNumber);

  QtGui::Molecule* m_mol;

  Core::Cube* m_cube;

  // These bool arrays should probably be converted into BitVectors
  bool*** isDone;
  bool*** isBound;
  bool*** inOut;
  int*** atomIds;

  dataStruct* data;
}; // End class EDTSurface

} // End namespace QtPlugins
} // End namespace Avogadro

#endif
