/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_EDTSURFACE_H
#define AVOGADRO_QTPLUGINS_EDTSURFACE_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Core {
class Cube;
class Molecule;
class Atom;
}

namespace QtPlugins {

  class dataClass;

  typedef struct volumePixel
  {
  	int atomId;
  	float distance;
  	bool inOut;
  	bool isBound;
  	bool isDone;
  }volumePixel;


class EDTSurface
{
public:
  EDTSurface();

  void initPara(bool atomType, bool bType);

  void fillVoxels(bool atomType);
  // Operates on the cube
  void fillAtom(int indx);
  // Operates on the cube
  void fillAtomWaals(int indx);
  // Operates on the cube
  void fillVoxelsWaals(bool atomType);
  // Operates on the cube
  void fastOneShell(int* inNum, int* allocOut, Vector3i*** boundPoint,
                    int* outNum, int* elimi);
  // Operates on the cube
  void fastDistanceMap();

  void buildBoundary();
  // Operates on the cube
  void boundBox(bool atomType);

  void boundingAtom(bool bType);

  Core::Cube *EDTCube(Core::Molecule *mol, int surfaceType);
  // Takes a molecule and a surface type and returns a cube

  Vector3i vectorFromArray(int* array);
  // Takes an array of integers and returns a vector3i

  int detail(unsigned char atomicNumber);
  // Takes an atomic number and returns an index for rasRad

  void setMolecule(Core::Molecule *mol);

  void setProbeRadius(double probeRadius);

  virtual ~EDTSurface();

  Molecule* m_mol;

  volumePixel*** volumePixels;

  Cube* m_cube;

  /*Vector3 pTran;
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
*/

private:
  dataClass *data;
}; // End class EDTSurface

struct dataStruct{
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

};//End class dataClass

} // End namespace QtPlugins
} // End namespace Avogadro

#endif
