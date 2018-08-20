/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "edtsurface.h"

#include <Eigen/Dense>

#include <avogadro/core/cube.h>
#include <avogadro/core/elementdata.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/molecule.h>

#include <QDebug>

#define X 0
#define Y 1
#define Z 2

using namespace Avogadro::Core;

namespace Avogadro {
namespace QtPlugins {

// Constructor
EDTSurface::EDTSurface()
{

  data = (dataStruct*)malloc(sizeof(dataStruct));

  data->boxLength = 128;
  data->probeRadius = 1.4;
  data->scaleFactor = 0;

  numberOfInnerVoxels = 0;

  m_cube = NULL;
  m_mol = NULL;
}

// Destructor
EDTSurface::~EDTSurface()
{
  free(data);
}

// Takes a molecule and a surface type and returns a cube

Core::Cube* EDTSurface::EDTCube(QtGui::Molecule* mol, Core::Cube* cube,
                                Surfaces::Type surfaceType, double probeRadius)
{
  this->setProbeRadius(probeRadius);
  return this->EDTCube(mol, cube, surfaceType);
}

Core::Cube* EDTSurface::EDTCube(QtGui::Molecule* mol, Core::Cube* cube,
                                Surfaces::Type surfaceType)
{

  if (surfaceType == Surfaces::VanDerWaals) {
    setProbeRadius(0.0);
  }

  this->setCube(cube);

  this->setMolecule(mol);
  // Set molecule

  this->initPara();
  // Initialize everything

  this->buildSolventAccessibleSolid();
  // Generate the molecular solid

  this->buildSurface();

  //  this->fastDistanceMap();

  if (surfaceType == Surfaces::SolventExcluded) {
    this->fastDistanceMap();
    this->buildSolventExcludedSolid();
    this->buildSurface();
  }

  return m_cube;
}

void EDTSurface::buildSolventAccessibleSolid()
{

  int numberOfAtoms = m_mol->atomCount();

  for (int i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = m_mol->atom(index);
    if (!data->ignoreHydrogens || current.atomicNumber() != 1) {
      fillAtom(index);
    }
    //			totalNumber++;
  }

  qDebug() << "number of inner voxels " << numberOfInnerVoxels;
}
// use isDone
void EDTSurface::buildSurface()
{
  int i, j, k;
  Vector3i ijk;
  Vector3i txyz;
  int ii;
  bool flagBound;
  numberOfSurfaceVoxels = 0;

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      for (k = 0; k < data->pHeight; k++) {
        ijk << i, j, k;
        if (m_cube->value(i, j, k) == 2) { // in solid
          flagBound = false;
          ii = 0;
          // If our voxel is in the solid,
          // Check all neighboring voxels
          // If any of them aren't in the solid, then this point is on the
          // surface
          while (!flagBound && ii < 26) {
            txyz = ijk + neighbors[ii];
            if (inBounds(txyz) &&
                (m_cube->value(txyz) == 1)) { // outside of solid
              m_cube->setValue(ijk, 0);       // on surface
              numberOfSurfaceVoxels++;
              flagBound = true;
            } else
              ii++;
          }
        }
      }
    }
  }
}

void EDTSurface::boundBox()
{
  /**
   *Finds the bound box of the sequence of atoms
   *The smallest rectangular prism that contains all the atoms
   *@param minPoint A pointer to a vector representing the minimum point
   *@param maxPoint A pointer to a vector representing the maximum point
   **/

  int numberOfAtoms = m_mol->atomCount();
  Array<Vector3> positions = m_mol->atomPositions3d();

  data->pMin << 100000, 100000, 100000;
  data->pMax << -100000, -100000, -100000;

  for (int i = 0; i < numberOfAtoms; i++) {
    Atom current = m_mol->atom(i);
    if (!data->ignoreHydrogens || current.atomicNumber() != 1) {
      if (positions[i](X) < data->pMin(X))
        data->pMin(X) = positions[i](X);
      if (positions[i](Y) < data->pMin(Y))
        data->pMin(Y) = positions[i](Y);
      if (positions[i](Z) < data->pMin(Z))
        data->pMin(Z) = positions[i](Z);
      if (positions[i](X) > data->pMax(X))
        data->pMax(X) = positions[i](X);
      if (positions[i](Y) > data->pMax(Y))
        data->pMax(Y) = positions[i](Y);
      if (positions[i](Z) > data->pMax(Z))
        data->pMax(Z) = positions[i](Z);
    }
  }
}

void EDTSurface::initPara()
{
  // Populate the array of neighbors

  int neighborNumber = 0;
  Vector3i ijk;

  neighbors = new Vector3i[26];

  for (int i = -1; i < 2; i++) {
    for (int j = -1; j < 2; j++) {
      for (int k = -1; k < 2; k++) {
        if (i != 0 || j != 0 || k != 0) {
          ijk << i, j, k;
          neighbors[neighborNumber] = ijk;
          neighborNumber++;
        }
      }
    }
  }

  double fixSf = 4;
  double fMargin = 2.5;

  Vector3 fMargins(fMargin, fMargin, fMargin);
  Vector3 probeRadii(data->probeRadius, data->probeRadius, data->probeRadius);

  // calculate the boundBox (get the pMin and pMax)
  boundBox();

  // inflate the pMin and pMax by a margin plus the probeRadius (0 if VWS)
  data->pMin -= (probeRadii + fMargins);
  data->pMax += (probeRadii + fMargins);

  data->pTran = -data->pMin;

  // set scaleFactor equal to the largest range between a max and min
  data->scaleFactor = data->pMax(X) - data->pMin(X);
  if ((data->pMax(Y) - data->pMin(Y)) > data->scaleFactor)
    data->scaleFactor = data->pMax(Y) - data->pMin(Y);
  if ((data->pMax(Z) - data->pMin(Z)) > data->scaleFactor)
    data->scaleFactor = data->pMax(Z) - data->pMin(Z);

  // data->scaleFactor is the maximum distance between our mins and maxes

  // set scaleFactor equal to boxLength (which defaults to 128)
  // over scaleFactor
  data->scaleFactor = (data->boxLength - 1.0) / double(data->scaleFactor);

  // multiply boxLength by fixSf (4) and then divide by scalefactor
  data->boxLength = int(data->boxLength * fixSf / data->scaleFactor);
  data->scaleFactor = fixSf;
  double threshBox = 300;
  if (data->boxLength > threshBox) {
    double sfThresh = threshBox / double(data->boxLength);
    data->boxLength = int(threshBox);
    data->scaleFactor = data->scaleFactor * sfThresh;
  }
  //	*/

  data->pLength =
    int(ceil(data->scaleFactor * (data->pMax(X) - data->pMin(X))) + 1);
  data->pWidth =
    int(ceil(data->scaleFactor * (data->pMax(Y) - data->pMin(Y))) + 1);
  data->pHeight =
    int(ceil(data->scaleFactor * (data->pMax(Z) - data->pMin(Z))) + 1);

  if (data->pLength > data->boxLength)
    data->pLength = data->boxLength;
  if (data->pWidth > data->boxLength)
    data->pWidth = data->boxLength;
  if (data->pHeight > data->boxLength)
    data->pHeight = data->boxLength;

  // Hoping this improves the resolution of our surfaces
  /*
    data->pLength *= 2;
    data->pWidth *= 2;
    data->pHeight *= 2;
    data->scaleFactor *=2;
  */

  Vector3i pDimensions(data->pLength, data->pWidth, data->pHeight);
  m_cube->setLimits(data->pMin, data->pMax, pDimensions);

  computed = new bool[128];
  spheres = new Vector3i*[128];
  numbersOfVectors = new int[128];

  for (int i = 0; i < 128; i++) {
    computed[i] = false;
    spheres[i] = NULL;
    numbersOfVectors[i] = -1;
  }

  for (int i = 0; i < data->pLength; i++) {
    for (int j = 0; j < data->pWidth; j++) {
      for (int k = 0; k < data->pHeight; k++) {
        m_cube->setValue(i, j, k, 1);
      }
    }
  }
}

void EDTSurface::setCube(Core::Cube* cube)
{
  m_cube = cube;
  //  m_cube->setCubeType(Core::Cube::EDT);
  return;
}

void EDTSurface::setMolecule(QtGui::Molecule* mol)
{
  m_mol = mol;
  return;
}

void EDTSurface::setProbeRadius(double probeRadius)
{
  data->probeRadius = probeRadius;
}

bool EDTSurface::inBounds(Vector3i vec)
{
  return (vec(X) > -1 && vec(Y) > -1 && vec(Z) > -1 && vec(X) < data->pLength &&
          vec(Y) < data->pWidth && vec(Z) < data->pHeight);
}

Vector3i EDTSurface::round(Vector3 vec)
{
  Vector3i intVec;
  intVec(0) = (int)vec(0);
  intVec(1) = (int)vec(1);
  intVec(2) = (int)vec(2);
  return intVec;
}

Vector3 EDTSurface::promote(Vector3i vec)
{
  Vector3 floatVec;
  floatVec(0) = (double)vec(0);
  floatVec(1) = (double)vec(1);
  floatVec(2) = (double)vec(2);
  return floatVec;
}

void EDTSurface::fillAtom(int indx)
{

  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i txyz; // vector from center of sphere to a point in solid
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz;  // vector from cxyz to oxyz

  // Obtain the current atom
  Atom current = m_mol->atom(indx);

  // Obtain its position, translate, and scale
  Array<Vector3> positions = m_mol->atomPositions3d();
  cp = (positions[indx] + data->pTran) * data->scaleFactor;
  cxyz = round(cp);

  // Obtain its atomic number
  int atomicNumber = current.atomicNumber();

  // If we haven't already computed the sphere for that element, do that
  if (!computed[atomicNumber]) {
    computeSphere(atomicNumber);
  }

  // Iterate through the vectors that lead to points in the sphere
  //
  for (int i = 0; i < numbersOfVectors[atomicNumber]; i++) {
    txyz = spheres[atomicNumber][i];
    oxyz = cxyz + txyz;

    if (inBounds(oxyz)) {
      if (m_cube->value(oxyz) == 1) { // not in solid yet
        m_cube->setValue(oxyz, 2);    // in solid now
        numberOfInnerVoxels++;
      }
    } // if inBounds
  }
  return;
}

void EDTSurface::buildSolventExcludedSolid()
{
  // When we call this function, we're building a solvent excluded surface
  // We've already built the solvent accessible solid
  // And done an EDT on all points within it
  // Now we just need to remove all points whose distance from the SAS is <=
  // probeRadius

  int numberOfAtoms = m_mol->atomCount();

  for (int i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = m_mol->atom(index);
    if (!data->ignoreHydrogens || current.atomicNumber() != 1) {
      fillAtomWaals(index);
    }
    //			totalNumber++;
  }
}

void EDTSurface::fastDistanceMap()
{
  qDebug() << "fastDistanceMap is executing";
  Vector3i ijk;
  Vector3i txyz; // Vector pulled from array of boundary points
  Vector3 dxyz;  // Vector from ijk to dxyz
  double distance = 0;

  surfaceVoxels = new Vector3i[numberOfSurfaceVoxels];
  int surfaceVoxelCount = 0;

  for (int i = 0; i < data->pLength; i++) {
    for (int j = 0; j < data->pWidth; j++) {
      for (int k = 0; k < data->pHeight; k++) {
        if (m_cube->value(i, j, k) == 0) { // on surface
          ijk << i, j, k;
          surfaceVoxels[surfaceVoxelCount] = ijk;
          surfaceVoxelCount++;
        }
      }
    }
  }

  qDebug() << " first loop finished ";

  for (int i = 0; i < data->pLength; i++) {
    for (int j = 0; j < data->pWidth; j++) {
      for (int k = 0; k < data->pHeight; k++) {
        distance = 0;
        if (m_cube->value(i, j, k) == 2) {
          ijk << i, j, k;
          for (int l = 0; l < numberOfSurfaceVoxels; l++) {
            txyz = surfaceVoxels[l];
            dxyz = promote(txyz - ijk);
            if (distance == 0 || dxyz.norm() < distance) {
              distance = dxyz.norm();
            } // end if distance
          }   // end for l
          m_cube->setValue(i, j, k, distance);
        } // end if in solid
      }   // end for k
    }     // end for j
  }       // end for i
  qDebug() << "second loop finished ";
}

void EDTSurface::computeSphere(unsigned char atomicNumber)
{
  Vector3 dxyz;
  Vector3i ijk;

  double scaledRad =
    (element_VDW[atomicNumber] + data->probeRadius) * data->scaleFactor + 0.5;
  int scaledRadius = (int)scaledRad;

  int dPlusOne = 2 * scaledRadius + 1;

  spheres[atomicNumber] = new Vector3i[dPlusOne * dPlusOne * dPlusOne];
  // This is a significant overallocation, but it's okay, we'll fix it
  //(This is the number of points with integer coords in the cube we're going to
  // construct) (It is a theoretical upper bound for points with integer coords
  // in the sphere) (There's definitely fewer than this, but it's difficult to
  // say how many)

  int count = 0;

  // We construct the cube containing the sphere
  // And check every point within it to see if it's within the radius
  // If it is, we add to our list a vector to that point

  for (int i = -scaledRadius; i <= scaledRadius; i++) {
    for (int j = -scaledRadius; j <= scaledRadius; j++) {
      for (int k = -scaledRadius; k <= scaledRadius; k++) {
        ijk << i, j, k;
        dxyz = promote(ijk);
        if (dxyz.norm() <= scaledRadius) {
          spheres[atomicNumber][count] = ijk;
          count++;
        }
      }
    }
  }

  // Create a new array of a more appropriate size
  Vector3i* tempOne;
  tempOne = new Vector3i[count];

  // Copy values from spheres[atomicNumber] into it
  for (int i = 0; i < count; i++) {
    tempOne[i] = spheres[atomicNumber][i];
  }

  // Free the old memory
  free(spheres[atomicNumber]);

  // Point the pointer to the new array
  spheres[atomicNumber] = tempOne;

  // Set numbersOfVectors
  numbersOfVectors[atomicNumber] = count;

  // And computed
  computed[atomicNumber] = true;

  return;
}

// This should be faster than iterating over the whole cube
// Unless the intersections of atoms get to be larger than the complement of the
// solid

void EDTSurface::fillAtomWaals(int index)
{
  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i txyz; // vector from center of sphere to a point in solid
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz;  // vector from cxyz to oxyz

  // Obtain the current atom
  Atom current = m_mol->atom(index);

  // Obtain its position, translate, and scale
  Array<Vector3> positions = m_mol->atomPositions3d();
  cp = (positions[index] + data->pTran) * data->scaleFactor;
  cxyz = round(cp);

  // Obtain its atomic number
  int atomicNumber = current.atomicNumber();

  for (int i = 0; i < numbersOfVectors[atomicNumber]; i++) {
    txyz = spheres[atomicNumber][i];
    oxyz = cxyz + txyz;

    if (inBounds(oxyz)) {
      if (m_cube->value(oxyz) <=
          data->probeRadius) {     // this runs right after fastDistanceMap
        m_cube->setValue(oxyz, 1); // outside of solid
        numberOfInnerVoxels--;
      }
    }
  }
  return;
}

} // End namespace Core

} // End namespace Avogadro
