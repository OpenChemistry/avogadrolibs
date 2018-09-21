/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "edtsurfaceconcurrent.h"

#include <Eigen/Dense>

#include <QDebug>
#include <QFuture>
#include <QFutureWatcher>
#include <QReadWriteLock>
#include <QtConcurrentMap>
#include <avogadro/core/cube.h>
#include <avogadro/core/elementdata.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/molecule.h>

#define X 0
#define Y 1
#define Z 2

using namespace Avogadro::Core;

namespace Avogadro {
namespace QtPlugins {

// Constructor
EDTSurfaceConcurrent::EDTSurfaceConcurrent()
{

  data = (dataStruct*)malloc(sizeof(dataStruct));

  data->probeRadius = 1.4;
  data->scaleFactor = 0;

  m_cube = NULL;
  m_mol = NULL;
}

// Destructor
EDTSurfaceConcurrent::~EDTSurfaceConcurrent()
{
  free(data);
}

// Takes a molecule and a surface type and returns a cube

Core::Cube* EDTSurfaceConcurrent::EDTCube(QtGui::Molecule* mol,
                                          Core::Cube* cube,
                                          Surfaces::Type surfaceType,
                                          double probeRadius, double resolution)
{
  this->setProbeRadius(probeRadius);
  return this->EDTCube(mol, cube, surfaceType, resolution);
}

Core::Cube* EDTSurfaceConcurrent::EDTCube(QtGui::Molecule* mol,
                                          Core::Cube* cube,
                                          Surfaces::Type surfaceType,
                                          double resolution)
{

  data->resolution = resolution;

  if (surfaceType == Surfaces::VanDerWaals) {
    setProbeRadius(0.0);
  }

  this->setCube(cube);

  this->setMolecule(mol);
  // Set molecule

  this->initPara();
  // Initialize everything

  for (unsigned int i = 0; i < m_mol->atomCount(); i++) {
    Atom current = m_mol->atom(i);
    int atomicNumber = (int)current.atomicNumber();
    if (!computed[atomicNumber]) {
      computeSphere(atomicNumber);
    }
  }

  this->buildSolventAccessibleSolid();
  // Generate the molecular solid

  this->buildSurface();

  this->fastDistanceMap();

  if (surfaceType == Surfaces::SolventExcluded) {
    this->buildSolventExcludedSolid();
    this->buildSurface();
    this->fastDistanceMap();
  }

  return m_cube;
}

void EDTSurfaceConcurrent::buildSolventAccessibleSolid()
{
  Array<Vector3> positions = m_mol->atomPositions3d();

  m_atomStructs.resize(m_mol->atomCount());

  for (int i = 0; i < m_atomStructs.size(); i++) {
    Atom current = m_mol->atom(i);
    int atomicNumber = (int)current.atomicNumber();

    m_atomStructs[i].data = data;
    m_atomStructs[i].cube = m_cube;
    m_atomStructs[i].index = i;
    m_atomStructs[i].vdwSphere = spheres[atomicNumber];
    m_atomStructs[i].numberOfVectors = numbersOfVectors[atomicNumber];
    m_atomStructs[i].position = positions[i];
  }

  //  m_cube->lock()->lockForWrite();
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(m_atomStructs, EDTSurfaceConcurrent::fillAtom);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);
}
// use isDone
void EDTSurfaceConcurrent::buildSurface()
{
  Vector3i ijk;
  int ii;
  bool flagBound;
  numberOfSurfaceVoxels = 0;

  for (int i = 0; i < data->pLength; i++) {
    for (int j = 0; j < data->pWidth; j++) {
      for (int k = 0; k < data->pHeight; k++) {
        ijk << i, j, k;
        if (m_cube->value(i, j, k) == 2) {
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

  surfaceVoxels = new Vector3i[numberOfSurfaceVoxels];
  int surfaceVoxelCount = 0;

  m_subCubes.resize(data->pLength);

  for (int i = 0; i < m_subCubes.size(); i++) {
    m_subCubes[i].data = data;
    m_subCubes[i].cube = m_cube;
    m_subCubes[i].index = i;
    m_subCubes[i].surfaceVoxels = surfaceVoxels;
    m_subCubes[i].surfaceVoxelCount = &surfaceVoxelCount;
    m_subCubes[i].numOfSurfaceVoxels = numberOfSurfaceVoxels;

  } // here we'll call buildSurfaceConcurrent

  //  m_cube->lock()->lockForWrite();
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  // The main part of the mapped reduced function...
  m_future =
    QtConcurrent::map(m_subCubes, EDTSurfaceConcurrent::buildSurfaceConcurrent);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);
}

void EDTSurfaceConcurrent::boundBox()
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

void EDTSurfaceConcurrent::initPara()
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
  data->pLength = (int)(data->pMax[0] - data->pMin[0]) / data->resolution + 1;
  data->pWidth = (int)(data->pMax[1] - data->pMin[1]) / data->resolution + 1;
  data->pHeight = (int)(data->pMax[2] - data->pMin[2]) / data->resolution + 1;
  data->scaleFactor = 1 / data->resolution;

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

void EDTSurfaceConcurrent::setCube(Core::Cube* cube)
{
  m_cube = cube;
  return;
}

void EDTSurfaceConcurrent::setMolecule(QtGui::Molecule* mol)
{
  m_mol = mol;
  return;
}

void EDTSurfaceConcurrent::setProbeRadius(double probeRadius)
{
  data->probeRadius = probeRadius;
}

bool EDTSurfaceConcurrent::inBounds(Vector3i vec)
{
  return (vec(X) > -1 && vec(Y) > -1 && vec(Z) > -1 && vec(X) < data->pLength &&
          vec(Y) < data->pWidth && vec(Z) < data->pHeight);
}
bool inBounds(Vector3i vec, dataStruct* data)
{
  return (vec(X) > -1 && vec(Y) > -1 && vec(Z) > -1 && vec(X) < data->pLength &&
          vec(Y) < data->pWidth && vec(Z) < data->pHeight);
} // this is kind of hacky, but I want it to work in both static and non-static
  // contexts
// And I don't want to have to pass data in the non-static cases

Vector3i EDTSurfaceConcurrent::round(Vector3 vec)
{
  Vector3i intVec;
  intVec(0) = (int)vec(0);
  intVec(1) = (int)vec(1);
  intVec(2) = (int)vec(2);
  return intVec;
}

Vector3 EDTSurfaceConcurrent::promote(Vector3i vec)
{
  Vector3 floatVec;
  floatVec(0) = (double)vec(0);
  floatVec(1) = (double)vec(1);
  floatVec(2) = (double)vec(2);
  return floatVec;
}

void EDTSurfaceConcurrent::fillAtom(atomStruct& edt)
{

  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i txyz; // vector from center of sphere to a point in solid
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz;  // vector from cxyz to oxyz

  cp = (edt.position + edt.data->pTran) * edt.data->scaleFactor;
  cxyz = round(cp);

  // Iterate through the vectors that lead to points in the sphere

  for (int i = 0; i < edt.numberOfVectors; i++) {
    txyz = edt.vdwSphere[i];
    oxyz = cxyz + txyz;

    // If inBounds, and not already designated as in inSolid
    // Set inSolid
    if (inBounds(oxyz, edt.data)) {
      if (edt.cube->value(oxyz) != 2) {
        edt.cube->setValue(oxyz, 2);
      } // if inSolid
    }   // if inBounds
  }
  return;
}

void EDTSurfaceConcurrent::buildSolventExcludedSolid()
{
  // When we call this function, we're building a solvent excluded surface
  // We've already built the solvent accessible solid
  // And done an EDT on all points within it
  // Now we just need to remove all points whose distance from the SAS is <=
  // probeRadius
  Array<Vector3> positions = m_mol->atomPositions3d();

  m_atomStructs.resize(m_mol->atomCount());

  for (int i = 0; i < m_atomStructs.size(); i++) {
    Atom current = m_mol->atom(i);
    int atomicNumber = (int)current.atomicNumber();

    m_atomStructs[i].data = data;
    m_atomStructs[i].cube = m_cube;
    m_atomStructs[i].index = i;
    m_atomStructs[i].vdwSphere = spheres[atomicNumber];
    m_atomStructs[i].numberOfVectors = numbersOfVectors[atomicNumber];
    m_atomStructs[i].position = positions[i];
  }

  //  m_cube->lock()->lockForWrite();//do we want to do this?
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  // The main part of the mapped reduced function...
  m_future =
    QtConcurrent::map(m_atomStructs, EDTSurfaceConcurrent::fillAtomWaals);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);
}

void EDTSurfaceConcurrent::fastDistanceMap()
{
  m_subCubes.resize(data->pLength);

  for (int i = 0; i < m_subCubes.size(); i++) {
    m_subCubes[i].data = data;
    m_subCubes[i].cube = m_cube;
    m_subCubes[i].surfaceVoxels = surfaceVoxels;
    m_subCubes[i].index = i;
  }

  //  m_cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(m_subCubes,
                               EDTSurfaceConcurrent::fastDistanceMapConcurrent);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);
}

void EDTSurfaceConcurrent::computeSphere(unsigned char atomicNumber)
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

void EDTSurfaceConcurrent::fillAtomWaals(atomStruct& edt)
{
  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i txyz; // vector from center of sphere to a point in solid
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz;  // vector from cxyz to oxyz

  cp = (edt.position + edt.data->pTran) * edt.data->scaleFactor;
  cxyz = round(cp);

  // Iterate through the vectors that lead to points in the sphere
  //
  for (int i = 0; i < edt.numberOfVectors; i++) {
    txyz = edt.vdwSphere[i];
    oxyz = cxyz + txyz;

    // If inBounds, and not already designated as in inSolid
    // Set inSolid
    if (inBounds(oxyz, edt.data)) {
      if (edt.cube->value(oxyz) <=
          edt.data->probeRadius * edt.data->scaleFactor) {
        edt.cube->setValue(oxyz, 1);
      } // if inSolid
    }   // if inBounds
  }
  return;
}

void EDTSurfaceConcurrent::buildSurfaceConcurrent(subCube& edt)
{
  Vector3i ijk;
  int i = edt.index;
  for (int j = 0; j < edt.data->pWidth; j++) {
    for (int k = 0; k < edt.data->pHeight; k++) {
      if (edt.cube->value(i, j, k) == 0) {
        ijk << i, j, k;
        edt.surfaceVoxels[*edt.surfaceVoxelCount] = ijk;
        (*edt.surfaceVoxelCount)++;
      }
    }
  }
}

void EDTSurfaceConcurrent::calculationComplete()
{
  disconnect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  //  m_cube->lock()->unlock();
  //  m_cube->update();
}

void EDTSurfaceConcurrent::fastDistanceMapConcurrent(subCube& edt)
{
  Vector3i ijk;
  Vector3i txyz; // Vector pulled from array of boundary points
  Vector3 dxyz;  // Vector from ijk to dxyz
  double distance = 0;

  // First we set surfacePoints' distance equal to zero
  // And move all the surfacePoints into a 1D array

  int i = edt.index;

  // Then for each point, if it's in the solid and not on the surface
  // We check the distance to each point on the surface and save the min in the
  // cube

  for (int j = 0; j < edt.data->pWidth; j++) {
    for (int k = 0; k < edt.data->pHeight; k++) {
      distance = 0;
      if (edt.cube->value(i, j, k) == 2) {
        ijk << i, j, k;
        for (int l = 0; l < edt.numOfSurfaceVoxels; l++) {
          txyz = edt.surfaceVoxels[l];
          dxyz = promote(txyz - ijk);
          if (distance == 0 || dxyz.norm() < distance) {
            distance = dxyz.norm();
          } // end if distance
        }   // end for l
        edt.cube->setValue(i, j, k, distance);
      } // end if in solid
    }   // end for k
  }     // end for j
}

} // namespace QtPlugins

} // End namespace Avogadro
