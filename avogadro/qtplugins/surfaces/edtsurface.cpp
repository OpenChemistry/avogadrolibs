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

#define VWS 0
#define MS 1
#define SAS 2
#define SES 3

#define X 0
#define Y 1
#define Z 2

#define I 0
#define J 1
#define K 2

static int neighbors[26][3] = {
  1, 0,  0,  -1, 0,  0, 0, 1,  0,  0,  -1, 0, 0,  0,  1,  0,  0,  -1, 1, 1,
  0, 1,  -1, 0,  -1, 1, 0, -1, -1, 0,  1,  0, 1,  1,  0,  -1, -1, 0,  1, -1,
  0, -1, 0,  1,  1,  0, 1, -1, 0,  -1, 1,  0, -1, -1, 1,  1,  1,  1,  1, -1,
  1, -1, 1,  -1, 1,  1, 1, -1, -1, -1, -1, 1, -1, 1,  -1, -1, -1, -1
};

static bool bTypes[4] = { false, true, true, true };

static bool atomTypes[4] = { false, false, true, false };

using namespace Avogadro::Core;

namespace Avogadro {
namespace QtPlugins {

// Constructor
EDTSurface::EDTSurface()
{

  data = (dataStruct*)malloc(sizeof(dataStruct));
  //	data->pTran(0.0,0.0,0.0);
  data->pTran(X) = 0.0;
  data->pTran(Y) = 0.0;
  data->pTran(Z) = 0.0;

  data->boxLength = 128;
  data->probeRadius = 1.4;
  data->fixSf = 1;
  data->scaleFactor = 0;
  //  data->pMin(0.0,0.0,0.0);
  data->pMin(X) = 0.0;
  data->pMin(Y) = 0.0;
  data->pMin(Z) = 0.0;
  //	data->pMax(0.0,0.0,0.0);
  data->pMax(X) = 0.0;
  data->pMax(Y) = 0.0;
  data->pMax(Z) = 0.0;

  data->pHeight = 0;
  data->pWidth = 0;
  data->pLength = 0;

  data->cutRadius = 0;
  m_cube = NULL;
  m_mol = NULL;
}

// Destructor
EDTSurface::~EDTSurface()
{
  int i, j;

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      delete[] atomIds[i][j];
    }
    delete[] atomIds[i];
  }
  delete[] atomIds;

  free(data);
  //	data->widXz = NULL;
}

// Takes a molecule and a surface type and returns a cube

Core::Cube* EDTSurface::EDTCube(QtGui::Molecule* mol, Core::Cube* cube,
                                Surfaces::Type surfType, double probeRadius)
{
  this->setProbeRadius(probeRadius);
  return this->EDTCube(mol, cube, surfType);
}

Core::Cube* EDTSurface::EDTCube(QtGui::Molecule* mol, Core::Cube* cube,
                                Surfaces::Type surfType)
{

  qDebug() << " starting " << mol->atomCount();
  qDebug() << " type: " << surfType;

  int surfaceType;

  if (surfType == Surfaces::VanDerWaals) {
    surfaceType = VWS;
    qDebug() << " VWS " << VWS;
  } else if (surfType == Surfaces::SolventExcluded) {
    surfaceType = SES;
  } else if (surfType == Surfaces::SolventAccessible) {
    surfaceType = SAS;
  } else {
    return NULL;
    // This isn't the right class for that surfaceType
  }

  if(surfaceType == VWS){
    setProbeRadius(0.0);
  }

  qDebug() << " surfaceType " << surfaceType;
  this->setCube(cube);

  this->setMolecule(mol);
  // Set molecule

  this->initPara(atomTypes[surfaceType], bTypes[surfaceType]);
  // Initialize everything

  qDebug() << " done with initialization ";
  qDebug() << "minval: " << m_cube->minValue()
           << " maxval: " << m_cube->maxValue();
  qDebug() << " pLength " << data->pLength << " pWidth " << data->pWidth
           << " pHeight " << data->pHeight;

  this->fillVoxels(atomTypes[surfaceType]);
  // Generate the molecular solid

  qDebug() << " done with voxels ";

  this->buildBoundary();

  qDebug() << " done with boundary ";

  //  if (surfaceType == SAS || surfaceType == SES) {
  this->fastDistanceMap();

  if (surfaceType == SES) {
    this->fillVoxelsWaals();
    this->buildBoundary();
    this->fastDistanceMap();
  }

  qDebug() << " done with fast distance map"
           << "minval: " << m_cube->minValue()
           << " maxval: " << m_cube->maxValue() << " surfaceVox "
           << data->totalSurfaceVox << " totalInnerVox" << data->totalInnerVox;

  return m_cube;
}

void EDTSurface::fastDistanceMap()
{
  int i, j, k;
  Vector3i ijk;
  data->totalSurfaceVox = 0;
  data->totalInnerVox = 0;

  Vector3i*** boundPoint;

  // In this section, we create a 3D array of Vector3is that maps to our voxels
  // We then iterate through the cube, and if a voxel is in the solid
  // We designate it as either a surface voxel or an inner voxel
  // If it is a surface voxel, we set distance to 0
  // And add a vector to that point at that location in boundPoint

  boundPoint = new Vector3i**[data->pLength];
  for (i = 0; i < data->pLength; i++) {
    boundPoint[i] = new Vector3i*[data->pWidth];
    for (j = 0; j < data->pWidth; j++) {
      boundPoint[i][j] = new Vector3i[data->pHeight];
      for (k = 0; k < data->pHeight; k++) {
        processed->setValue(i, j, k, false);
        if (!inSolid->value(i, j, k)) {
          if (onSurface->value(i, j, k)) {
            data->totalSurfaceVox++;
            ijk(I) = i;
            ijk(J) = j;
            ijk(K) = k;
            boundPoint[i][j][k] = ijk;
            m_cube->setValue(i, j, k, 0);
            processed->setValue(i, j, k, true);
          } else {
            data->totalInnerVox++;
          }
        }
      }
    }
  }

  int allocIn = int(1.2 * data->totalSurfaceVox);
  int allocOut = int(1.2 * data->totalSurfaceVox);
  // AllocIn and allocOut are both 1.2 times the surfaceVox

  if (allocIn > data->totalInnerVox)
    allocIn = data->totalInnerVox;

  if (allocIn < data->totalSurfaceVox)
    allocIn = data->totalSurfaceVox;

  // allocIn is the max of totalSurfaceVox and (the min of totalInnerVox and 1.2
  // * totalSurfaceVox)

  if (allocOut > data->totalInnerVox)
    allocOut = data->totalInnerVox;

  // allocOut is the min of totalInnerVox and 1.2 * totalSurfaceVox

  data->inArray = new Vector3i[allocIn];
  data->outArray = new Vector3i[allocOut];

  data->positIn = 0;
  data->positOut = 0;

  // In this section, we populate inArray with vectors pointing to surface
  // voxels positIn is the number of elements in that array

  qDebug() << " surfaceVox " << data->totalSurfaceVox;
  qDebug() << " totalInnerVox " << data->totalInnerVox;

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      for (k = 0; k < data->pHeight; k++) {
        if (onSurface->value(i, j, k)) {
          ijk(I) = i;
          ijk(J) = j;
          ijk(K) = k;
          data->inArray[data->positIn] = ijk;
          data->positIn++;
          onSurface->setValue(i, j, k, false); // as flag of data->outArray
        }
      }
    }
  }
  data->certificate = data->totalInnerVox;
  ///////////////////////////////////////////////////

  do {
    fastOneShell(&data->positIn, &allocOut, boundPoint, &data->positOut,
                 &data->eliminate);
    //	printf("%d %d %d %d
    //%d\n",data->positIn,allocOut,data->positOut,data->totalSurfaceVox,data->totalInnerVox);
    data->certificate -= data->eliminate;

    data->positIn = 0;
    for (i = 0; i < data->positOut; i++) {
      onSurface->setValue(data->outArray[i], false);
      if (m_cube->value(data->outArray[i]) <= 1.02 * data->cutRadius) {
        data->inArray[data->positIn] = data->outArray[i];
        data->positIn++;
      }
      if (data->positIn >= allocIn) {
        allocIn *= 2;
        if (allocIn > data->totalInnerVox)
          allocIn = data->totalInnerVox;
        data->inArray =
          (Vector3i*)realloc(data->inArray, allocIn * sizeof(Vector3i));
      }
    }
  } while (data->positIn != 0);

  if (data->certificate != 0) {
    //	printf("wrong number\n");
  }

  delete[] data->inArray;
  delete[] data->outArray;

  double cutsf = data->scaleFactor - 0.5;
  if (cutsf < 0)
    cutsf = 0;
  //	 cutsf=100000000;
  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      for (k = 0; k < data->pHeight; k++) {
        onSurface->setValue(i, j, k, false);
        // ses solid
        if (inSolid->value(i, j, k)) {
          if (!processed->value(i, j, k) ||
               m_cube->value(i, j, k) >=
                 data->cutRadius -
                   0.50 / (0.1 + cutsf)) // 0.33  0.75/data->scaleFactor
           {
            onSurface->setValue(i, j, k, true);
            // new add
            if (processed->value(i, j, k))
              atomIds[i][j][k] = atomId(boundPoint[i][j][k]);
          }
        }
      }
    }
  }

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      delete[] boundPoint[i][j];
    }
    delete[] boundPoint[i];
  }
  delete[] boundPoint;
}

void EDTSurface::fastOneShell(int* inNum, int* allocOut, Vector3i*** boundPoint,
                              int* outNum, int* elimi)
{
  int i, number;
  Vector3 dxyz;
  Vector3i txyz;
  data->eliminate = 0;
  float squre;
  data->positOut = 0;
  number = *inNum;
  if (number == 0)
    return;
  // new code
  int j;
  Vector3i tnv;

  for (i = 0; i < number; i++) {
    // if(allocOut <= 6)
    if (data->positOut >= (*allocOut) - 6) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > data->totalInnerVox)
        *allocOut = data->totalInnerVox;
      //        qDebug() << " allocOut " << *allocOut;
      data->outArray =
        (Vector3i*)realloc(data->outArray, (*allocOut) * sizeof(Vector3i));
    }
    //    qDebug() << " fastOneShell executing ";
    txyz = data->inArray[i];
    // txyz is full of vectors pointing to points on the surface

    for (j = 0; j < 6; j++) {

      tnv = txyz + vectorFromArray(neighbors[j]);

      // tnv is a vector pointing to a point neighboring the one we got from the
      // surface

      if (inBounds(tnv) && inSolid->value(tnv) && !processed->value(tnv)) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);

        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        processed->setValue(tnv, true);
        onSurface->setValue(tnv, true);

        qDebug() << "positOut" << data->positOut << "tnv" << tnv[0] << tnv[1] << tnv[2];

        data->outArray[data->positOut] = tnv;
        //this is a problem now when it wasn't before??

        data->positOut++;
        data->eliminate++;
      } else if (inBounds(tnv) && inSolid->value(tnv) && processed->value(tnv))
      {
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        if (dxyz.norm() < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
          if (!onSurface->value(tnv)) {
            onSurface->setValue(tnv, true);
            data->outArray[data->positOut] = tnv;
            data->positOut++;
          }
        }
      }
    }
  }

  for (i = 0; i < number; i++) {
    if (data->positOut >= (*allocOut) - 12) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > data->totalInnerVox)
        *allocOut = data->totalInnerVox;

      data->outArray =
        (Vector3i*)realloc(data->outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = data->inArray[i];
    for (j = 6; j < 18; j++) {
      tnv = txyz + vectorFromArray(neighbors[j]);
      // So nothing happens here if !inBounds(tnv) || !inOut
      if (inBounds(tnv) && inSolid->value(tnv) &&!processed->value(tnv)) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        processed->setValue(tnv, true);
        onSurface->setValue(tnv, true);

        data->outArray[data->positOut] = tnv;
        data->positOut++;
        data->eliminate++;
      }
      else if (inBounds(tnv) && inSolid->value(tnv) && processed->value(tnv)) {
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        squre = dxyz.norm();
        if (squre < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, float(squre) * data->scaleFactor);
          if (!onSurface->value(tnv)) {
            onSurface->setValue(tnv, true);
            data->outArray[data->positOut] = tnv;
            data->positOut++;
          }
        }
      }
    }
  }
  for (i = 0; i < number; i++) {
    if (data->positOut >= (*allocOut) - 9) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > data->totalInnerVox)
        *allocOut = data->totalInnerVox;
      data->outArray =
        (Vector3i*)realloc(data->outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = data->inArray[i];

    for (j = 18; j < 26; j++) {
      tnv = txyz + vectorFromArray(neighbors[j]);
      if (inBounds(tnv) && inSolid->value(tnv) && !processed->value(tnv)) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        processed->setValue(tnv, true);
        onSurface->setValue(tnv, true);
        data->outArray[data->positOut] = tnv;
        data->positOut++;
        data->eliminate++;
      } else if (inBounds(tnv) && inSolid->value(tnv) && processed->value(tnv)) {

        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);

        if (dxyz.norm() < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
          if (!onSurface->value(tnv)) {
            onSurface->setValue(tnv, true);
            data->outArray[data->positOut] = tnv;
            data->positOut++;
          }
        }
      }
    }
  }

  *outNum = data->positOut;
  *elimi = data->eliminate;
}

// sas use inOut
void EDTSurface::fillVoxels(bool atomType)
{

  int i;

  int numberOfAtoms = m_mol->atomCount();

  for (i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = m_mol->atom(index);
    if (!atomType || current.atomicNumber() != 1) {
      fillAtom(index);
    }
    //			totalNumber++;
  }

}
// use isDone
void EDTSurface::buildBoundary()
{
  int i, j, k;
  Vector3i ikj;
  int ii;
  bool flagBound;

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pHeight; j++) {
      for (k = 0; k < data->pWidth; k++) {
        ikj(I) = i;
        ikj(J) = k;
        ikj(K) = j;
        if (inSolid->value(i, k, j)) {
          flagBound = false;
          ii = 0;
          while (!flagBound && ii < 26) {
            if (inBounds(ikj + vectorFromArray(neighbors[ii])) &&
                !inSolid->value(ikj + vectorFromArray(neighbors[ii]))) {
              onSurface->setValue(ikj, true);
              flagBound = true;
            } else
              ii++;
          }
        }
      }
    }
  }
}

void EDTSurface::boundBox(bool atomType)
{
  /**
   *Finds the bound box of the sequence of atoms
   *The smallest rectangular prism that contains all the atoms
   *@param minPoint A pointer to a vector representing the minimum point
   *@param maxPoint A pointer to a vector representing the maximum point
   **/

  int i;

  int numberOfAtoms = m_mol->atomCount();
  Array<Vector3> positions = m_mol->atomPositions3d();

  data->pMin(X) = 100000;
  data->pMin(Y) = 100000;
  data->pMin(Z) = 100000;
  data->pMax(X) = -100000;
  data->pMax(Y) = -100000;
  data->pMax(Z) = -100000;

  for (i = 0; i < numberOfAtoms; i++) {
    Atom current = m_mol->atom(i);
    if (!atomType || current.atomicNumber() != 1) {
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

void EDTSurface::initPara(bool atomType, bool bType)
{
  int i, j, k;
  data->fixSf = 4;
  double fMargin = 2.5;

  boundBox(atomType);

  qDebug() << " bound box done ";
  qDebug() << " PMin X " << data->pMin(X) << " PMin Y " << data->pMin(Y)
           << " PMin Z " << data->pMin(Z);
  qDebug() << " PMax X " << data->pMax(X) << " PMax Y " << data->pMax(Y)
           << " PMax Z " << data->pMax(Z);

  if (bType == false) {
    data->pMin(X) -= fMargin;
    data->pMin(Y) -= fMargin;
    data->pMin(Z) -= fMargin;
    data->pMax(X) += fMargin;
    data->pMax(Y) += fMargin;
    data->pMax(Z) += fMargin;
  } else {
    data->pMin(X) -= data->probeRadius + fMargin;
    data->pMin(Y) -= data->probeRadius + fMargin;
    data->pMin(Z) -= data->probeRadius + fMargin;
    data->pMax(X) += data->probeRadius + fMargin;
    data->pMax(Y) += data->probeRadius + fMargin;
    data->pMax(Z) += data->probeRadius + fMargin;
  }

  data->pTran = -data->pMin;

  // data->pTran is the vector to get us to our minimum x, minimum y, and
  // minimum z points

  data->scaleFactor = data->pMax(X) - data->pMin(X);
  if ((data->pMax(Y) - data->pMin(Y)) > data->scaleFactor)
    data->scaleFactor = data->pMax(Y) - data->pMin(Y);
  if ((data->pMax(Z) - data->pMin(Z)) > data->scaleFactor)
    data->scaleFactor = data->pMax(Z) - data->pMin(Z);

  qDebug() << " scaleFactor " << data->scaleFactor;

  // data->scaleFactor is the maximum distance between our mins and maxes

  data->scaleFactor = (data->boxLength - 1.0) / double(data->scaleFactor);
  ///////////////////////////add this automatically first fix sf then fix
  /// data->boxLength
  //	/*
  data->boxLength = int(data->boxLength * data->fixSf / data->scaleFactor);
  data->scaleFactor = data->fixSf;
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

//  boundingAtom(bType);

  Vector3 zeroVector(0.0, 0.0, 0.0);
  Vector3i pDimensions(data->pLength, data->pWidth, data->pHeight);
  double spacing = 0.;
  m_cube->setLimits(zeroVector, pDimensions, spacing);


  data->cutRadius = data->probeRadius * data->scaleFactor;

  inSolid = new BitVector(data->pLength, data->pWidth, data->pHeight);
  onSurface = new BitVector(data->pLength, data->pWidth, data->pHeight);
  processed = new BitVector(data->pLength, data->pWidth, data->pHeight);

//  inSolid = new BoolCube(data->pLength, data->pWidth, data->pHeight);
//  onSurface = new BoolCube(data->pLength, data->pWidth, data->pHeight);
//  processed = new BoolCube(data->pLength, data->pWidth, data->pHeight);

  computed = new bool[128];
  spheres = new Vector3i*[128];
  numbersOfVectors = new int[128];

  for(int i = 0; i < 128; i++){
    computed[i] = false;
    spheres[i] = NULL;
    numbersOfVectors[i] = -1;
  }

  atomIds = new int**[data->pLength];

  for (i = 0; i < data->pLength; i++) {
    atomIds[i] = new int*[data->pWidth];
    for (j = 0; j < data->pWidth; j++) {
      atomIds[i][j] = new int[data->pHeight];
      for (k = 0; k < data->pHeight; k++) {
        atomIds[i][j][k] = -1;
        m_cube->setValue(i, j, k, -1);
      }
    }
  }
}

Vector3i EDTSurface::vectorFromArray(int* array)
{
  Vector3i vec;
  vec(0) = array[0];
  vec(1) = array[1];
  vec(2) = array[2];
  return vec;
}

void EDTSurface::setCube(Core::Cube* cube)
{
  m_cube = cube;
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

int EDTSurface::atomId(Vector3i vec)
{
  return atomIds[vec(0)][vec(1)][vec(2)];
}

Vector3i EDTSurface::round(Vector3 vec)
{
  Vector3i intVec;
  intVec(0) = (int)vec(0) + 0.5;
  intVec(1) = (int)vec(1) + 0.5;
  intVec(2) = (int)vec(2) + 0.5;
  return intVec;
}

Vector3 EDTSurface::promote(Vector3i vec){
  Vector3 floatVec;
  floatVec(0) = (double)vec(0);
  floatVec(1) = (double)vec(1);
  floatVec(2) = (double)vec(2);
  return floatVec;
}

double EDTSurface::getScaleFactor(){
  if(m_cube == NULL){
    return 0;
  }
  else{
    return data->scaleFactor;
  }
}

Vector3 EDTSurface::getPTran(){
  if(m_cube == NULL){
    data->pTran *= 0.0;
  }
  return data->pTran;
}

void EDTSurface::fillAtom(int indx){

  int otherIndex; // used in the event of overlapping radii

  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz; // vector from cxyz to oxyz
  Vector3i txyz; // vector from center of sphere to a point in solid
  Vector3 axyz; // additional vector used to determine which atom is closer

  //Obtain the current atom
  Atom current = m_mol->atom(indx);

  //Obtain its position, translate, and scale
  Array<Vector3> positions = m_mol->atomPositions3d();
  cp = (positions[indx] + data->pTran) * data->scaleFactor;
  cxyz = round(cp);

  //Obtain its atomic number
  int atomicNumber = current.atomicNumber();

  //If we haven't already computed the sphere for that element, do that
  if(!computed[atomicNumber]){
    computeSphere(atomicNumber);
  }

  //Iterate through the vectors that lead to points in the sphere
  //
  for(int i = 0; i < numbersOfVectors[atomicNumber]; i++){
    txyz = spheres[atomicNumber][i];
    oxyz = cxyz + txyz;

  //If inBounds, and not already designated as in inSolid
  //Set inSolid, processed and atomId
    if(inBounds(oxyz)){
      if(!inSolid->value(oxyz)){
        inSolid->setValue(oxyz, true);
        processed->setValue(oxyz, true);
        atomIds[oxyz(X)][oxyz(Y)][oxyz(Z)] = indx;
      }//if _
      //If in bounds, but already designated as in solid
      //Check which atom is closer and set atomId to that
      else{
        otherIndex = atomId(oxyz);
        txyz = round(positions[otherIndex]);
        axyz = promote(oxyz - txyz);
        if(axyz.squaredNorm() > txyz.squaredNorm()){
          atomIds[oxyz(X)][oxyz(Y)][oxyz(Z)] = indx;
        }//if axyz.squaredNorm
      }//else
    }//if inBounds
  }
  return;
}

void EDTSurface::fillVoxelsWaals(){
  //When we call this function, we're building a solvent excluded surface
  //We've already built the solvent accessible solid
  //And done an EDT on all points within it
  //Now we just need to remove all points whose distance from the SAS is <= probeRadius

  for(int i = 0; i < data->pLength; i++){
    for(int j = 0; j < data->pWidth; j++){
      for(int k = 0; k < data->pHeight; k++){
        if(inSolid->value(i, j, k) && m_cube->value(i, j, k) <= data->probeRadius){
          inSolid->setValue(i, j, k, false);
        }
      }
    }
  }
}

void EDTSurface::computeSphere(unsigned char atomicNumber){
  Vector3i dxyz;

  double scaledRad = (element_VDW[atomicNumber] + data->probeRadius) * data->scaleFactor + 0.5;
  int scaledRadius = (int)scaledRad;
  int dPlusOne = 2 * scaledRadius + 1;

  spheres[atomicNumber] = new Vector3i[dPlusOne * dPlusOne * dPlusOne];
  //This is a significant overallocation, but it's okay, we'll fix it
  //(This is the number of points with integer coords in the cube we're going to construct)
  //(It is a theoretical upper bound for points with integer coords in the sphere)
  //(There's definitely fewer than this, but it's difficult to say how many)

  int count = 0;

  //We construct the cube containing the sphere
  //And check every point within it to see if it's within the radius
  //If it is, we add to our list a vector to that point

  for(int i = -scaledRadius; i <= scaledRadius; i++){
    for(int j = -scaledRadius; j <= scaledRadius; j++){
      for(int k = -scaledRadius; k <= scaledRadius; k++){
        dxyz(X) = i;
        dxyz(Y) = j;
        dxyz(Z) = k;
        if(dxyz.norm()<= scaledRadius){
          spheres[atomicNumber][count] = dxyz;
          count++;
        }
      }
    }
  }

  //Create a new array of a more appropriate size
  Vector3i* tempOne;
  tempOne = new Vector3i[count];

  //Copy values from spheres[atomicNumber] into it
  for(int i = 0; i < count; i++){
    tempOne[i] = spheres[atomicNumber][i];
  }

  //Free the old memory
  free(spheres[atomicNumber]);

  //Point the pointer to the new array
  spheres[atomicNumber] = tempOne;

  //Set numbersOfVectors
  numbersOfVectors[atomicNumber] = count;

  //And computed
  computed[atomicNumber] = true;

  return;
}

} // End namespace Core

} // End namespace Avogadro
