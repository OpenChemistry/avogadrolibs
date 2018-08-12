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

// static double rasrad[
// ]={1.872,1.872,1.507,1.4,1.848,1.1,1.88,1.872,1.507,1.948,1.5,
// 1.4, 1.1};//lsms
static double rasRad[] = { 1.90, 1.88, 1.63, 1.48, 1.78, 1.2, 1.87,
                           1.96, 1.63, 0.74, 1.8,  1.48, 1.2 }; // liang
//                         ca   c    n    o    s    h   p   cb    ne   fe  other
//                         ox  hx

using namespace Avogadro::Core;

namespace Avogadro {
namespace QtPlugins {

// Constructor
EDTSurface::EDTSurface()
{
  int i;

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

  data->widXz = new int[13];
  data->deptY = new int*[13];

  for (i = 0; i < 13; i++) {
    data->widXz[i] = 0;
    data->deptY[i] = NULL;
  }
  data->cutRadius = 0;
  m_cube = NULL;
  m_mol = NULL;
}

// Destructor
EDTSurface::~EDTSurface()
{
  int i, j;

  for (i = 0; i < 13; i++) {
    delete[] data->deptY[i];
  }
  delete[] data->deptY;
  //	data->deptY = NULL;

  delete[] data->widXz;

  for (i = 0; i < data->pLength; i++) {
    for (j = 0; j < data->pWidth; j++) {
      delete[] _isBound[i][j];
      delete[] _inOut[i][j];
      delete[] _isDone[i][j];
      delete[] atomIds[i][j];
    }
    delete[] _isBound[i];
    delete[] _inOut[i];
    delete[] _isDone[i];
    delete[] atomIds[i];
  }

  delete[] _isBound;
  delete[] _inOut;
  delete[] _isDone;
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
//    this->boundingAtom(false);
    qDebug() << " done with boundingAtom: ";
//    this->fillVoxelsWaals(atomTypes[surfaceType]);
    qDebug() << " done with fillVoxelsWaals ";
    //this->seansFillVoxelsWaals();
    //this->buildBoundary();
    //this->fastDistanceMap();
  }
  //  }
  // EDT (if applicable)

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
        _isDone[i][j][k] = false;
        if (_inOut[i][j][k]) {
          if (_isBound[i][j][k]) {
            data->totalSurfaceVox++;
            ijk(I) = i;
            ijk(J) = j;
            ijk(K) = k;
            boundPoint[i][j][k] = ijk;
            m_cube->setValue(i, j, k, 0);
            _isDone[i][j][k] = true;
          } else {
            // So we're never reaching this place
            // Are the totalInnerVox erroneously being marked surfaceVox
            // Or are they erroneously being excluded from the solid
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
        if (_isBound[i][j][k]) {
          ijk(I) = i;
          ijk(J) = j;
          ijk(K) = k;
          data->inArray[data->positIn] = ijk;
          data->positIn++;
          _isBound[i][j][k] = false; // as flag of data->outArray
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
      _isBound[data->outArray[i](X)][data->outArray[i](Y)]
              [data->outArray[i](Z)] = false;
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
        _isBound[i][j][k] = false;
        // ses solid
        if (_inOut[i][j][k]) {
          if (!_isDone[i][j][k] ||
              (_isDone[i][j][k] &&
               m_cube->value(i, j, k) >=
                 data->cutRadius -
                   0.50 / (0.1 + cutsf)) // 0.33  0.75/data->scaleFactor
          ) {
            _isBound[i][j][k] = true;
            // new add
            if (_isDone[i][j][k])
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

      if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
          !_isDone[tnv(X)][tnv(Y)][tnv(Z)]) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);

        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        _isDone[tnv(X)][tnv(Y)][tnv(Z)] = true;
        _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;

        data->outArray[data->positOut] = tnv;

        data->positOut++;
        data->eliminate++;
      } else if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
                 _isDone[tnv(X)][tnv(Y)][tnv(Z)]) {
        dxyz =promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        if (dxyz.norm() < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
          if (!_isBound[tnv(X)][tnv(Y)][tnv(Z)]) {
            _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;
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

      // we're passing this realloc 0.  Why?

      data->outArray =
        (Vector3i*)realloc(data->outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = data->inArray[i];
    for (j = 6; j < 18; j++) {
      tnv = txyz + vectorFromArray(neighbors[j]);
      // So nothing happens here if !inBounds(tnv) || !inOut
      if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
          !_isDone[tnv(X)][tnv(Y)][tnv(Z)]) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        _isDone[tnv(X)][tnv(Y)][tnv(Z)] = true;
        _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;
        data->outArray[data->positOut] = tnv;
        data->positOut++;
        data->eliminate++;
      } else if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
                 _isDone[tnv(X)][tnv(Y)][tnv(Z)]) {
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        squre = dxyz.norm();
        if (squre < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, float(squre) * data->scaleFactor);
          if (!_isBound[tnv(X)][tnv(Y)][tnv(Z)]) {
            _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;
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
      if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
          !_isDone[tnv(X)][tnv(Y)][tnv(Z)]) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);
        m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
        _isDone[tnv(X)][tnv(Y)][tnv(Z)] = true;
        _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;
        data->outArray[data->positOut] = tnv;
        data->positOut++;
        data->eliminate++;
      } else if (inBounds(tnv) && _inOut[tnv(X)][tnv(Y)][tnv(Z)] &&
                 _isDone[tnv(X)][tnv(Y)][tnv(Z)]) {

        dxyz = promote(tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)]);

        if (dxyz.norm() < m_cube->value(tnv)) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          m_cube->setValue(tnv, dxyz.norm() * data->scaleFactor);
          if (!_isBound[tnv(X)][tnv(Y)][tnv(Z)]) {
            _isBound[tnv(X)][tnv(Y)][tnv(Z)] = true;
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

void EDTSurface::fillAtom(int indx)
{

  Vector3 cp; // vector containing coordinates of atom at position indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest integers
  Vector3i oxyz;

  Array<Vector3> positions = m_mol->atomPositions3d();

  cp = (positions[indx] + data->pTran) * data->scaleFactor;

  cxyz = round(cp);

  Index index = indx;
  Atom current = m_mol->atom(index);
  int at = detail(current.atomicNumber());

  int i, j, k;
  int ii, jj, kk;
  int mi, mj, mk;

  Vector3i mijk;
  Vector3i sijk;

  int tIndex;
  int nIndex = 0;
  for (i = 0; i < data->widXz[at]; i++) {
    for (j = 0; j < data->widXz[at]; j++) {
      if (data->deptY[at][nIndex] != -1) {
        for (ii = -1; ii < 2; ii += 2) {
          for (jj = -1; jj < 2; jj += 2) {
            for (kk = -1; kk < 2; kk += 2) {
              mi = ii * i;
              mk = kk * j;
              for (k = 0; k <= data->deptY[at][nIndex]; k++) {
                mj = k * jj;
                mijk(I) = mi;
                mijk(J) = mj;
                mijk(K) = mk;
                sijk = cxyz + mijk;

                if (!inBounds(sijk)) {
                  continue;
                }

                // So either we're not producing the right vectors here
                // Or inBounds is wrongly excluding them(less likely)
                // boundingAtom seems to be doing its job
                // Which would mean the issue's somewhere in that god-awful loop

                else {
                  if (_inOut[sijk(I)][sijk(J)][sijk(K)] == false) {
                    _inOut[sijk(I)][sijk(J)][sijk(K)] = true;
                    _isDone[sijk(I)][sijk(J)][sijk(K)] = true;
                    atomIds[sijk(I)][sijk(J)][sijk(K)] = indx;
                  }
                  // If voxel isn't occupied, designate it as occupied
                  // And make a note of which atom occupies it
                  //*

                  else if (_inOut[sijk(I)][sijk(J)][sijk(K)]) {
                    tIndex = atomIds[sijk(I)][sijk(J)][sijk(K)];
                    cp = (positions[tIndex] + data->pTran) * data->scaleFactor;

                    oxyz = round(cp) - sijk;

                    // mijk.squaredNorm is the distance to the new atom
                    // oxyz.squaredNorm is the distance to the old atom
                    // if the new atom is closer than the old atom
                    // then designate atomId as the new atom
                    if (mijk.squaredNorm() < oxyz.squaredNorm())
                      atomIds[sijk(I)][sijk(J)][sijk(K)] = indx;
                    //
                  }
                  // This should be an arcane way of saying
                  // That if a given ijk is within the atomic radius of an
                  // atom Then We assign that atom's id to atomids[ijk]
                  //	*/
                } // k
              }   // else
            }     // kk
          }       // jj
        }         // ii

      } // if
      nIndex++;
    } // j
  }   // i
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
      seansFillAtom(index);
    }
    //			totalNumber++;
  }
  // This can also be done concurrently if we write a function for it
  //	printf("%d\n",totalNumber);

  // This can be done concurrently if we write a function for it
}
// use isDone
void EDTSurface::fillVoxelsWaals(bool atomType)
{
  int i;

  int numberOfAtoms = m_mol->atomCount();

  for (i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = m_mol->atom(index);
    if (!atomType || current.atomicNumber() != 1) {
      fillAtomWaals(i);
    }
  }
}

void EDTSurface::fillAtomWaals(int indx)
{
  //  int cx, cy, cz;
  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i oxyz;

  Array<Vector3> positions = m_mol->atomPositions3d();
  Atom current = m_mol->atom(indx);

  cp = (positions[indx] + data->pTran) * data->scaleFactor;
  // Translating and scaling

  cxyz = round(cp);

  int at = detail(current.atomicNumber());
  int i, j, k;
  int ii, jj, kk;
  Vector3i mijk;
  Vector3i sijk;
  int tIndex;
  int nIndex = 0;

  for (i = 0; i < data->widXz[at]; i++) {
    for (j = 0; j < data->widXz[at]; j++) {
      if (data->deptY[at][nIndex] != -1) {
        for (ii = -1; ii < 2; ii += 2) {
          for (jj = -1; jj < 2; jj += 2) {
            for (kk = -1; kk < 2; kk += 2) {
              mijk(I) = ii * i;
              mijk(K) = kk * j;
              for (k = 0; k <= data->deptY[at][nIndex]; k++) {
                mijk(J) = jj * k;
                sijk = cxyz + mijk;
                if (sijk(I) < 0 || sijk(J) < 0 || sijk(K) < 0) {
                  continue;
                }

                else {
                  if (!isDone(sijk)) {
                    _isDone[sijk(I)][sijk(J)][sijk(K)] = true;
                    atomIds[sijk(I)][sijk(J)][sijk(K)] = indx;
                  }
                  // with atomic info change above line
                  //*
                  else if (_isDone[sijk(I)][sijk(J)][sijk(K)]) {
                    tIndex = atomIds[sijk(I)][sijk(J)][sijk(K)];
                    cp = (positions[tIndex] + data->pTran) * data->scaleFactor;
                    // Translating and scaling
                    oxyz = cxyz - sijk;
                    if (mijk.squaredNorm() < oxyz.squaredNorm())
                      atomIds[sijk(I)][sijk(J)][sijk(K)] = indx;
                  }
                  //	 */
                } // else
              }   // k
            }     // kk
          }       // jj
        }         // ii

      } // if
      nIndex++;
    } // j
  }   // i
}

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
        if (_inOut[i][k][j]) {
          flagBound = false;
          ii = 0;
          while (!flagBound && ii < 26) {
            if (inBounds(ikj + vectorFromArray(neighbors[ii])) &&
                !inOut(ikj + vectorFromArray(neighbors[ii]))) {
              _isBound[i][k][j] = true;
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

  _inOut = new bool**[data->pLength];
  _isDone = new bool**[data->pLength];
  _isBound = new bool**[data->pLength];
  atomIds = new int**[data->pLength];

  for (i = 0; i < data->pLength; i++) {
    _inOut[i] = new bool*[data->pWidth];
    _isDone[i] = new bool*[data->pWidth];
    _isBound[i] = new bool*[data->pWidth];
    atomIds[i] = new int*[data->pWidth];
    for (j = 0; j < data->pWidth; j++) {
      _inOut[i][j] = new bool[data->pHeight];
      _isDone[i][j] = new bool[data->pHeight];
      _isBound[i][j] = new bool[data->pHeight];
      atomIds[i][j] = new int[data->pHeight];
      for (k = 0; k < data->pHeight; k++) {
        _inOut[i][j][k] = false;
        _isDone[i][j][k] = false;
        _isBound[i][j][k] = false;
        atomIds[i][j][k] = -1;
        m_cube->setValue(i, j, k, -1);
      }
    }
  }
}

void EDTSurface::boundingAtom(bool bType)
{

  // This function populates widXz and deptY with values (radii) based on atomic
  // numbers It is functioning correctly

  int i, j, k;
  double tRadius[13];
  double tXz, tDepth, sRadius;
  int indx;
  for (i = 0; i < 13; i++) {
    if (data->deptY[i] != NULL)
      delete[] data->deptY[i];
  }

  for (i = 0; i < 13; i++) {
    if (bType == false)
      tRadius[i] = rasRad[i] * data->scaleFactor + 0.5;
    else
      tRadius[i] = (rasRad[i] + data->probeRadius) * data->scaleFactor + 0.5;

    // Multiply by data->scaleFactor
    // Maybe add data->probeRadius first

    sRadius = tRadius[i] * tRadius[i];
    // Square that
    data->widXz[i] = int(tRadius[i]) + 1;
    data->deptY[i] = new int[data->widXz[i] * data->widXz[i]];
    indx = 0;
    for (j = 0; j < data->widXz[i]; j++) {
      for (k = 0; k < data->widXz[i]; k++) {
        tXz = j * j + k * k;
        if (tXz > sRadius) {
          data->deptY[i][indx] = -1;
        } else {
          tDepth = sqrt(sRadius - tXz);
          data->deptY[i][indx] = int(tDepth + 0.0);
        }
        indx++;
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

int EDTSurface::detail(unsigned char atomicNumber)
{
  // Takes an atomic number and returns the index for rasRad
  switch (atomicNumber) {
    // Hydrogen
    case 1:
      return 5;
    // Carbon
    case 6:
      return 1;
    // Nitrogen
    case 7:
      return 2;
    // Oxygen
    case 8:
      return 3;
    // Phosphorous
    case 15:
      return 6;
    // Sulfur
    case 16:
      return 4;
    // Other
    default:
      return 10;
  }
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

bool EDTSurface::isBound(Vector3i vec)
{
  return _isBound[vec(0)][vec(1)][vec(2)];
}

bool EDTSurface::isDone(Vector3i vec)
{
  return _isDone[vec(0)][vec(1)][vec(2)];
}

bool EDTSurface::inOut(Vector3i vec)
{
  return _inOut[vec(0)][vec(1)][vec(2)];
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

void EDTSurface::seansFillAtom(int indx){

  int otherIndex; // used in the event of overlapping radii

  Vector3 cp;    // vector containing coordinates for atom at indx in m_mol
  Vector3i cxyz; // cp rounded to the nearest int values
  Vector3i oxyz; // vector from origin to point in question
  Vector3 dxyz; // vector from cxyz to oxyz
  Vector3i txyz; // vector used to determine which atom is closer
  Vector3 axyz; // additional vector used to determine which atom is closer

  Array<Vector3> positions = m_mol->atomPositions3d();
  Atom current = m_mol->atom(indx);

  cp = (positions[indx] + data->pTran) * data->scaleFactor;
  // Translating and scaling

  cxyz = round(cp);
  int atomicNumber = detail(current.atomicNumber());
  double scaledRad = (element_VDW[atomicNumber] + data->probeRadius) * data->scaleFactor + 0.5;
  int scaledRadius = (int)scaledRad;

  for(int i = cxyz(X) - scaledRadius; i < cxyz(X) + scaledRadius; i++){
    for(int j = cxyz(Y) - scaledRadius; j < cxyz(Y) + scaledRadius; j++){
      for(int k = cxyz(Z) - scaledRadius; k < cxyz(Z) + scaledRadius; k++){
        oxyz(X) = i;
        oxyz(Y) = j;
        oxyz(Z) = k;
        if(inBounds(oxyz)){
          dxyz = promote(cxyz - oxyz);
          if(dxyz.norm() <= scaledRadius){
            if(!_inOut[i][j][k]){
              _inOut[i][j][k] = true;
              _isDone[i][j][k] = true;
              atomIds[i][j][k] = indx;
            }//if _inOut
            else{
              otherIndex = atomIds[i][j][k];
              txyz = round(positions[otherIndex]);
              axyz = promote(cxyz - txyz);
              if(axyz.squaredNorm() > dxyz.squaredNorm()){
                atomIds[i][j][k] = indx;
              }//if axyz.squaredNorm
            }//else
          }//if dxyz.norm
        }//if inBounds (which it really should be or the bounds are bad)
      }//k
    }//j
  }//i
  return;
}

void EDTSurface::seansFillVoxelsWaals(){
  //When we call this function, we're building a solvent excluded surface
  //We've already built the solvent accessible solid
  //And done an EDT on all points within it
  //Now we just need to remove all points whose distance from the SAS is <= probeRadius

  for(int i = 0; i < data->pLength; i++){
    for(int j = 0; j < data->pWidth; j++){
      for(int k = 0; k < data->pHeight; k++){
        if(_inOut[i][j][k] && m_cube->value(i, j, k) <= data->probeRadius){
          _inOut[i][j][k] = false;
        }
      }
    }
  }
}

} // End namespace Core

} // End namespace Avogadro
