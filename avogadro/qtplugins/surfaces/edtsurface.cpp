/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "edtsurface.h"

#include <Eigen/Dense>

#include <avogadro/core/cube.h>
#include <avogadro/core/elementdata.h>
#include <avogadro/core/molecule.h>

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

static int nb[26][3] = { 1,  0,  0,  -1, 0,  0,  0, 1,  0,  0,  -1, 0,  0,
                         0,  1,  0,  0,  -1, 1,  1, 0,  1,  -1, 0,  -1, 1,
                         0,  -1, -1, 0,  1,  0,  1, 1,  0,  -1, -1, 0,  1,
                         -1, 0,  -1, 0,  1,  1,  0, 1,  -1, 0,  -1, 1,  0,
                         -1, -1, 1,  1,  1,  1,  1, -1, 1,  -1, 1,  -1, 1,
                         1,  1,  -1, -1, -1, -1, 1, -1, 1,  -1, -1, -1, -1 };

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
  //	pTran(0.0,0.0,0.0);
  pTran(X) = 0.0;
  pTran(Y) = 0.0;
  pTran(Z) = 0.0;

  boxLength = 0;
  probeRadius = 0;
  fixSf = 0;
  scaleFactor = 0;
  //  pMin(0.0,0.0,0.0);
  pMin(X) = 0.0;
  pMin(Y) = 0.0;
  pMin(Z) = 0.0;
  //	pMax(0.0,0.0,0.0);
  pMax(X) = 0.0;
  pMax(Y) = 0.0;
  pMax(Z) = 0.0;

  pHeight = 0;
  pWidth = 0;
  pLength = 0;

  for (i = 0; i < 13; i++) {
    widXz[i] = 0;
    deptY[i] = NULL;
  }
  cutRadius = 0;
  volumePixels = NULL;
}

// Destructor
EDTSurface::~EDTSurface()
{
  int i, j;

  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      free(volumePixels[i][j]);
      volumePixels[i][j] = NULL;
    }
    free(volumePixels[i]);
    volumePixels[i] = NULL;
  }
  free(volumePixels);
  volumePixels = NULL;

  for (i = 0; i < 13; i++) {
    free(deptY[i]);
    deptY[i] = NULL;
  }
  free(deptY);
  //	deptY = NULL;

  free(widXz);
  //	widXz = NULL;
}

// Takes a molecule and a surface type and returns a cube

Cube* EDTSurface::EDTCube(Molecule mol, int surfaceType)
{
  int numberOfAtoms = (int)mol.atomCount();
  // Get number of atoms from molecule

  int i, j, k;

  this->initPara(mol, atomTypes[surfaceType], bTypes[surfaceType]);
  // Initialize everything

  if (surfaceType == SAS || surfaceType == SES) {
    this->fastDistanceMap();
  }
  // EDT

  this->fillVoxels(atomTypes[surfaceType], mol);

  this->buildBoundary();

  if (surfaceType == SES) {
    this->fillVoxelsWaals(atomTypes[surfaceType], mol);
    this->boundingAtom(false);
  }

  Cube* aCube;
  aCube = new Cube();
  // Initialize cube

  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      for (k = 0; k < pHeight; k++) {
        aCube->setValue(i, j, k, volumePixels[i][j][k].distance);
      }
      delete[] volumePixels[i][j];
    }
    delete[] volumePixels[i];
  }
  delete[] volumePixels;
  // Copy VolumePixels array into Cube and delete volumePixels

  return aCube;
}

void EDTSurface::fastDistanceMap()
{
  int i, j, k;
  Vector3i ijk;
  totalSurfaceVox = 0;
  totalInnerVox = 0;

  Vector3i*** boundPoint;
  boundPoint = new Vector3i**[pLength];

  for (i = 0; i < pLength; i++) {
    boundPoint[i] = new Vector3i*[pWidth];
    for (j = 0; j < pWidth; j++) {
      boundPoint[i][j] = new Vector3i[pHeight];
      for (k = 0; k < pHeight; k++) {
        volumePixels[i][j][k].isDone = false;
        if (volumePixels[i][j][k].inOut) {
          if (volumePixels[i][j][k].isBound) {
            totalSurfaceVox++;
            ijk(I) = i;
            ijk(J) = j;
            ijk(K) = k;
            boundPoint[i][j][k] = ijk;
            volumePixels[i][j][k].distance = 0;
            volumePixels[i][j][k].isDone = true;
          } else {
            totalInnerVox++;
          }
        }
      }
    }
  }

  int allocIn = int(1.2 * totalSurfaceVox);
  int allocOut = int(1.2 * totalSurfaceVox);
  if (allocIn > totalInnerVox)
    allocIn = totalInnerVox;
  if (allocIn < totalSurfaceVox)
    allocIn = totalSurfaceVox;
  if (allocOut > totalInnerVox)
    allocOut = totalInnerVox;
  inArray = new Vector3i[allocIn];
  outArray = new Vector3i[allocOut];
  positIn = 0;
  positOut = 0;

  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      for (k = 0; k < pHeight; k++) {
        if (volumePixels[i][j][k].isBound) {
          ijk(I) = i;
          ijk(J) = j;
          ijk(K) = k;
          inArray[positIn] = ijk;
          positIn++;
          volumePixels[i][j][k].isBound = false; // as flag of outArray
        }
      }
    }
  }
  certificate = totalInnerVox;
  ///////////////////////////////////////////////////
  // if(type==0)//do part
  //{
  // type == 0 when we're not doing depth
  do {
    fastOneShell(&positIn, &allocOut, boundPoint, &positOut, &eliminate);
    //	printf("%d %d %d %d
    //%d\n",positIn,allocOut,positOut,totalSurfaceVox,totalInnerVox);
    certificate -= eliminate;

    /*		for(i=0;i<positOut;i++)
                            {
                              inArray[i](X)=outArray[i](X);
                              inArray[i](Y)=outArray[i](Y);
                              inArray[i](Z)=outArray[i](Z);
                            }
                            positIn=positOut;
                    //new code only less dist
            */
    positIn = 0;
    for (i = 0; i < positOut; i++) {
      volumePixels[outArray[i](X)][outArray[i](Y)][outArray[i](Z)].isBound =
        false;
      if (volumePixels[outArray[i](X)][outArray[i](Y)][outArray[i](Z)]
            .distance <= 1.02 * cutRadius) {
        inArray[positIn] = outArray[i];
        positIn++;
      }
      if (positIn >= allocIn) {
        allocIn *= 2;
        if (allocIn > totalInnerVox)
          allocIn = totalInnerVox;
        inArray = (Vector3i*)realloc(inArray, allocIn * sizeof(Vector3i));
      }
    }
  } while (positIn != 0);

  //}
  /*else if(type==1)//do all
  {
          Vector3i *tpoint;
          do {

                  fastOneShell( &positIn, &allocOut, boundPoint,
  &positOut,&eliminate);//inArray, outArray, certificate-=eliminate;
  //	/*
  //			for(i=0;i<positOut;i++)
  //			{
  //
  volumePixels[outArray[i](X)][outArray[i](Y)][outArray[i](Z)].isBound=false;
  //			  inArray[i](X)=outArray[i](X);
  //			  inArray[i](Y)=outArray[i](Y);
  //			  inArray[i](Z)=outArray[i](Z);
  //			}
                          tpoint=inArray;
                          inArray=outArray;
                          outArray=tpoint;
                          positIn=positOut;
                          int alloctmp;
                          alloctmp=allocIn;
                          allocIn=allocOut;
                          allocOut=alloctmp;
                          for(i=0;i<positIn;i++)
                                  volumePixels[inArray[i](X)][inArray[i](Y)][inArray[i](Z)].isBound=false;
  //			*/
  // new code only less dist
  /*
  positIn=0;
  for(i=0;i<positOut;i++)
  {
          volumePixels[outArray[i](X)][outArray[i](Y)][outArray[i](Z)].isBound=false;
          if(volumePixels[outArray[i](X)][outArray[i](Y)][outArray[i](Z)].distance<=1.0*cutRadius)
          {
                  inArray[positIn](X)=outArray[i](X);
                  inArray[positIn](Y)=outArray[i](Y);
                  inArray[positIn](Z)=outArray[i](Z);
                  positIn++;
          }
  }
  */

  //	}
  //	while(positIn!=0);
  //	while(positOut!=0);
  //}
  // while(positOut!=0);
  if (certificate != 0) {
    //	printf("wrong number\n");
  }

  free(inArray);
  free(outArray);

  double cutsf = scaleFactor - 0.5;
  if (cutsf < 0)
    cutsf = 0;
  //	 cutsf=100000000;
  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      for (k = 0; k < pHeight; k++) {
        volumePixels[i][j][k].isBound = false;
        // ses solid
        if (volumePixels[i][j][k].inOut) {
          if (!volumePixels[i][j][k].isDone ||
              (volumePixels[i][j][k].isDone &&
               volumePixels[i][j][k].distance >=
                 cutRadius - 0.50 / (0.1 + cutsf)) // 0.33  0.75/scaleFactor
          ) {
            volumePixels[i][j][k].isBound = true;
            // new add
            if (volumePixels[i][j][k].isDone)
              volumePixels[i][j][k].atomId =
                volumePixels[boundPoint[i][j][k](X)][boundPoint[i][j][k](Y)]
                            [boundPoint[i][j][k](Z)]
                              .atomId;
          }
        }
      }
    }
  }

  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      delete[] boundPoint[i][j];
    }
    delete[] boundPoint[i];
  }
  delete[] boundPoint;
}

void EDTSurface::fastOneShell(int* inNum, int* allocOut, Vector3i*** boundPoint,
                              int* outNum, int* elimi)
{
  int i, number, positOut;
  int tx, ty, tz;
  Vector3i dxyz;
  Vector3i txyz;
  int dx, dy, dz;
  int eliminate = 0;
  float squre;
  positOut = 0;
  number = *inNum;
  if (number == 0)
    return;
  // new code
  int j;
  Vector3i tnv;
  //	Vector3i tnv;
  for (i = 0; i < number; i++) {
    if (positOut >= (*allocOut) - 6) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > totalInnerVox)
        *allocOut = totalInnerVox;
      outArray = (Vector3i*)realloc(outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = inArray[i];

    for (j = 0; j < 6; j++) {

      tnv = txyz + vectorFromArray(nb[j]);

      if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth && tnv(Y) > -1 &&
          tnv(Z) < pHeight && tnv(Z) > -1 &&
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
          !volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];

        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = dxyz.norm();
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone = true;
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;

        outArray[positOut] = tnv;

        positOut++;
        eliminate++;
      } else if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth &&
                 tnv(Y) > -1 && tnv(Z) < pHeight && tnv(Z) > -1 &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {
        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        if (squre < volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = dxyz.norm();
          if (!volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound) {
            volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;
            outArray[positOut] = tnv;
            positOut++;
          }
        }
      }
    }
  }

  for (i = 0; i < number; i++) {
    if (positOut >= (*allocOut) - 12) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > totalInnerVox)
        *allocOut = totalInnerVox;
      outArray = (Vector3i*)realloc(outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = inArray[i];
    for (j = 6; j < 18; j++) {
      tnv = txyz + vectorFromArray(nb[j]);
      ;
      if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth && tnv(Y) > -1 &&
          tnv(Z) < pHeight && tnv(Z) > -1 &&
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
          !volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = dxyz.norm();
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone = true;
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;
        outArray[positOut] = tnv;
        positOut++;
        eliminate++;
      } else if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth &&
                 tnv(Y) > -1 && tnv(Z) < pHeight && tnv(Z) > -1 &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {
        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        squre = dxyz.norm();
        if (squre < volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = float(squre);
          if (!volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound) {
            volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;
            outArray[positOut] = tnv;
            positOut++;
          }
        }
      }
    }
  }
  for (i = 0; i < number; i++) {
    if (positOut >= (*allocOut) - 9) {
      (*allocOut) = int(1.2 * (*allocOut));
      if (*allocOut > totalInnerVox)
        *allocOut = totalInnerVox;
      outArray = (Vector3i*)realloc(outArray, (*allocOut) * sizeof(Vector3i));
    }
    txyz = inArray[i];

    for (j = 18; j < 26; j++) {
      tnv = txyz + vectorFromArray(nb[j]);
      ;
      if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth && tnv(Y) > -1 &&
          tnv(Z) < pHeight && tnv(Z) > -1 &&
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
          !volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {
        boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
          boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = dxyz.norm();
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone = true;
        volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;
        outArray[positOut] = tnv;
        positOut++;
        eliminate++;
      } else if (tnv(X) < pLength && tnv(X) > -1 && tnv(Y) < pWidth &&
                 tnv(Y) > -1 && tnv(Z) < pHeight && tnv(Z) > -1 &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].inOut &&
                 volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isDone) {

        dxyz = tnv - boundPoint[txyz(X)][txyz(Y)][txyz(Z)];

        if (squre < volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance) {
          boundPoint[tnv(X)][tnv(Y)][tnv(Z)] =
            boundPoint[txyz(X)][txyz(Y)][txyz(Z)];
          volumePixels[tnv(X)][tnv(Y)][tnv(Z)].distance = dxyz.norm();
          if (!volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound) {
            volumePixels[tnv(X)][tnv(Y)][tnv(Z)].isBound = true;
            outArray[positOut] = tnv;
            positOut++;
          }
        }
      }
    }
  }

  *outNum = positOut;
  *elimi = eliminate;
}

void EDTSurface::fillAtom(int indx, Molecule mol)
{
  int cx, cy, cz;
  Vector3i cxyz;
  int ox, oy, oz;
  Vector3i oxyz;
  Vector3 cp;

  Array<Vector3> positions = mol.atomPositions3d();

  cp = (positions[indx] + pTran) * scaleFactor;
  cx = int(cp(X) + 0.5);
  cy = int(cp(Y) + 0.5);
  cz = int(cp(Z) + 0.5);

  cxyz(X) = cx;
  cxyz(Y) = cy;
  cxyz(Z) = cz;
  /*Translate, scale, and round positions*/

  Index index = indx;
  Atom current = mol.atom(index);
  int at = detail(current.atomicNumber());
  int i, j, k;
  int ii, jj, kk;
  int mi, mj, mk;
  Vector3i mijk;
  int si, sj, sk;
  Vector3i sijk;
  int tIndex;
  int nIndex = 0;
  for (i = 0; i < widXz[at]; i++) {
    for (j = 0; j < widXz[at]; j++) {
      if (deptY[at][nIndex] != -1) {

        for (ii = -1; ii < 2; ii++) {
          for (jj = -1; jj < 2; jj++) {
            for (kk = -1; kk < 2; kk++) {
              if (ii != 0 && jj != 0 && kk != 0) {
                mi = ii * i;
                mk = kk * j;
                for (k = 0; k <= deptY[at][nIndex]; k++) {
                  mj = k * jj;
                  mijk(I) = mi;
                  mijk(J) = mj;
                  mijk(K) = mk;
                  sijk = cxyz + mijk;
                  if (sijk(I) < 0 || sijk(J) < 0 || sijk(K) < 0 ||
                      sijk(I) >= pLength || sijk(J) >= pWidth ||
                      sijk(K) >= pHeight) {
                    continue;
                  }

                  else {
                    if (volumePixels[sijk(I)][sijk(J)][sijk(K)].inOut ==
                        false) {
                      volumePixels[sijk(I)][sijk(J)][sijk(K)].inOut = true;
                      volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId = indx;
                    }
                    // no atomic info to each Vector3i change above line
                    //*
                    else if (volumePixels[sijk(I)][sijk(J)][sijk(K)].inOut) {
                      tIndex = volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId;

                      cp = (positions[tIndex] + pTran) * scaleFactor;
                      // Translating and scaling

                      ox = int(cp(X) + 0.5) - sijk(I);
                      oy = int(cp(Y) + 0.5) - sijk(J);
                      oz = int(cp(Z) + 0.5) - sijk(K);
                      oxyz(X) = ox;
                      oxyz(Y) = oy;
                      oxyz(Z) = oz;
                      // Rounding to the nearest integer

                      if (mijk.squaredNorm() < oxyz.squaredNorm())
                        volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId = indx;
                    }
                    //	*/
                  } // k
                }   // else
              }     // if
            }       // kk
          }         // jj
        }           // ii

      } // if
      nIndex++;
    } // j
  }   // i
}
// sas use inOut
void EDTSurface::fillVoxels(bool atomType, Molecule mol)
{

  int i, j, k;

  int numberOfAtoms = mol.atomCount();

  for (i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = mol.atom(index);
    if (!atomType || current.atomicNumber() != 1)
      fillAtom(i, mol);
    //			totalNumber++;
  }
  //	printf("%d\n",totalNumber);
  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pWidth; j++) {
      for (k = 0; k < pHeight; k++) {
        if (volumePixels[i][j][k].inOut) {
          volumePixels[i][j][k].isDone = true;
        }
      }
    }
  }
}
// use isDone
void EDTSurface::fillVoxelsWaals(bool atomType, Molecule mol)
{
  int i, j, k;

  int numberOfAtoms = mol.atomCount();

  for (i = 0; i < numberOfAtoms; i++) {
    Index index = i;
    Atom current = mol.atom(index);
    if (!atomType || current.atomicNumber() != 1) {
      fillAtomWaals(i, mol);
    }
  }
}

void EDTSurface::fillAtomWaals(int indx, Molecule mol)
{
  int cx, cy, cz;
  Vector3i cxyz;
  int ox, oy, oz;
  Vector3i oxyz;
  Vector3 cp;

  int numberOfAtoms = mol.atomCount();
  Array<Vector3> positions = mol.atomPositions3d();
  Atom current = mol.atom(indx);

  cp = (positions[indx] + pTran) * scaleFactor;
  // Translating and scaling

  cx = int(cp(X) + 0.5);
  cy = int(cp(Y) + 0.5);
  cz = int(cp(Z) + 0.5);

  cxyz(X) = cx;
  cxyz(Y) = cy;
  cxyz(Z) = cz;
  // Rounding to the nearest integer

  int at = detail(current.atomicNumber());
  int i, j, k;
  int ii, jj, kk;
  Vector3i mijk;
  int mi, mj, mk;
  Vector3i sijk;
  int si, sj, sk;
  int tIndex;
  int nIndex = 0;
  for (i = 0; i < widXz[at]; i++) {
    for (j = 0; j < widXz[at]; j++) {
      if (deptY[at][nIndex] != -1) {
        for (ii = -1; ii < 2; ii++) {
          for (jj = -1; jj < 2; jj++) {
            for (kk = -1; kk < 2; kk++) {
              if (ii != 0 && jj != 0 && kk != 0) {
                mijk(I) = ii * i;
                mijk(K) = kk * j;
                for (k = 0; k <= deptY[at][nIndex]; k++) {
                  mijk(J) = jj * k;
                  sijk = cxyz + mijk;
                  if (sijk(I) < 0 || sijk(J) < 0 || sijk(K) < 0) {
                    continue;
                  }

                  else {
                    if (volumePixels[sijk(I)][sijk(J)][sijk(K)].isDone ==
                        false) {
                      volumePixels[sijk(I)][sijk(J)][sijk(K)].isDone = true;
                      volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId = indx;
                    }
                    // with atomic info change above line
                    //*
                    else if (volumePixels[sijk(I)][sijk(J)][sijk(K)].isDone) {
                      tIndex = volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId;
                      cp = (positions[tIndex] + pTran) * scaleFactor;
                      // Translating and scaling
                      oxyz = cxyz - sijk;
                      if (mijk.squaredNorm() < oxyz.squaredNorm())
                        volumePixels[sijk(I)][sijk(J)][sijk(K)].atomId = indx;
                    }
                    //	 */
                  } // else
                }   // k

              } // if
            }   // kk
          }     // jj
        }       // ii

      } // if
      nIndex++;
    } // j
  }   // i
}

void EDTSurface::buildBoundary()
{
  int i, j, k;
  int ii;
  bool flagBound;

  //! Thread this!

  for (i = 0; i < pLength; i++) {
    for (j = 0; j < pHeight; j++) {
      for (k = 0; k < pWidth; k++) {
        if (volumePixels[i][k][j].inOut) {
          // 6 neighbors
          //					if(( k-1>-1 && !volumePixels[i][k-1][j].inOut)
          //|| ( k+1<pWidth &&!volumePixels[i][k+1][j].inOut)
          //					|| ( j-1>-1 && !volumePixels[i][k][j-1].inOut)
          //|| ( j+1<pHeight &&!volumePixels[i][k][j+1].inOut)
          //					|| ( i-1>-1 && !volumePixels[i-1][k][j].inOut)
          //|| ( i+1<pLength &&!volumePixels[i+1][k][j].inOut))
          //						volumePixels[i][k][j].isBound=true;
          //	/*
          // 26 neighbors
          flagBound = false;
          ii = 0;
          while (!flagBound && ii < 26) {
            if (i + vectorFromArray(nb[ii])(X) > -1 &&
                i + vectorFromArray(nb[ii])(X) < pLength &&
                k + vectorFromArray(nb[ii])(Y) > -1 &&
                k + vectorFromArray(nb[ii])(Y) < pWidth &&
                j + vectorFromArray(nb[ii])(Z) > -1 &&
                j + vectorFromArray(nb[ii])(Z) < pHeight &&
                !volumePixels[i + vectorFromArray(nb[ii])(X)]
                             [k + vectorFromArray(nb[ii])(Y)]
                             [j + vectorFromArray(nb[ii])(Z)]
                               .inOut) {
              volumePixels[i][k][j].isBound = true;
              flagBound = true;
            } else
              ii++;
          }
          //		*/
        }
      }
    }
  }
}

void EDTSurface::boundBox(bool atomType, Molecule mol)
{
  /**
   *Finds the bound box of the sequence of atoms
   *The smallest rectangular prism that contains all the atoms
   *@param minPoint A pointer to a vector representing the minimum point
   *@param maxPoint A pointer to a vector representing the maximum point
   **/

  int i;

  int numberOfAtoms = mol.atomCount();
  Array<Vector3> positions = mol.atomPositions3d();

  pMin(X) = 100000;
  pMin(Y) = 100000;
  pMin(Z) = 100000;
  pMax(X) = -100000;
  pMax(Y) = -100000;
  pMax(Z) = -100000;

  for (i = 0; i < numberOfAtoms; i++) {
    Atom current = mol.atom(i);
    if (!atomType || current.atomicNumber() != 1) {
      if (positions[i](X) < pMin(X))
        pMin(X) = positions[i](X);
      if (positions[i](Y) < pMin(Y))
        pMin(Y) = positions[i](Y);
      if (positions[i](Z) < pMin(Z))
        pMin(Z) = positions[i](Z);
      if (positions[i](X) > pMax(X))
        pMax(X) = positions[i](X);
      if (positions[i](Y) > pMax(Y))
        pMax(Y) = positions[i](Y);
      if (positions[i](Z) > pMax(Z))
        pMax(Z) = positions[i](Z);
    }
  }
}

void EDTSurface::initPara(Molecule mol, bool atomType, bool bType)
{
  int i, j;
  int fixSf = 4;
  double fMargin = 2.5;
  int pLength, pWidth;

  if (volumePixels != NULL) {
    for (i = 0; i < pLength; i++) {
      for (j = 0; j < pWidth; j++) {
        free(volumePixels[i][j]);
      }
      free(volumePixels[i]);
    }

    free(volumePixels);
    volumePixels = NULL;
  }
  boundBox(atomType, mol);
  if (bType == false) {
    pMin(X) -= fMargin;
    pMin(Y) -= fMargin;
    pMin(Z) -= fMargin;
    pMax(X) += fMargin;
    pMax(Y) += fMargin;
    pMax(Z) += fMargin;
  } else {
    pMin(X) -= probeRadius + fMargin;
    pMin(Y) -= probeRadius + fMargin;
    pMin(Z) -= probeRadius + fMargin;
    pMax(X) += probeRadius + fMargin;
    pMax(Y) += probeRadius + fMargin;
    pMax(Z) += probeRadius + fMargin;
  }

  pTran = -pMin;

  // pTran is the vector to get us to our minimum x, minimum y, and minimum z
  // points

  scaleFactor = pMax(X) - pMin(X);
  if ((pMax(Y) - pMin(Y)) > scaleFactor)
    scaleFactor = pMax(Y) - pMin(Y);
  if ((pMax(Z) - pMin(Z)) > scaleFactor)
    scaleFactor = pMax(Z) - pMin(Z);

  // scaleFactor is the maximum distance between our mins and maxes

  scaleFactor = (boxLength - 1.0) / double(scaleFactor);
  ///////////////////////////add this automatically first fix sf then fix
  ///boxLength
  //	/*
  boxLength = int(boxLength * fixSf / scaleFactor);
  scaleFactor = fixSf;
  double threshBox = 300;
  if (boxLength > threshBox) {
    double sfThresh = threshBox / double(boxLength);
    boxLength = int(threshBox);
    scaleFactor = scaleFactor * sfThresh;
  }
  //	*/

  pLength = int(ceil(scaleFactor * (pMax(X) - pMin(X))) + 1);
  pWidth = int(ceil(scaleFactor * (pMax(Y) - pMin(Y))) + 1);
  pHeight = int(ceil(scaleFactor * (pMax(Z) - pMin(Z))) + 1);

  if (pLength > boxLength)
    pLength = boxLength;
  if (pWidth > boxLength)
    pWidth = boxLength;
  if (pHeight > boxLength)
    pHeight = boxLength;

  boundingAtom(bType);
  cutRadius = probeRadius * scaleFactor;
}

void EDTSurface::boundingAtom(bool bType)
{
  int i, j, k;
  double tRadius[13];
  double tXz, tDepth, sRadius;
  int indx;
  for (i = 0; i < 13; i++) {
    if (deptY[i] != NULL)
      free(deptY[i]);
  }

  for (i = 0; i < 13; i++) {
    if (bType == false)
      tRadius[i] = rasRad[i] * scaleFactor + 0.5;
    else
      tRadius[i] = (rasRad[i] + probeRadius) * scaleFactor + 0.5;

    // Multiply by scaleFactor
    // Maybe add probeRadius first

    sRadius = tRadius[i] * tRadius[i];
    // Square that
    widXz[i] = int(tRadius[i]) + 1;
    deptY[i] = new int[widXz[i] * widXz[i]];
    indx = 0;
    for (j = 0; j < widXz[i]; j++) {
      for (k = 0; k < widXz[i]; k++) {
        tXz = j * j + k * k;
        if (tXz > sRadius) {
          deptY[i][indx] = -1;
        } else {
          tDepth = sqrt(sRadius - tXz);
          deptY[i][indx] = int(tDepth + 0.0);
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

} // End namespace Core

} // End namespace Avogadro
