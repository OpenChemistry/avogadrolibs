/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "meshgenerator.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/mutex.h>

#include <QDebug>
#include <QReadWriteLock>

namespace Avogadro::QtGui {

using Core::Cube;
using Core::Mesh;

MeshGenerator::MeshGenerator(QObject* p)
  : QThread(p), m_iso(0.0), m_passes(6), m_reverseWinding(false), m_cube(nullptr),
    m_mesh(nullptr), m_stepSize(0.0, 0.0, 0.0), m_min(0.0, 0.0, 0.0),
    m_dim(0, 0, 0), m_progmin(0), m_progmax(0)
{
}

MeshGenerator::MeshGenerator(const Cube* cube_, Mesh* mesh_, float iso,
                             int passes, bool reverse, QObject* p)
  : QThread(p), m_iso(0.0), m_passes(6), m_reverseWinding(reverse), m_cube(nullptr),
    m_mesh(nullptr), m_stepSize(0.0, 0.0, 0.0), m_min(0.0, 0.0, 0.0),
    m_dim(0, 0, 0), m_progmin(0), m_progmax(0)
{
  initialize(cube_, mesh_, iso, passes);
}

MeshGenerator::~MeshGenerator()
{
}

bool MeshGenerator::initialize(const Cube* cube_, Mesh* mesh_, float iso,
                               int passes, bool reverse)
{
  if (!cube_ || !mesh_)
    return false;
  m_cube = cube_;
  m_mesh = mesh_;
  m_iso = iso;
  m_passes = passes;
  m_reverseWinding = reverse;

  // In BlockMarchFunctor.cpp:
  // The volume reader setup happens here with dimensions, origin, and spacing.
  // dims = volReader.imageData->getDimension();
  // origin = volReader.imageData->getOrigin();
  // spacing = volReader.imageData->getSpacing();
  
  if (!m_cube->lock()->tryLock()) {
    qDebug() << "Cannot get a read lock…";
    return false;
  }

  for (unsigned int i = 0; i < 3; ++i)
    m_stepSize[i] = static_cast<float>(m_cube->spacing()[i]);
  m_min = m_cube->min().cast<float>();
  m_dim = m_cube->dimensions();
  edgeCases.resize((m_dim.x() - 1) * (m_dim.y() - 1) * (m_dim.z() - 1));
  gridEdges.resize(m_dim.y() * m_dim.z());
  m_progmax = m_dim.x();
  
  // Similar to setting up sliceSize and grid traversal boundaries in BlockMarchFunctor.cpp:
  // sliceSize = dims[0] * dims[1];

  m_cube->lock()->unlock();
  return true;
}

void MeshGenerator::FlyingEdgesAlgorithmPass1()
{
  // Loop through z-dimension
  for(size_t k = 0; k != m_dim.z(); ++k) {
  // Loop through y-dimension    
  for(size_t j = 0; j != m_dim.y(); ++j)
  {

  // Calculate the starting position of edgeCases for the current row    

    auto curEdgeCases = edgeCases.begin() + (m_dim.x() - 1) * (k * m_dim.y() + j);

  // Get an iterator to the current row of point values

    auto curPointValues = m_cube->getRowIter(j, k);
    
  // Initialize the isGE array to track isosurface crossings
    std::array<bool, 2> isGE;
    isGE[0] = (curPointValues[0] >= m_iso); // first element initialization   

  // loop through x-dimension     
    for(int i = 1; i != m_dim.x(); ++i)
    {
      // update isGE for the current point
      isGE[i % 2] = (curPointValues[i] >= m_iso);

      // calculate edge case and update curEdgeCase         
      curEdgeCases[i-1] = calcCaseEdge(isGE[(i+1)%2], isGE[i%2]);
    }
  }
}

  for(size_t k = 0; k != m_dim.z(); ++k){
    for(size_t j = 0; j != m_dim.y(); ++j)
    {
        gridEdge& curGridEdge = gridEdges[k * m_dim.y() + j];
        curGridEdge.xl = m_dim.x();  

        for(int i = 1; i != m_dim.x(); ++i)
        {
          // if the edge is cut     
          if(isCutEdge(i-1, j, k))
          {
            if(curGridEdge.xl == m_dim.x())
            {
              curGridEdge.xl = i-1;
            }
            curGridEdge.xr = i;
          }
        }
     }}
}


void MeshGenerator::FlyingEdgesAlgorithmPass2()
{

    for(size_t k = 0; k != m_dim.z() - 1; ++k){
       for(size_t j = 0; j != m_dim.y() - 1; ++j)
       {
        // find adjusted trim values    
        size_t xl, xr;
        calcTrimValues(xl, xr, j, k); // xl, xr set in this function

        gridEdge& g0 = gridEdges[k * m_dim.y() + j];
        gridEdge& ge1 = gridEdges[k*m_dim.y() +j + 1];
        gridEdge& ge2 = gridEdges[(k+1) * m_dim.y() + j];
        gridEdge& ge3 = gridEdges[(k+1) * m_dim.y() + j + 1];

        auto const& ec0 = edgeCases.begin() + (m_dim.x()-1) * (k * m_dim.y() + j);
        auto const& ec1 = edgeCases.begin() + (m_dim.x()-1) * (k * m_dim.y() + j + 1);
        auto const& ec2 = edgeCases.begin() + (m_dim.x()-1) * ((k+1) * m_dim.y() + j);
        auto const& ec3 = edgeCases.begin() + (m_dim.x()-1) * ((k+1) * m_dim.y() + j + 1);

        // Count the number of triangles along this row of cubes
        size_t& curTriCounter = *(triCounter.begin() + k * (m_dim.y() - 1) + j);

        auto curCubeCaseIds = cubeCases.begin() + (m_dim.x() - 1) * (k * (m_dim.y() - 1) + j);

        bool isYEnd = (j == m_dim.y() - 2);
        bool isZEnd = (k == m_dim.z() - 2);

        for(size_t i = xl; i != xr; ++i)
        {
          bool isXEnd = (i == m_dim.x() - 2);

          unsigned char caseId = calcCubeCase(ec0[i], ec1[i], ec2[i], ec3[i]);

          curCubeCaseIds[i] = caseId;

          if(caseId == 0 || caseId == 255)
          {
            continue;
          }


        curTrimCounter += numTris[caseId];
        
        const bool* isCutCase = isCut[caseId]; // size 12
        

        ge0.xstart += isCutCase[0];    
        ge0.ystart += isCutCase[3];
        ge0.zstart += isCutCase[8];

        if(isXEnd)
        {
          ge0.ystart += isCutCase[1];
          ge0.zstart += isCutCase[9];
        }

        if(isYEnd)
        {
          ge1.xstart += isCutCase[2];
          ge1.zstart += isCutCase[10];
        }
        if(isZEnd)
        {
          ge2.xstart += isCutCase[4];
          ge2.ystart += isCutCase[7];
        }
        if(isXEnd and isYEnd)
        {
          ge1.zstart += isCutCase[11];
        }
        if(isXEnd and isZEnd)
        {
          ge2.ystart += isCutCase[5];
        }
        if(isYEnd and isZEnd)
        {
          ge3.xstart += isCutCase[6];
        }

        }

       }
    }
}



void MeshGenerator::FlyingEdgesAlgorithmPass3()
{

    size_t tmp;
    size_t triAccum = 0;
    for(size_t k = 0; k != m_dim.z()-1; ++k) {
    for(size_t j = 0; j != m_dim.y()-1; ++j)
    {
        size_t& curTriCounter = triCounter[k*(m_dim.y()-1)+j];

        tmp = curTriCounter;
        curTriCounter = triAccum;
        triAccum += tmp;
    }}

    size_t pointAccum = 0;
    for(size_t k = 0; k != m_dim.z(); ++k) {
    for(size_t j = 0; j != m_dim.y(); ++j)
    {
        gridEdge& curGridEdge = gridEdges[k * m_dim.y() + j];

        tmp = curGridEdge.xstart;
        curGridEdge.xstart = pointAccum;
        pointAccum += tmp;

        tmp = curGridEdge.ystart;
        curGridEdge.ystart = pointAccum;
        pointAccum += tmp;

        tmp = curGridEdge.zstart;
        curGridEdge.zstart = pointAccum;
        pointAccum += tmp;
    }}

    points = std::vector<std::array<float, 3> >(pointAccum);
    normals = std::vector<std::array<float, 3> >(pointAccum);
    tris = std::vector<std::array<size_t, 3> >(triAccum);
}

void MeshGenerator::FlyingEdgesAlgorithmPass4()
{
 for(size_t k = 0; k != m_dim.z()-1; ++k) {
    for(size_t j = 0; j != m_dim.y()-1; ++j)
    {
        // find adjusted trim values
        size_t xl, xr;
        calcTrimValues(xl, xr, j, k); // xl, xr set in this function

        if(xl == xr)
            continue;

        size_t triIdx = triCounter[k*(m_dim.y()-1) + j];
        auto curCubeCaseIds = cubeCases.begin() + (m_dim.x()-1)*(k*(m_dim.y()-1) + j);

        gridEdge const& ge0 = gridEdges[k* m_dim.y() + j];
        gridEdge const& ge1 = gridEdges[k* m_dim.y() + j + 1];
        gridEdge const& ge2 = gridEdges[(k+1)* m_dim.y() + j];
        gridEdge const& ge3 = gridEdges[(k+1)* m_dim.y() + j + 1];

        size_t x0counter = 0;
        size_t y0counter = 0;
        size_t z0counter = 0;

        size_t x1counter = 0;
        size_t z1counter = 0;

        size_t x2counter = 0;
        size_t y2counter = 0;

        size_t x3counter = 0;

        bool isYEnd = (j == m_dim.y()-2);
        bool isZEnd = (k == m_dim.z()-2);

        for(size_t i = xl; i != xr; ++i)
        {
            bool isXEnd = (i == nx-2);

            unsigned char caseId = curCubeCaseIds[i];

            if(caseId == 0 || caseId == 255)
            {
                continue;
            }

            cube_t        pointCube = m_cube->getPosCube(i, j, k);
            scalarCube_t  isovalCube = m_cube->getValsCube(i, j, k);
            cube_t        gradCube = m_cube->getGradCube(i, j, k);

            // Add Points and normals.
            // Calculate global indices for triangles
            std::array<size_t, 12> globalIdxs;

            if(isCut[0])
            {
                size_t idx = ge0.xstart + x0counter;
                points[idx] = interpolateOnCube(pointCube, isovalCube, 0);
                normals[idx] = interpolateOnCube(gradCube, isovalCube, 0);
                globalIdxs[0] = idx;
                ++x0counter;
            }

            if(isCut[3])
            {
                size_t idx = ge0.ystart + y0counter;
                points[idx] = interpolateOnCube(pointCube, isovalCube, 3);
                normals[idx] = interpolateOnCube(gradCube, isovalCube, 3);
                globalIdxs[3] = idx;
                ++y0counter;
            }

            if(isCut[8])
            {
                size_t idx = ge0.zstart + z0counter;
                points[idx] = interpolateOnCube(pointCube, isovalCube, 8);
                normals[idx] = interpolateOnCube(gradCube, isovalCube, 8);
                globalIdxs[8] = idx;
                ++z0counter;
            }

            // Note:
            //   e1, e5, e9 and e11 will be visited in the next iteration
            //   when they are e3, e7, e8 and 10 respectively. So don't
            //   increment their counters. When the cube is an edge cube,
            //   their counters don't need to be incremented because they
            //   won't be used agin.

            // Manage boundary cases if needed. Otherwise just update
            // globalIdx.
            if(isCut[1])
            {
                size_t idx = ge0.ystart + y0counter;
                if(isXEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 1);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 1);
                    // y0counter counter doesn't need to be incremented
                    // because it won't be used again.
                }
                globalIdxs[1] = idx;
            }

            if(isCut[9])
            {
                size_t idx = ge0.zstart + z0counter;
                if(isXEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 9);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 9);
                    // z0counter doesn't need to in incremented.
                }
                globalIdxs[9] = idx;
            }

            if(isCut[2])
            {
                size_t idx = ge1.xstart + x1counter;
                if(isYEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 2);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 2);
                }
                globalIdxs[2] = idx;
                ++x1counter;
            }

            if(isCut[10])
            {
                size_t idx = ge1.zstart + z1counter;

                if(isYEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 10);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 10);
                }
                globalIdxs[10] = idx;
                ++z1counter;
            }

            if(isCut[4])
            {
                size_t idx = ge2.xstart + x2counter;
                if(isZEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 4);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 4);
                }
                globalIdxs[4] = idx;
                ++x2counter;
            }

            if(isCut[7])
            {
                size_t idx = ge2.ystart + y2counter;
                if(isZEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 7);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 7);
                }
                globalIdxs[7] = idx;
                ++y2counter;
            }

            if(isCut[11])
            {
                size_t idx = ge1.zstart + z1counter;
                if(isXEnd and isYEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 11);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 11);
                    // z1counter does not need to be incremented.
                }
                globalIdxs[11] = idx;
            }

            if(isCut[5])
            {
                size_t idx = ge2.ystart + y2counter;
                if(isXEnd and isZEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 5);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 5);
                    // y2 counter does not need to be incremented.
                }
                globalIdxs[5] = idx;
            }

            if(isCut[6])
            {
                size_t idx = ge3.xstart + x3counter;
                if(isYEnd and isZEnd)
                {
                    points[idx] = interpolateOnCube(pointCube, isovalCube, 6);
                    normals[idx] = interpolateOnCube(gradCube, isovalCube, 6);
                }
                globalIdxs[6] = idx;
                ++x3counter;
            }

            // Add triangles
            const char* caseTri = caseTriangles[caseId]; // size 16
            for(int idx = 0; caseTri[idx] != -1; idx += 3)
            {
                tris[triIdx][0] = globalIdxs[caseTri[idx]];
                tris[triIdx][1] = globalIdxs[caseTri[idx+1]];
                tris[triIdx][2] = globalIdxs[caseTri[idx+2]];
                ++triIdx;
            }
        }
    }}
}


void MeshGenerator::run()
{
  if (!m_cube || !m_mesh) {
    qDebug() << "No mesh or cube set - nothing to find isosurface of…";
    return;
  }

  // Attempt to obtain a lock, wait one second between attempts.
  while (!m_cube->lock()->tryLock())
    sleep(1);

  // Mark the mesh as being worked on and clear it
  m_mesh->setStable(false);
  m_mesh->clear();

  m_vertices.reserve(m_dim.x() * m_dim.y() * m_dim.z() * 3);
  m_normals.reserve(m_dim.x() * m_dim.y() * m_dim.z() * 3);

  // Now to march the cube (Similar to marching loop in BlockMarchFunctor.cpp)
  for (int i = 0; i < m_dim.x() - 1; ++i) {
    for (int j = 0; j < m_dim.y() - 1; ++j) {
      for (int k = 0; k < m_dim.z() - 1; ++k) {
        marchingCube(Vector3i(i, j, k));  // Same logic as marching each cell in BlockMarchFunctor.cpp
      }
    }
    if (m_vertices.capacity() < m_vertices.size() + m_dim.y() * m_dim.x() * 3) {
      m_vertices.reserve(m_vertices.capacity() * 2);
      m_normals.reserve(m_normals.capacity() * 2);
    }
    emit progressValueChanged(i);
  }

  m_cube->lock()->unlock();

  // Copy the data across
  m_mesh->setVertices(m_vertices);
  m_mesh->setNormals(m_normals);
  m_mesh->setStable(true);

  // Now we are done give all that memory back
  m_vertices.resize(0);
  m_normals.resize(0);

  // Smooth out the mesh (Similar smoothing is performed at the end of BlockMarchFunctor.cpp)
  m_mesh->smooth(m_passes);
}

void MeshGenerator::clear()
{
  m_iso = 0.0;
  m_passes = 6;
  m_cube = nullptr;
  m_mesh = nullptr;
  m_stepSize.setZero();
  m_min.setZero();
  m_dim.setZero();
  m_progmin = 0;
  m_progmax = 0;
}

Vector3f MeshGenerator::normal(const Vector3f& pos)
{
  Vector3f norm(m_cube->valuef(pos - Vector3f(0.01f, 0.00f, 0.00f)) -
                  m_cube->valuef(pos + Vector3f(0.01f, 0.00f, 0.00f)),
                m_cube->valuef(pos - Vector3f(0.00f, 0.01f, 0.00f)) -
                  m_cube->valuef(pos + Vector3f(0.00f, 0.01f, 0.00f)),
                m_cube->valuef(pos - Vector3f(0.00f, 0.00f, 0.01f)) -
                  m_cube->valuef(pos + Vector3f(0.00f, 0.00f, 0.01f)));
  norm.normalize();
  return norm;
}

inline float MeshGenerator::offset(float val1, float val2)
{
  if (val2 - val1 < 1.0e-9f && val1 - val2 < 1.0e-9f)
    return 0.5;
  return (m_iso - val1) / (val2 - val1);
}

// This function is similar to interpolating positions in BlockMarchFunctor.cpp:
// In BlockMarchFunctor.cpp: 
//  T w = (isoval - val[v1]) / (val[v2] - val[v1]);
//  Interpolation using lerp() function

unsigned long MeshGenerator::duplicate(const Vector3i&, const Vector3f&)
{
  // FIXME Not implemented yet.
  return 0;
}

bool MeshGenerator::marchingCube(const Vector3i& pos)
{
  float afCubeValue[8];
  Vector3f asEdgeVertex[12];
  Vector3f asEdgeNorm[12];

  // Calculate the position in the Cube
  Vector3f fPos;
  for (unsigned int i = 0; i < 3; ++i)
    fPos[i] = static_cast<float>(pos[i]) * m_stepSize[i] + m_min[i];

  // Fetch the cube's corner values (Similar to volReader.getVertexValues in BlockMarchFunctor.cpp)
  for (int i = 0; i < 8; ++i) {
    afCubeValue[i] = static_cast<float>(
      m_cube->value(Vector3i(pos + Vector3i(a2iVertexOffset[i]))));
  }

  // Determine which edges are intersected by the isosurface
  long iFlagIndex = 0;
  for (int i = 0; i < 8; ++i) {
    if (afCubeValue[i] <= m_iso) {
      iFlagIndex |= 1 << i;
    }
  }

  // Find which edges are intersected by the surface
  long iEdgeFlags = aiCubeEdgeFlags[iFlagIndex];

  // If there are no intersections, skip the cube (Same as case 0 or 255 in BlockMarchFunctor.cpp)
  if (iEdgeFlags == 0) {
    return false;
  }

  // Interpolate edge vertices (Similar to interpolation in BlockMarchFunctor.cpp with lerp)
  for (int i = 0; i < 12; ++i) {
    if (iEdgeFlags & (1 << i)) {
      float fOffset = offset(afCubeValue[a2iEdgeConnection[i][0]],
                             afCubeValue[a2iEdgeConnection[i][1]]);

      asEdgeVertex[i] =
        Vector3f(fPos.x() +
                   (a2fVertexOffset[a2iEdgeConnection[i][0]][0] +
                    fOffset * a2fEdgeDirection[i][0]) *
                     m_stepSize[0],
                 fPos.y() +
                   (a2fVertexOffset[a2iEdgeConnection[i][0]][1] +
                    fOffset * a2fEdgeDirection[i][1]) *
                     m_stepSize[1],
                 fPos.z() +
                   (a2fVertexOffset[a2iEdgeConnection[i][0]][2] +
                    fOffset * a2fEdgeDirection[i][2]) *
                     m_stepSize[2]);

      // Normals are computed similarly in BlockMarchFunctor.cpp with `computeAllGradients`
      asEdgeNorm[i] = normal(asEdgeVertex[i]);
    }
  }

  // Store the triangles based on the edges intersected (Same logic as adding triangles in BlockMarchFunctor.cpp)
  for (int i = 0; i < 5; ++i) {
    if (a2iTriangleConnectionTable[iFlagIndex][3 * i] < 0)
      break;
    int iVertex = 0;
    iEdgeFlags = a2iTriangleConnectionTable[iFlagIndex][3 * i];
    if (!m_reverseWinding) {
      for (int j = 0; j < 3; ++j) {
        iVertex = a2iTriangleConnectionTable[iFlagIndex][3 * i + j];
        m_indices.push_back(static_cast<unsigned int>(m_vertices.size()));
        m_normals.push_back(asEdgeNorm[iVertex]);
        m_vertices.push_back(asEdgeVertex[iVertex]);
      }
    } else {
      for (int j = 2; j >= 0; --j) {
        iVertex = a2iTriangleConnectionTable[iFlagIndex][3 * i + j];
        m_indices.push_back(static_cast<unsigned int>(m_vertices.size()));
        m_normals.push_back(-asEdgeNorm[iVertex]);
        m_vertices.push_back(asEdgeVertex[iVertex]);
      }
    }
  }
  return true;
}

unsigned char MeshGenerator::calcCubeCase(
    unsigned char const& ec0, unsigned char const& ec1,
    unsigned char const& ec2, unsigned char const& ec3) const
{
    // ec0 | (i, j, k)
    // ec1 | (i, j+1, k)
    // ec2 | (i, j, k+1)
    // ec3 | (i, j+1, k+1)

    unsigned char caseId = 0;
    if ((ec0 == 0) || (ec0 == 2)) // Vertex 0 at (i, j, k)
        caseId |= 1;
    if ((ec0 == 0) || (ec0 == 1)) // Vertex 1 at (i+1, j, k)
        caseId |= 2;
    if ((ec1 == 0) || (ec1 == 1)) // Vertex 2 at (i+1, j+1, k)
        caseId |= 4;
    if ((ec1 == 0) || (ec1 == 2)) // Vertex 3 at (i, j+1, k)
        caseId |= 8;
    if ((ec2 == 0) || (ec2 == 2)) // Vertex 4 at (i, j, k+1)
        caseId |= 16;
    if ((ec2 == 0) || (ec2 == 1)) // Vertex 5 at (i+1, j, k+1)
        caseId |= 32;
    if ((ec3 == 0) || (ec3 == 1)) // Vertex 6 at (i+1, j+1, k+1)
        caseId |= 64;
    if ((ec3 == 0) || (ec3 == 2)) // Vertex 7 at (i, j+1, k+1)
        caseId |= 128;
    return caseId;
}


bool MeshGenerator::isCutEdge(size_t i, size_t j, size_t k) const
{
  size_t nx = m_dim.x();
  size_t ny = m_dim.y();
  size_t nz = m_dim.z();

  // Assuming edgeCases are all set
  size_t edgeCaseIdx = k * (nx - 1) * ny + j * (nx - 1) + i;
  unsigned char edgeCase = edgeCases[edgeCaseIdx];

  if (edgeCase == 1 || edgeCase == 2)
  {
    return true;
  }

  if (j != ny - 1)
  {
    size_t edgeCaseIdxY = k * (nx - 1) * ny + (j + 1) * (nx - 1) + i;
    unsigned char edgeCaseY = edgeCases[edgeCaseIdxY];

    // If the sum is odd, the edge along the y-axis is cut
    if ((edgeCase + edgeCaseY) % 2 == 1)
    {
      return true;
    }
  }

  if (k != nz - 1)
  {
    size_t edgeCaseIdxZ = (k + 1) * (nx - 1) * ny + j * (nx - 1) + i;
    unsigned char edgeCaseZ = edgeCases[edgeCaseIdxZ];

    // If the sum is odd, the edge along the z-axis is cut
    if ((edgeCase + edgeCaseZ) % 2 == 1)
    {
      return true;
    }
  }

  return false;
}

unsigned char MeshGenerator::calcCaseEdge(bool const& prevEdge, bool const& currEdge) const
{
    // o -- is greater than or equal to
    // case 0: prevEdge = true, currEdge = true
    // case 1: prevEdge = false, currEdge = true
    // case 2: prevEdge = true, currEdge = false
    // case 3: prevEdge = false, currEdge = false
    if (prevEdge && currEdge)
        return 0;
    if (!prevEdge && currEdge)
        return 1;
    if (prevEdge && !currEdge)
        return 2;
    else // !prevEdge && !currEdge
        return 3;
}

void MeshGenerator::calcTrimValues(size_t& xl, size_t& xr, size_t const& j, size_t const& k) const
{
  size_t ny = m_dim.y();

  const gridEdge& ge0 = gridEdges[k * ny + j];
  const gridEdge& ge1 = gridEdges[k * ny + j + 1];
  const gridEdge& ge2 = gridEdges[(k + 1) * ny + j];
  const gridEdge& ge3 = gridEdges[(k + 1) * ny + j + 1];

  xl = std::min({ge0.xl, ge1.xl, ge2.xl, ge3.xl});
  xr = std::max({ge0.xr, ge1.xr, ge2.xr, ge3.xr});

  if (xl > xr)
    xl = xr;
}

// flying edges tables using: 


const unsigned char MeshGenerator::numTris[256] = 
    {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 2,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 3,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 3,
        2, 3, 3, 2, 3, 4, 4, 3, 3, 4, 4, 3, 4, 5, 5, 2,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 3,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 4,
        2, 3, 3, 4, 3, 4, 2, 3, 3, 4, 4, 5, 4, 5, 3, 2,
        3, 4, 4, 3, 4, 5, 3, 2, 4, 5, 5, 4, 5, 2, 4, 1,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 3,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 2, 4, 3, 4, 3, 5, 2,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 4,
        3, 4, 4, 3, 4, 5, 5, 4, 4, 3, 5, 2, 5, 4, 2, 1,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 2, 3, 3, 2,
        3, 4, 4, 5, 4, 5, 5, 2, 4, 3, 5, 4, 3, 2, 4, 1,
        3, 4, 4, 5, 4, 5, 3, 4, 4, 5, 5, 2, 3, 4, 2, 1,
        2, 3, 3, 2, 3, 4, 2, 1, 3, 2, 4, 1, 2, 1, 1, 0
    };

const bool MeshGenerator::isCut[256][12] = 
{
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0},
        {1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        {1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1},
        {1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1},
        {0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1},
        {0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0},
        {1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0},
        {1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0},
        {0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1},
        {1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1},
        {1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1},
        {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
        {0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0},
        {1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0},
        {1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0},
        {0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0},
        {0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1},
        {1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1},
        {1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1},
        {0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1},
        {0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0},
        {1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0},
        {1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0},
        {0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0},
        {0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1},
        {1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1},
        {1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1},
        {0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1},
        {0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0},
        {1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0},
        {1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0},
        {0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0},
        {0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1},
        {1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1},
        {1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1},
        {0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1},
        {0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0},
        {1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0},
        {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0},
        {0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0},
        {0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1},
        {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1},
        {1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1},
        {0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1},
        {0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0},
        {1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0},
        {1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0},
        {0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0},
        {0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1},
        {1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1},
        {1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1},
        {0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1},
        {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0},
        {1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0},
        {1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0},
        {0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0},
        {0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1},
        {1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1},
        {1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1},
        {0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1},
        {0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1},
        {1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1},
        {1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1},
        {0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1},
        {0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0},
        {1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0},
        {1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0},
        {0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0},
        {0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1},
        {1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1},
        {1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1},
        {0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1},
        {0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0},
        {1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0},
        {1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0},
        {0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0},
        {0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1},
        {1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1},
        {1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1},
        {0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1},
        {0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0},
        {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0},
        {1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0},
        {0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0},
        {0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1},
        {1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1},
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        {0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1},
        {0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0},
        {1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0},
        {1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0},
        {0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0},
        {0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1},
        {1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1},
        {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1},
        {0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1},
        {0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0},
        {1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0},
        {1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0},
        {0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0},
        {0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1},
        {1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1},
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1},
        {0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1},
        {0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0},
        {1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0},
        {1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0},
        {0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0},
        {0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1},
        {1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1},
        {1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1},
        {0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1},
        {0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0},
        {1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0},
        {1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0},
        {0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0},
        {0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1},
        {1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1},
        {1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1},
        {0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1},
        {0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0},
        {1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0},
        {1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0},
        {0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0},
        {0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0},
        {1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0},
        {1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0},
        {0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0},
        {0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1},
        {1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1},
        {1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1},
        {0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1},
        {0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0},
        {1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0},
        {0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0},
        {0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1},
        {1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1},
        {1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1},
        {0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1},
        {0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0},
        {1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0},
        {1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0},
        {0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0},
        {0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1},
        {1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1},
        {1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1},
        {0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1},
        {0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0},
        {1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0},
        {1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0},
        {0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0},
        {0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1},
        {1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1},
        {1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1},
        {0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1},
        {0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0},
        {1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0},
        {1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0},
        {0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0},
        {0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1},
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        {1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1},
        {0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1},
        {0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0},
        {1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0},
        {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0},
        {0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0},
        {0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1},
        {1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1},
        {1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1},
        {0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1},
        {0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0},
        {1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0},
        {1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0},
        {0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0},
        {0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1},
        {1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1},
        {1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1},
        {0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1},
        {0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0},
        {1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0},
        {1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0},
        {0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0},
        {0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1},
        {1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1},
        {1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1},
        {0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1},
        {1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1},
        {1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1},
        {0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1},
        {0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0},
        {1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0},
        {1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0},
        {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0},
        {0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1},
        {1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1},
        {1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1},
        {0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1},
        {0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0},
        {1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0},
        {1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0},
        {0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0},
        {0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1},
        {1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1},
        {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1},
        {0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1},
        {0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0},
        {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0},
        {1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0},
        {0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0},
        {0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1},
        {1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1},
        {1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1},
        {0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1},
        {0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0},
        {1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0},
        {0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0},
        {0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1},
        {1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1},
        {1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1},
        {0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1},
        {0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0},
        {1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0},
        {1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0},
        {0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0},
        {0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1},
        {1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1},
        {1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1},
        {0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1},
        {0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0},
        {1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0},
        {1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0},
        {0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
        {1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1},
        {1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1},
        {0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1},
        {0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0},
        {1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0},
        {1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0},
        {0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0},
        {0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1},
        {1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1},
        {1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        {0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0},
        {1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

const char MeshGenerator::caseTriangles[256][16]
    {
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  9,  1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  3,  8,  9,  1,  8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  1,  11, 2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  11, 2,  0,  9,  2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {2,  3,  8,  2,  8,  11, 11, 8,  9,  -1, -1, -1, -1, -1, -1, -1},
        {3,  2,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  2,  10, 8,  0,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  0,  9,  2,  10, 3,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  2,  10, 1,  10, 9,  9,  10, 8,  -1, -1, -1, -1, -1, -1, -1},
        {3,  1,  11, 10, 3,  11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  1,  11, 0,  11, 8,  8,  11, 10, -1, -1, -1, -1, -1, -1, -1},
        {3,  0,  9,  3,  9,  10, 10, 9,  11, -1, -1, -1, -1, -1, -1, -1},
        {9,  11, 8,  11, 10, 8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  8,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  0,  3,  7,  4,  3,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  9,  1,  8,  7,  4,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  9,  1,  4,  1,  7,  7,  1,  3,  -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  8,  7,  4,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  7,  4,  3,  4,  0,  1,  11, 2,  -1, -1, -1, -1, -1, -1, -1},
        {9,  11, 2,  9,  2,  0,  8,  7,  4,  -1, -1, -1, -1, -1, -1, -1},
        {2,  9,  11, 2,  7,  9,  2,  3,  7,  7,  4,  9,  -1, -1, -1, -1},
        {8,  7,  4,  3,  2,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {10, 7,  4,  10, 4,  2,  2,  4,  0,  -1, -1, -1, -1, -1, -1, -1},
        {9,  1,  0,  8,  7,  4,  2,  10, 3,  -1, -1, -1, -1, -1, -1, -1},
        {4,  10, 7,  9,  10, 4,  9,  2,  10, 9,  1,  2,  -1, -1, -1, -1},
        {3,  1,  11, 3,  11, 10, 7,  4,  8,  -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 10, 1,  10, 4,  1,  4,  0,  7,  4,  10, -1, -1, -1, -1},
        {4,  8,  7,  9,  10, 0,  9,  11, 10, 10, 3,  0,  -1, -1, -1, -1},
        {4,  10, 7,  4,  9,  10, 9,  11, 10, -1, -1, -1, -1, -1, -1, -1},
        {9,  4,  5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  4,  5,  0,  3,  8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  4,  5,  1,  0,  5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {8,  4,  5,  8,  5,  3,  3,  5,  1,  -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  9,  4,  5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  8,  0,  1,  11, 2,  4,  5,  9,  -1, -1, -1, -1, -1, -1, -1},
        {5,  11, 2,  5,  2,  4,  4,  2,  0,  -1, -1, -1, -1, -1, -1, -1},
        {2,  5,  11, 3,  5,  2,  3,  4,  5,  3,  8,  4,  -1, -1, -1, -1},
        {9,  4,  5,  2,  10, 3,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  2,  10, 0,  10, 8,  4,  5,  9,  -1, -1, -1, -1, -1, -1, -1},
        {0,  4,  5,  0,  5,  1,  2,  10, 3,  -1, -1, -1, -1, -1, -1, -1},
        {2,  5,  1,  2,  8,  5,  2,  10, 8,  4,  5,  8,  -1, -1, -1, -1},
        {11, 10, 3,  11, 3,  1,  9,  4,  5,  -1, -1, -1, -1, -1, -1, -1},
        {4,  5,  9,  0,  1,  8,  8,  1,  11, 8,  11, 10, -1, -1, -1, -1},
        {5,  0,  4,  5,  10, 0,  5,  11, 10, 10, 3,  0,  -1, -1, -1, -1},
        {5,  8,  4,  5,  11, 8,  11, 10, 8,  -1, -1, -1, -1, -1, -1, -1},
        {9,  8,  7,  5,  9,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  0,  3,  9,  3,  5,  5,  3,  7,  -1, -1, -1, -1, -1, -1, -1},
        {0,  8,  7,  0,  7,  1,  1,  7,  5,  -1, -1, -1, -1, -1, -1, -1},
        {1,  3,  5,  3,  7,  5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  8,  7,  9,  7,  5,  11, 2,  1,  -1, -1, -1, -1, -1, -1, -1},
        {11, 2,  1,  9,  0,  5,  5,  0,  3,  5,  3,  7,  -1, -1, -1, -1},
        {8,  2,  0,  8,  5,  2,  8,  7,  5,  11, 2,  5,  -1, -1, -1, -1},
        {2,  5,  11, 2,  3,  5,  3,  7,  5,  -1, -1, -1, -1, -1, -1, -1},
        {7,  5,  9,  7,  9,  8,  3,  2,  10, -1, -1, -1, -1, -1, -1, -1},
        {9,  7,  5,  9,  2,  7,  9,  0,  2,  2,  10, 7,  -1, -1, -1, -1},
        {2,  10, 3,  0,  8,  1,  1,  8,  7,  1,  7,  5,  -1, -1, -1, -1},
        {10, 1,  2,  10, 7,  1,  7,  5,  1,  -1, -1, -1, -1, -1, -1, -1},
        {9,  8,  5,  8,  7,  5,  11, 3,  1,  11, 10, 3,  -1, -1, -1, -1},
        {5,  0,  7,  5,  9,  0,  7,  0,  10, 1,  11, 0,  10, 0,  11, -1},
        {10, 0,  11, 10, 3,  0,  11, 0,  5,  8,  7,  0,  5,  0,  7,  -1},
        {10, 5,  11, 7,  5,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {11, 5,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  5,  6,  11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  1,  0,  5,  6,  11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  3,  8,  1,  8,  9,  5,  6,  11, -1, -1, -1, -1, -1, -1, -1},
        {1,  5,  6,  2,  1,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  5,  6,  1,  6,  2,  3,  8,  0,  -1, -1, -1, -1, -1, -1, -1},
        {9,  5,  6,  9,  6,  0,  0,  6,  2,  -1, -1, -1, -1, -1, -1, -1},
        {5,  8,  9,  5,  2,  8,  5,  6,  2,  3,  8,  2,  -1, -1, -1, -1},
        {2,  10, 3,  11, 5,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {10, 8,  0,  10, 0,  2,  11, 5,  6,  -1, -1, -1, -1, -1, -1, -1},
        {0,  9,  1,  2,  10, 3,  5,  6,  11, -1, -1, -1, -1, -1, -1, -1},
        {5,  6,  11, 1,  2,  9,  9,  2,  10, 9,  10, 8,  -1, -1, -1, -1},
        {6,  10, 3,  6,  3,  5,  5,  3,  1,  -1, -1, -1, -1, -1, -1, -1},
        {0,  10, 8,  0,  5,  10, 0,  1,  5,  5,  6,  10, -1, -1, -1, -1},
        {3,  6,  10, 0,  6,  3,  0,  5,  6,  0,  9,  5,  -1, -1, -1, -1},
        {6,  9,  5,  6,  10, 9,  10, 8,  9,  -1, -1, -1, -1, -1, -1, -1},
        {5,  6,  11, 4,  8,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  0,  3,  4,  3,  7,  6,  11, 5,  -1, -1, -1, -1, -1, -1, -1},
        {1,  0,  9,  5,  6,  11, 8,  7,  4,  -1, -1, -1, -1, -1, -1, -1},
        {11, 5,  6,  1,  7,  9,  1,  3,  7,  7,  4,  9,  -1, -1, -1, -1},
        {6,  2,  1,  6,  1,  5,  4,  8,  7,  -1, -1, -1, -1, -1, -1, -1},
        {1,  5,  2,  5,  6,  2,  3,  4,  0,  3,  7,  4,  -1, -1, -1, -1},
        {8,  7,  4,  9,  5,  0,  0,  5,  6,  0,  6,  2,  -1, -1, -1, -1},
        {7,  9,  3,  7,  4,  9,  3,  9,  2,  5,  6,  9,  2,  9,  6,  -1},
        {3,  2,  10, 7,  4,  8,  11, 5,  6,  -1, -1, -1, -1, -1, -1, -1},
        {5,  6,  11, 4,  2,  7,  4,  0,  2,  2,  10, 7,  -1, -1, -1, -1},
        {0,  9,  1,  4,  8,  7,  2,  10, 3,  5,  6,  11, -1, -1, -1, -1},
        {9,  1,  2,  9,  2,  10, 9,  10, 4,  7,  4,  10, 5,  6,  11, -1},
        {8,  7,  4,  3,  5,  10, 3,  1,  5,  5,  6,  10, -1, -1, -1, -1},
        {5,  10, 1,  5,  6,  10, 1,  10, 0,  7,  4,  10, 0,  10, 4,  -1},
        {0,  9,  5,  0,  5,  6,  0,  6,  3,  10, 3,  6,  8,  7,  4,  -1},
        {6,  9,  5,  6,  10, 9,  4,  9,  7,  7,  9,  10, -1, -1, -1, -1},
        {11, 9,  4,  6,  11, 4,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  6,  11, 4,  11, 9,  0,  3,  8,  -1, -1, -1, -1, -1, -1, -1},
        {11, 1,  0,  11, 0,  6,  6,  0,  4,  -1, -1, -1, -1, -1, -1, -1},
        {8,  1,  3,  8,  6,  1,  8,  4,  6,  6,  11, 1,  -1, -1, -1, -1},
        {1,  9,  4,  1,  4,  2,  2,  4,  6,  -1, -1, -1, -1, -1, -1, -1},
        {3,  8,  0,  1,  9,  2,  2,  9,  4,  2,  4,  6,  -1, -1, -1, -1},
        {0,  4,  2,  4,  6,  2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {8,  2,  3,  8,  4,  2,  4,  6,  2,  -1, -1, -1, -1, -1, -1, -1},
        {11, 9,  4,  11, 4,  6,  10, 3,  2,  -1, -1, -1, -1, -1, -1, -1},
        {0,  2,  8,  2,  10, 8,  4,  11, 9,  4,  6,  11, -1, -1, -1, -1},
        {3,  2,  10, 0,  6,  1,  0,  4,  6,  6,  11, 1,  -1, -1, -1, -1},
        {6,  1,  4,  6,  11, 1,  4,  1,  8,  2,  10, 1,  8,  1,  10, -1},
        {9,  4,  6,  9,  6,  3,  9,  3,  1,  10, 3,  6,  -1, -1, -1, -1},
        {8,  1,  10, 8,  0,  1,  10, 1,  6,  9,  4,  1,  6,  1,  4,  -1},
        {3,  6,  10, 3,  0,  6,  0,  4,  6,  -1, -1, -1, -1, -1, -1, -1},
        {6,  8,  4,  10, 8,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {7,  6,  11, 7,  11, 8,  8,  11, 9,  -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  7,  0,  7,  11, 0,  11, 9,  6,  11, 7,  -1, -1, -1, -1},
        {11, 7,  6,  1,  7,  11, 1,  8,  7,  1,  0,  8,  -1, -1, -1, -1},
        {11, 7,  6,  11, 1,  7,  1,  3,  7,  -1, -1, -1, -1, -1, -1, -1},
        {1,  6,  2,  1,  8,  6,  1,  9,  8,  8,  7,  6,  -1, -1, -1, -1},
        {2,  9,  6,  2,  1,  9,  6,  9,  7,  0,  3,  9,  7,  9,  3,  -1},
        {7,  0,  8,  7,  6,  0,  6,  2,  0,  -1, -1, -1, -1, -1, -1, -1},
        {7,  2,  3,  6,  2,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {2,  10, 3,  11, 8,  6,  11, 9,  8,  8,  7,  6,  -1, -1, -1, -1},
        {2,  7,  0,  2,  10, 7,  0,  7,  9,  6,  11, 7,  9,  7,  11, -1},
        {1,  0,  8,  1,  8,  7,  1,  7,  11, 6,  11, 7,  2,  10, 3,  -1},
        {10, 1,  2,  10, 7,  1,  11, 1,  6,  6,  1,  7,  -1, -1, -1, -1},
        {8,  6,  9,  8,  7,  6,  9,  6,  1,  10, 3,  6,  1,  6,  3,  -1},
        {0,  1,  9,  10, 7,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {7,  0,  8,  7,  6,  0,  3,  0,  10, 10, 0,  6,  -1, -1, -1, -1},
        {7,  6,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {7,  10, 6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  8,  0,  10, 6,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  9,  1,  10, 6,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {8,  9,  1,  8,  1,  3,  10, 6,  7,  -1, -1, -1, -1, -1, -1, -1},
        {11, 2,  1,  6,  7,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  3,  8,  0,  6,  7,  10, -1, -1, -1, -1, -1, -1, -1},
        {2,  0,  9,  2,  9,  11, 6,  7,  10, -1, -1, -1, -1, -1, -1, -1},
        {6,  7,  10, 2,  3,  11, 11, 3,  8,  11, 8,  9,  -1, -1, -1, -1},
        {7,  3,  2,  6,  7,  2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {7,  8,  0,  7,  0,  6,  6,  0,  2,  -1, -1, -1, -1, -1, -1, -1},
        {2,  6,  7,  2,  7,  3,  0,  9,  1,  -1, -1, -1, -1, -1, -1, -1},
        {1,  2,  6,  1,  6,  8,  1,  8,  9,  8,  6,  7,  -1, -1, -1, -1},
        {11, 6,  7,  11, 7,  1,  1,  7,  3,  -1, -1, -1, -1, -1, -1, -1},
        {11, 6,  7,  1,  11, 7,  1,  7,  8,  1,  8,  0,  -1, -1, -1, -1},
        {0,  7,  3,  0,  11, 7,  0,  9,  11, 6,  7,  11, -1, -1, -1, -1},
        {7,  11, 6,  7,  8,  11, 8,  9,  11, -1, -1, -1, -1, -1, -1, -1},
        {6,  4,  8,  10, 6,  8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  10, 6,  3,  6,  0,  0,  6,  4,  -1, -1, -1, -1, -1, -1, -1},
        {8,  10, 6,  8,  6,  4,  9,  1,  0,  -1, -1, -1, -1, -1, -1, -1},
        {9,  6,  4,  9,  3,  6,  9,  1,  3,  10, 6,  3,  -1, -1, -1, -1},
        {6,  4,  8,  6,  8,  10, 2,  1,  11, -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  3,  10, 0,  0,  10, 6,  0,  6,  4,  -1, -1, -1, -1},
        {4,  8,  10, 4,  10, 6,  0,  9,  2,  2,  9,  11, -1, -1, -1, -1},
        {11, 3,  9,  11, 2,  3,  9,  3,  4,  10, 6,  3,  4,  3,  6,  -1},
        {8,  3,  2,  8,  2,  4,  4,  2,  6,  -1, -1, -1, -1, -1, -1, -1},
        {0,  2,  4,  4,  2,  6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  0,  9,  2,  4,  3,  2,  6,  4,  4,  8,  3,  -1, -1, -1, -1},
        {1,  4,  9,  1,  2,  4,  2,  6,  4,  -1, -1, -1, -1, -1, -1, -1},
        {8,  3,  1,  8,  1,  6,  8,  6,  4,  6,  1,  11, -1, -1, -1, -1},
        {11, 0,  1,  11, 6,  0,  6,  4,  0,  -1, -1, -1, -1, -1, -1, -1},
        {4,  3,  6,  4,  8,  3,  6,  3,  11, 0,  9,  3,  11, 3,  9,  -1},
        {11, 4,  9,  6,  4,  11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  5,  9,  7,  10, 6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  4,  5,  9,  10, 6,  7,  -1, -1, -1, -1, -1, -1, -1},
        {5,  1,  0,  5,  0,  4,  7,  10, 6,  -1, -1, -1, -1, -1, -1, -1},
        {10, 6,  7,  8,  4,  3,  3,  4,  5,  3,  5,  1,  -1, -1, -1, -1},
        {9,  4,  5,  11, 2,  1,  7,  10, 6,  -1, -1, -1, -1, -1, -1, -1},
        {6,  7,  10, 1,  11, 2,  0,  3,  8,  4,  5,  9,  -1, -1, -1, -1},
        {7,  10, 6,  5,  11, 4,  4,  11, 2,  4,  2,  0,  -1, -1, -1, -1},
        {3,  8,  4,  3,  4,  5,  3,  5,  2,  11, 2,  5,  10, 6,  7,  -1},
        {7,  3,  2,  7,  2,  6,  5,  9,  4,  -1, -1, -1, -1, -1, -1, -1},
        {9,  4,  5,  0,  6,  8,  0,  2,  6,  6,  7,  8,  -1, -1, -1, -1},
        {3,  2,  6,  3,  6,  7,  1,  0,  5,  5,  0,  4,  -1, -1, -1, -1},
        {6,  8,  2,  6,  7,  8,  2,  8,  1,  4,  5,  8,  1,  8,  5,  -1},
        {9,  4,  5,  11, 6,  1,  1,  6,  7,  1,  7,  3,  -1, -1, -1, -1},
        {1,  11, 6,  1,  6,  7,  1,  7,  0,  8,  0,  7,  9,  4,  5,  -1},
        {4,  11, 0,  4,  5,  11, 0,  11, 3,  6,  7,  11, 3,  11, 7,  -1},
        {7,  11, 6,  7,  8,  11, 5,  11, 4,  4,  11, 8,  -1, -1, -1, -1},
        {6,  5,  9,  6,  9,  10, 10, 9,  8,  -1, -1, -1, -1, -1, -1, -1},
        {3,  10, 6,  0,  3,  6,  0,  6,  5,  0,  5,  9,  -1, -1, -1, -1},
        {0,  8,  10, 0,  10, 5,  0,  5,  1,  5,  10, 6,  -1, -1, -1, -1},
        {6,  3,  10, 6,  5,  3,  5,  1,  3,  -1, -1, -1, -1, -1, -1, -1},
        {1,  11, 2,  9,  10, 5,  9,  8,  10, 10, 6,  5,  -1, -1, -1, -1},
        {0,  3,  10, 0,  10, 6,  0,  6,  9,  5,  9,  6,  1,  11, 2,  -1},
        {10, 5,  8,  10, 6,  5,  8,  5,  0,  11, 2,  5,  0,  5,  2,  -1},
        {6,  3,  10, 6,  5,  3,  2,  3,  11, 11, 3,  5,  -1, -1, -1, -1},
        {5,  9,  8,  5,  8,  2,  5,  2,  6,  3,  2,  8,  -1, -1, -1, -1},
        {9,  6,  5,  9,  0,  6,  0,  2,  6,  -1, -1, -1, -1, -1, -1, -1},
        {1,  8,  5,  1,  0,  8,  5,  8,  6,  3,  2,  8,  6,  8,  2,  -1},
        {1,  6,  5,  2,  6,  1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  6,  3,  1,  11, 6,  3,  6,  8,  5,  9,  6,  8,  6,  9,  -1},
        {11, 0,  1,  11, 6,  0,  9,  0,  5,  5,  0,  6,  -1, -1, -1, -1},
        {0,  8,  3,  5,  11, 6,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {11, 6,  5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {10, 11, 5,  7,  10, 5,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {10, 11, 5,  10, 5,  7,  8,  0,  3,  -1, -1, -1, -1, -1, -1, -1},
        {5,  7,  10, 5,  10, 11, 1,  0,  9,  -1, -1, -1, -1, -1, -1, -1},
        {11, 5,  7,  11, 7,  10, 9,  1,  8,  8,  1,  3,  -1, -1, -1, -1},
        {10, 2,  1,  10, 1,  7,  7,  1,  5,  -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  1,  7,  2,  1,  5,  7,  7,  10, 2,  -1, -1, -1, -1},
        {9,  5,  7,  9,  7,  2,  9,  2,  0,  2,  7,  10, -1, -1, -1, -1},
        {7,  2,  5,  7,  10, 2,  5,  2,  9,  3,  8,  2,  9,  2,  8,  -1},
        {2,  11, 5,  2,  5,  3,  3,  5,  7,  -1, -1, -1, -1, -1, -1, -1},
        {8,  0,  2,  8,  2,  5,  8,  5,  7,  11, 5,  2,  -1, -1, -1, -1},
        {9,  1,  0,  5,  3,  11, 5,  7,  3,  3,  2,  11, -1, -1, -1, -1},
        {9,  2,  8,  9,  1,  2,  8,  2,  7,  11, 5,  2,  7,  2,  5,  -1},
        {1,  5,  3,  3,  5,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  7,  8,  0,  1,  7,  1,  5,  7,  -1, -1, -1, -1, -1, -1, -1},
        {9,  3,  0,  9,  5,  3,  5,  7,  3,  -1, -1, -1, -1, -1, -1, -1},
        {9,  7,  8,  5,  7,  9,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {5,  4,  8,  5,  8,  11, 11, 8,  10, -1, -1, -1, -1, -1, -1, -1},
        {5,  4,  0,  5,  0,  10, 5,  10, 11, 10, 0,  3,  -1, -1, -1, -1},
        {0,  9,  1,  8,  11, 4,  8,  10, 11, 11, 5,  4,  -1, -1, -1, -1},
        {11, 4,  10, 11, 5,  4,  10, 4,  3,  9,  1,  4,  3,  4,  1,  -1},
        {2,  1,  5,  2,  5,  8,  2,  8,  10, 4,  8,  5,  -1, -1, -1, -1},
        {0,  10, 4,  0,  3,  10, 4,  10, 5,  2,  1,  10, 5,  10, 1,  -1},
        {0,  5,  2,  0,  9,  5,  2,  5,  10, 4,  8,  5,  10, 5,  8,  -1},
        {9,  5,  4,  2,  3,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {2,  11, 5,  3,  2,  5,  3,  5,  4,  3,  4,  8,  -1, -1, -1, -1},
        {5,  2,  11, 5,  4,  2,  4,  0,  2,  -1, -1, -1, -1, -1, -1, -1},
        {3,  2,  11, 3,  11, 5,  3,  5,  8,  4,  8,  5,  0,  9,  1,  -1},
        {5,  2,  11, 5,  4,  2,  1,  2,  9,  9,  2,  4,  -1, -1, -1, -1},
        {8,  5,  4,  8,  3,  5,  3,  1,  5,  -1, -1, -1, -1, -1, -1, -1},
        {0,  5,  4,  1,  5,  0,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {8,  5,  4,  8,  3,  5,  9,  5,  0,  0,  5,  3,  -1, -1, -1, -1},
        {9,  5,  4,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  7,  10, 4,  10, 9,  9,  10, 11, -1, -1, -1, -1, -1, -1, -1},
        {0,  3,  8,  4,  7,  9,  9,  7,  10, 9,  10, 11, -1, -1, -1, -1},
        {1,  10, 11, 1,  4,  10, 1,  0,  4,  7,  10, 4,  -1, -1, -1, -1},
        {3,  4,  1,  3,  8,  4,  1,  4,  11, 7,  10, 4,  11, 4,  10, -1},
        {4,  7,  10, 9,  4,  10, 9,  10, 2,  9,  2,  1,  -1, -1, -1, -1},
        {9,  4,  7,  9,  7,  10, 9,  10, 1,  2,  1,  10, 0,  3,  8,  -1},
        {10, 4,  7,  10, 2,  4,  2,  0,  4,  -1, -1, -1, -1, -1, -1, -1},
        {10, 4,  7,  10, 2,  4,  8,  4,  3,  3,  4,  2,  -1, -1, -1, -1},
        {2,  11, 9,  2,  9,  7,  2,  7,  3,  7,  9,  4,  -1, -1, -1, -1},
        {9,  7,  11, 9,  4,  7,  11, 7,  2,  8,  0,  7,  2,  7,  0,  -1},
        {3,  11, 7,  3,  2,  11, 7,  11, 4,  1,  0,  11, 4,  11, 0,  -1},
        {1,  2,  11, 8,  4,  7,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  1,  9,  4,  7,  1,  7,  3,  1,  -1, -1, -1, -1, -1, -1, -1},
        {4,  1,  9,  4,  7,  1,  0,  1,  8,  8,  1,  7,  -1, -1, -1, -1},
        {4,  3,  0,  7,  3,  4,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {4,  7,  8,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {9,  8,  11, 11, 8,  10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  9,  0,  3,  10, 9,  10, 11, 9,  -1, -1, -1, -1, -1, -1, -1},
        {0,  11, 1,  0,  8,  11, 8,  10, 11, -1, -1, -1, -1, -1, -1, -1},
        {3,  11, 1,  10, 11, 3,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  10, 2,  1,  9,  10, 9,  8,  10, -1, -1, -1, -1, -1, -1, -1},
        {3,  9,  0,  3,  10, 9,  1,  9,  2,  2,  9,  10, -1, -1, -1, -1},
        {0,  10, 2,  8,  10, 0,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {3,  10, 2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {2,  8,  3,  2,  11, 8,  11, 9,  8,  -1, -1, -1, -1, -1, -1, -1},
        {9,  2,  11, 0,  2,  9,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {2,  8,  3,  2,  11, 8,  0,  8,  1,  1,  8,  11, -1, -1, -1, -1},
        {1,  2,  11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {1,  8,  3,  9,  8,  1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  1,  9,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0,  8,  3,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}
    };

const unsigned char edgeVertices[12][2] = 
  { 
        {0,1}, {1,2}, {3,2},
        {0,3}, {4,5}, {5,6},
        {7,6}, {4,7}, {0,4},
        {1,5}, {3,7}, {2,6}
    };

} // End namespace Avogadro
