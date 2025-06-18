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
  : QThread(p), m_iso(0.0), m_passes(6), m_reverseWinding(false),
    m_cube(nullptr), m_mesh(nullptr), m_stepSize(0.0, 0.0, 0.0),
    m_min(0.0, 0.0, 0.0), m_dim(0, 0, 0), m_progmin(0), m_progmax(0)
{
}

MeshGenerator::MeshGenerator(const Cube* cube_, Mesh* mesh_, float iso,
                             int passes, bool reverse, QObject* p)
  : QThread(p), m_iso(0.0), m_passes(6), m_reverseWinding(reverse),
    m_cube(nullptr), m_mesh(nullptr), m_stepSize(0.0, 0.0, 0.0),
    m_min(0.0, 0.0, 0.0), m_dim(0, 0, 0), m_progmin(0), m_progmax(0)
{
  initialize(cube_, mesh_, iso, passes);
}

MeshGenerator::~MeshGenerator() {}

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

  for (unsigned int i = 0; i < 3; ++i)
    m_stepSize[i] = static_cast<float>(m_cube->spacing()[i]);
  m_min = m_cube->min().cast<float>();
  m_dim = m_cube->dimensions();
  edgeCases.resize((m_dim.x() - 1) * (m_dim.y()) * (m_dim.z()));
  cubeCases.resize((m_dim.x() - 1) * (m_dim.y() - 1) * (m_dim.z() - 1));
  gridEdges.resize(m_dim.y() * m_dim.z());
  triCounter.resize((m_dim.y() - 1) * (m_dim.z() - 1));

  m_progmax = m_dim.x();

  return true;
}

void MeshGenerator::FlyingEdgesAlgorithmPass1()
{
  for (int k = 0; k != m_dim.z(); ++k) {
    for (int j = 0; j != m_dim.y(); ++j) {

      auto curEdgeCases =
        edgeCases.begin() + (m_dim.x() - 1) * (k * m_dim.y() + j);
      std::array<bool, 2> isGE;
      isGE[0] = (m_cube->getData(0, j, k) >= m_iso);

      for (int i = 1; i != m_dim.x(); ++i) {
        isGE[i % 2] = (m_cube->getData(i, j, k) >= m_iso);
        curEdgeCases[i - 1] = calcCaseEdge(isGE[(i + 1) % 2], isGE[i % 2]);
      }
    }
  }

  for (int k = 0; k != m_dim.z(); ++k) {
    for (int j = 0; j != m_dim.y(); ++j) {
      gridEdge& curGridEdge = gridEdges[k * m_dim.y() + j];
      curGridEdge.xl = m_dim.x();

      for (int i = 1; i != m_dim.x(); ++i) {
        // if the edge is cut
        if (isCutEdge(i - 1, j, k)) {
          if (curGridEdge.xl == m_dim.x()) {
            curGridEdge.xl = i - 1;
          }
          curGridEdge.xr = i;
        }
      }
    }
  }
}

void MeshGenerator::FlyingEdgesAlgorithmPass2()
{
  for (int k = 0; k != m_dim.z() - 1; ++k) {
    for (int j = 0; j != m_dim.y() - 1; ++j) {
      int xl, xr;
      calcTrimValues(xl, xr, j, k); // xl, xr set in this function

      gridEdge& ge0 = gridEdges[k * m_dim.y() + j];
      gridEdge& ge1 = gridEdges[k * m_dim.y() + j + 1];
      gridEdge& ge2 = gridEdges[(k + 1) * m_dim.y() + j];
      gridEdge& ge3 = gridEdges[(k + 1) * m_dim.y() + j + 1];

      auto const& ec0 =
        edgeCases.begin() + (m_dim.x() - 1) * (k * m_dim.y() + j);
      auto const& ec1 =
        edgeCases.begin() + (m_dim.x() - 1) * (k * m_dim.y() + j + 1);
      auto const& ec2 =
        edgeCases.begin() + (m_dim.x() - 1) * ((k + 1) * m_dim.y() + j);
      auto const& ec3 =
        edgeCases.begin() + (m_dim.x() - 1) * ((k + 1) * m_dim.y() + j + 1);

      // Count the number of triangles along this row of cubes
      int& curTriCounter = *(triCounter.begin() + k * (m_dim.y() - 1) + j);

      auto curCubeCaseIds =
        cubeCases.begin() + (m_dim.x() - 1) * (k * (m_dim.y() - 1) + j);

      bool isYEnd = (j == m_dim.y() - 2);
      bool isZEnd = (k == m_dim.z() - 2);

      for (int i = xl; i != xr; ++i) {
        bool isXEnd = (i == m_dim.x() - 2);

        unsigned char caseId = calcCubeCase(
          ec0[i], ec1[i], ec2[i], ec3[i]); // todo cubeCase not decleared
        curCubeCaseIds[i] = caseId;

        if (caseId == 0 || caseId == 255) {
          continue;
        }

        curTriCounter += m_numTris[caseId]; // not declared

        const bool* isCutCase = m_isCut[caseId]; // size 12

        ge0.xstart += isCutCase[0];
        ge0.ystart += isCutCase[3];
        ge0.zstart += isCutCase[8];

        if (isXEnd) {
          ge0.ystart += isCutCase[1];
          ge0.zstart += isCutCase[9];
        }

        if (isYEnd) {
          ge1.xstart += isCutCase[2];
          ge1.zstart += isCutCase[10];
        }
        if (isZEnd) {
          ge2.xstart += isCutCase[4];
          ge2.ystart += isCutCase[7];
        }
        if (isXEnd && isYEnd) {
          ge1.zstart += isCutCase[11];
        }
        if (isXEnd && isZEnd) {
          ge2.ystart += isCutCase[5];
        }
        if (isYEnd && isZEnd) {
          ge3.xstart += isCutCase[6];
        }
      }
    }
  }
}

void MeshGenerator::FlyingEdgesAlgorithmPass3()
{
  int tmp;
  int triAccum = 0;
  for (int k = 0; k != m_dim.z() - 1; ++k) {
    for (int j = 0; j != m_dim.y() - 1; ++j) {
      int& curTriCounter = triCounter[k * (m_dim.y() - 1) + j];

      tmp = curTriCounter;
      curTriCounter = triAccum;
      triAccum += tmp;
    }
  }

  int pointAccum = 0;
  for (int k = 0; k != m_dim.z(); ++k) {
    for (int j = 0; j != m_dim.y(); ++j) {
      gridEdge& curGridEdge = gridEdges[(k * m_dim.y()) + j];

      tmp = curGridEdge.xstart;
      curGridEdge.xstart = pointAccum;
      pointAccum += tmp;

      tmp = curGridEdge.ystart;
      curGridEdge.ystart = pointAccum;
      pointAccum += tmp;

      tmp = curGridEdge.zstart;
      curGridEdge.zstart = pointAccum;
      pointAccum += tmp;
    }
  }

  m_vertices.resize(pointAccum);
  m_normals.resize(pointAccum);
  m_triangles.resize(triAccum);
}

void MeshGenerator::FlyingEdgesAlgorithmPass4()
{

  for (int k = 0; k != m_dim.z() - 1; ++k) {
    for (int j = 0; j != m_dim.y() - 1; ++j) {
      // find adjusted trim values
      int xl, xr;
      calcTrimValues(xl, xr, j, k); // xl, xr set in this function

      if (xl == xr)
        continue;

      int triIdx = triCounter[(k * (m_dim.y() - 1)) + j];
      auto curCubeCaseIds =
        cubeCases.begin() + (m_dim.x() - 1) * (k * (m_dim.y() - 1) + j);

      gridEdge const& ge0 = gridEdges[k * m_dim.y() + j];
      gridEdge const& ge1 = gridEdges[k * m_dim.y() + j + 1];
      gridEdge const& ge2 = gridEdges[(k + 1) * m_dim.y() + j];
      gridEdge const& ge3 = gridEdges[(k + 1) * m_dim.y() + j + 1];

      int x0counter = 0;
      int y0counter = 0;
      int z0counter = 0;

      int x1counter = 0;
      int z1counter = 0;

      int x2counter = 0;
      int y2counter = 0;

      int x3counter = 0;

      bool isYEnd = (j == m_dim.y() - 2);
      bool isZEnd = (k == m_dim.z() - 2);

      for (int i = xl; i != xr; ++i) {
        bool isXEnd = (i == m_dim.x() - 2);

        unsigned char caseId = curCubeCaseIds[i];

        if (caseId == 0 || caseId == 255) {
          continue;
        }

        const bool* isCutCase = m_isCut[caseId]; // size 12
        std::array<std::array<float, 3>, 8> pointCube =
          m_cube->getPosCube(i, j, k);
        std::array<float, 8> isovalCube = m_cube->getValsCube(i, j, k);
        std::array<std::array<float, 3>, 8> gradCube =
          m_cube->getGradCube(i, j, k);

        // Add Points and normals.
        // Calculate global indices for triangles
        std::array<int, 12> globalIdxs;

        if (isCutCase[0]) {
          // points-> array<vector3f>
          int idx = ge0.xstart + x0counter;
          std::array<float, 3> interpolatedPoint =
            interpolateOnCube(pointCube, isovalCube, 0);
          std::array<float, 3> interpolatedNormal =
            interpolateOnCube(gradCube, isovalCube, 0);

          m_vertices[idx] = Vector3f(interpolatedPoint[0], interpolatedPoint[1],
                                     interpolatedPoint[2]);
          m_normals[idx] =
            Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                     interpolatedNormal[2]);
          globalIdxs[0] = idx;
          ++x0counter;
        }

        if (isCutCase[3]) {
          int idx = ge0.ystart + y0counter;
          std::array<float, 3> interpolatedPoint =
            interpolateOnCube(pointCube, isovalCube, 3);
          std::array<float, 3> interpolatedNormal =
            interpolateOnCube(gradCube, isovalCube, 3);
          m_vertices[idx] = Vector3f(interpolatedPoint[0], interpolatedPoint[1],
                                     interpolatedPoint[2]);
          m_normals[idx] =
            Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                     interpolatedNormal[2]);
          globalIdxs[3] = idx;
          ++y0counter;
        }

        if (isCutCase[8]) {
          int idx = ge0.zstart + z0counter;
          std::array<float, 3> interpolatedPoint =
            interpolateOnCube(pointCube, isovalCube, 8);
          std::array<float, 3> interpolatedNormal =
            interpolateOnCube(gradCube, isovalCube, 8);
          m_vertices[idx] = Vector3f(interpolatedPoint[0], interpolatedPoint[1],
                                     interpolatedPoint[2]);
          m_normals[idx] =
            Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                     interpolatedNormal[2]);
          globalIdxs[8] = idx;
          ++z0counter;
        }

        if (isCutCase[1]) {
          int idx = ge0.ystart + y0counter;
          if (isXEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 1);
            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 1);
            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
            // y0counter counter doesn't need to be incremented
            // because it won't be used again.
          }
          globalIdxs[1] = idx;
        }

        if (isCutCase[9]) {
          int idx = ge0.zstart + z0counter;
          if (isXEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 9);
            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 9);
            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
            // z0counter doesn't need to in incremented.
          }
          globalIdxs[9] = idx;
        }

        if (isCutCase[2]) {
          int idx = ge1.xstart + x1counter;
          if (isYEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 2);
            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 2);
            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[2] = idx;
          ++x1counter;
        }

        if (isCutCase[10]) {
          int idx = ge1.zstart + z1counter;

          if (isYEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 10);
            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 10);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[10] = idx;
          ++z1counter;
        }

        if (isCutCase[4]) {
          int idx = ge2.xstart + x2counter;
          if (isZEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 4);

            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 4);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[4] = idx;
          ++x2counter;
        }

        if (isCutCase[7]) {
          int idx = ge2.ystart + y2counter;
          if (isZEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 7);

            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 7);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[7] = idx;
          ++y2counter;
        }

        if (isCutCase[11]) {
          int idx = ge1.zstart + z1counter;
          if (isXEnd && isYEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 11);

            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 11);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[11] = idx;
        }

        if (isCutCase[5]) {
          int idx = ge2.ystart + y2counter;
          if (isXEnd && isZEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 5);

            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 5);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
            // y2 counter does not need to be incremented.
          }
          globalIdxs[5] = idx;
        }

        if (isCutCase[6]) {
          int idx = ge3.xstart + x3counter;
          if (isYEnd && isZEnd) {
            std::array<float, 3> interpolatedPoint =
              interpolateOnCube(pointCube, isovalCube, 6);
            std::array<float, 3> interpolatedNormal =
              interpolateOnCube(gradCube, isovalCube, 6);

            m_vertices[idx] = Vector3f(
              interpolatedPoint[0], interpolatedPoint[1], interpolatedPoint[2]);
            m_normals[idx] =
              Vector3f(interpolatedNormal[0], interpolatedNormal[1],
                       interpolatedNormal[2]);
          }
          globalIdxs[6] = idx;
          ++x3counter;
        }

        // Add triangles
        const signed char* caseTri = m_caseTriangles[caseId]; // size 16
        for (int idx = 0; caseTri[idx] != -1; idx += 3) {

          m_triangles[triIdx][0] = globalIdxs[caseTri[idx]];
          m_triangles[triIdx][1] = globalIdxs[caseTri[idx + 1]];
          m_triangles[triIdx][2] = globalIdxs[caseTri[idx + 2]];
          ++triIdx;
        }
      }
    }
  }
}

void MeshGenerator::run()
{
  if (!m_cube || !m_mesh) {
    qDebug() << "No mesh or cube set - nothing to find isosurface of…";
    return;
  }

  m_mesh->setStable(false);
  m_mesh->clear();

  // flying-edges passes for the creation of normal, vertices and triangles
  FlyingEdgesAlgorithmPass1();
  FlyingEdgesAlgorithmPass2();
  FlyingEdgesAlgorithmPass3();
  FlyingEdgesAlgorithmPass4();

  m_mesh->setVertices(m_vertices);
  m_mesh->setNormals(m_normals);
  m_mesh->setTriangles(m_triangles);
  m_mesh->smooth(m_passes);
  m_mesh->setStable(true);

  // clearing the memory
  m_vertices.resize(0);
  m_normals.resize(0);
  m_triangles.resize(0);
  edgeCases.resize(0);
  cubeCases.resize(0);
  gridEdges.resize(0);
  triCounter.resize(0);
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

unsigned char MeshGenerator::calcCubeCase(unsigned char const& ec0,
                                          unsigned char const& ec1,
                                          unsigned char const& ec2,
                                          unsigned char const& ec3) const
{
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

bool MeshGenerator::isCutEdge(int const& i, int const& j, int const& k) const
{
  // Assuming edgeCases are all set
  int edgeCaseIdx =
    k * ((m_dim.x() - 1) * m_dim.y()) + (j * (m_dim.x() - 1)) + i;
  unsigned char edgeCase = edgeCases[edgeCaseIdx];

  if (edgeCase == 1 || edgeCase == 2) {
    return true;
  }

  if (j != m_dim.y() - 1) {
    int edgeCaseIdxY =
      (k * (m_dim.x() - 1) * m_dim.y()) + ((j + 1) * (m_dim.x() - 1)) + i;
    unsigned char edgeCaseY = edgeCases[edgeCaseIdxY];

    // If the sum is odd, the edge along the y-axis is cut
    if ((edgeCase + edgeCaseY) % 2 == 1) {
      return true;
    }
  }

  if (k != m_dim.z() - 1) {
    int edgeCaseIdxZ =
      ((k + 1) * (m_dim.x() - 1) * m_dim.y()) + (j * (m_dim.x() - 1)) + i;
    unsigned char edgeCaseZ = edgeCases[edgeCaseIdxZ];

    // If the sum is odd, the edge along the z-axis is cut
    if ((edgeCase + edgeCaseZ) % 2 == 1) {
      return true;
    }
  }
  return false;
}

unsigned char MeshGenerator::calcCaseEdge(bool const& prevEdge,
                                          bool const& currEdge) const
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

unsigned long MeshGenerator::duplicate(const Vector3i&, const Vector3f&)
{
  // FIXME Not implemented yet.
  return 0;
}

void MeshGenerator::calcTrimValues(int& xl, int& xr, int const& j,
                                   int const& k) const
{

  const gridEdge& ge0 = gridEdges[k * m_dim.y() + j];
  const gridEdge& ge1 = gridEdges[k * m_dim.y() + j + 1];
  const gridEdge& ge2 = gridEdges[(k + 1) * m_dim.y() + j];
  const gridEdge& ge3 = gridEdges[(k + 1) * m_dim.y() + j + 1];

  xl = std::min({ ge0.xl, ge1.xl, ge2.xl, ge3.xl });
  xr = std::max({ ge0.xr, ge1.xr, ge2.xr, ge3.xr });

  if (xl > xr)
    xl = xr;
}

inline std::array<float, 3> MeshGenerator::interpolateOnCube(
  std::array<std::array<float, 3>, 8> const& pts,
  std::array<float, 8> const& isovals, unsigned char const& edge) const
{
  unsigned char i0 = m_edgeVertices[edge][0];
  unsigned char i1 = m_edgeVertices[edge][1];

  float weight = (m_iso - isovals[i0]) / (isovals[i1] - isovals[i0]);
  return interpolate(pts[i0], pts[i1], weight);
}

inline std::array<float, 3> MeshGenerator::interpolate(
  std::array<float, 3> const& a, std::array<float, 3> const& b,
  float const& weight) const
{
  std::array<float, 3> ret;
  ret[0] = a[0] + (weight * (b[0] - a[0]));
  ret[1] = a[1] + (weight * (b[1] - a[1]));
  ret[2] = a[2] + (weight * (b[2] - a[2]));
  return ret;
}

// flying edges tables using:

const unsigned char MeshGenerator::m_numTris[256] = {
  // clang-format off
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
  // clang-format on
};

const bool MeshGenerator::m_isCut[256][12] = {
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  { 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0 },
  { 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
  { 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0 },
  { 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
  { 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1 },
  { 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1 },
  { 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1 },
  { 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0 },
  { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0 },
  { 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0 },
  { 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0 },
  { 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1 },
  { 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1 },
  { 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1 },
  { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 },
  { 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0 },
  { 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0 },
  { 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0 },
  { 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0 },
  { 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1 },
  { 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1 },
  { 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1 },
  { 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1 },
  { 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0 },
  { 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0 },
  { 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0 },
  { 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0 },
  { 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1 },
  { 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1 },
  { 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1 },
  { 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1 },
  { 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0 },
  { 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0 },
  { 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 },
  { 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0 },
  { 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1 },
  { 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1 },
  { 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1 },
  { 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1 },
  { 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0 },
  { 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0 },
  { 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0 },
  { 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0 },
  { 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1 },
  { 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1 },
  { 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1 },
  { 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1 },
  { 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0 },
  { 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0 },
  { 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0 },
  { 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0 },
  { 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1 },
  { 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1 },
  { 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1 },
  { 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1 },
  { 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0 },
  { 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0 },
  { 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0 },
  { 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0 },
  { 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1 },
  { 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1 },
  { 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1 },
  { 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1 },
  { 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1 },
  { 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1 },
  { 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1 },
  { 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1 },
  { 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0 },
  { 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0 },
  { 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0 },
  { 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0 },
  { 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1 },
  { 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1 },
  { 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1 },
  { 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1 },
  { 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0 },
  { 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0 },
  { 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0 },
  { 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0 },
  { 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1 },
  { 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1 },
  { 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1 },
  { 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1 },
  { 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0 },
  { 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0 },
  { 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0 },
  { 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0 },
  { 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
  { 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1 },
  { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
  { 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1 },
  { 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
  { 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0 },
  { 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 },
  { 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0 },
  { 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1 },
  { 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1 },
  { 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1 },
  { 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1 },
  { 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0 },
  { 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0 },
  { 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 },
  { 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0 },
  { 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1 },
  { 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1 },
  { 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1 },
  { 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1 },
  { 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0 },
  { 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0 },
  { 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0 },
  { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0 },
  { 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1 },
  { 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1 },
  { 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1 },
  { 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1 },
  { 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0 },
  { 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0 },
  { 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0 },
  { 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0 },
  { 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1 },
  { 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1 },
  { 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1 },
  { 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1 },
  { 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0 },
  { 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0 },
  { 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0 },
  { 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0 },
  { 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0 },
  { 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0 },
  { 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0 },
  { 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0 },
  { 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1 },
  { 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1 },
  { 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1 },
  { 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1 },
  { 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0 },
  { 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0 },
  { 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0 },
  { 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0 },
  { 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1 },
  { 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1 },
  { 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1 },
  { 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1 },
  { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0 },
  { 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0 },
  { 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0 },
  { 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0 },
  { 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1 },
  { 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1 },
  { 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1 },
  { 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1 },
  { 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0 },
  { 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 },
  { 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0 },
  { 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0 },
  { 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1 },
  { 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1 },
  { 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1 },
  { 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1 },
  { 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0 },
  { 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 },
  { 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0 },
  { 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0 },
  { 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1 },
  { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
  { 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1 },
  { 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1 },
  { 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0 },
  { 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0 },
  { 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0 },
  { 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0 },
  { 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1 },
  { 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1 },
  { 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1 },
  { 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1 },
  { 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0 },
  { 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0 },
  { 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0 },
  { 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0 },
  { 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1 },
  { 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1 },
  { 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1 },
  { 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1 },
  { 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0 },
  { 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0 },
  { 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0 },
  { 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0 },
  { 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1 },
  { 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1 },
  { 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1 },
  { 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1 },
  { 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1 },
  { 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1 },
  { 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1 },
  { 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1 },
  { 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0 },
  { 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0 },
  { 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0 },
  { 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0 },
  { 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1 },
  { 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1 },
  { 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1 },
  { 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1 },
  { 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0 },
  { 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0 },
  { 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0 },
  { 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0 },
  { 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1 },
  { 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1 },
  { 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1 },
  { 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1 },
  { 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0 },
  { 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0 },
  { 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0 },
  { 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0 },
  { 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1 },
  { 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1 },
  { 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1 },
  { 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1 },
  { 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0 },
  { 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 },
  { 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0 },
  { 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0 },
  { 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1 },
  { 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1 },
  { 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1 },
  { 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1 },
  { 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0 },
  { 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0 },
  { 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0 },
  { 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0 },
  { 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1 },
  { 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1 },
  { 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1 },
  { 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1 },
  { 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0 },
  { 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0 },
  { 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0 },
  { 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0 },
  { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 },
  { 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1 },
  { 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1 },
  { 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1 },
  { 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0 },
  { 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0 },
  { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0 },
  { 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0 },
  { 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1 },
  { 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1 },
  { 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1 },
  { 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
  { 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0 },
  { 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
  { 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0 },
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

const signed char MeshGenerator::m_caseTriangles[256][16]{
  { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 9, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 3, 8, 9, 1, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, 1, 11, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 11, 2, 0, 9, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 3, 8, 2, 8, 11, 11, 8, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 2, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 2, 10, 8, 0, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 0, 9, 2, 10, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 2, 10, 1, 10, 9, 9, 10, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 1, 11, 10, 3, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 1, 11, 0, 11, 8, 8, 11, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 0, 9, 3, 9, 10, 10, 9, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 11, 8, 11, 10, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 8, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 0, 3, 7, 4, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 9, 1, 8, 7, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 9, 1, 4, 1, 7, 7, 1, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, 8, 7, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 7, 4, 3, 4, 0, 1, 11, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 11, 2, 9, 2, 0, 8, 7, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 9, 11, 2, 7, 9, 2, 3, 7, 7, 4, 9, -1, -1, -1, -1 },
  { 8, 7, 4, 3, 2, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 7, 4, 10, 4, 2, 2, 4, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 1, 0, 8, 7, 4, 2, 10, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 10, 7, 9, 10, 4, 9, 2, 10, 9, 1, 2, -1, -1, -1, -1 },
  { 3, 1, 11, 3, 11, 10, 7, 4, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 10, 1, 10, 4, 1, 4, 0, 7, 4, 10, -1, -1, -1, -1 },
  { 4, 8, 7, 9, 10, 0, 9, 11, 10, 10, 3, 0, -1, -1, -1, -1 },
  { 4, 10, 7, 4, 9, 10, 9, 11, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 4, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 4, 5, 0, 3, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 4, 5, 1, 0, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 4, 5, 8, 5, 3, 3, 5, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, 9, 4, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 8, 0, 1, 11, 2, 4, 5, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 11, 2, 5, 2, 4, 4, 2, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 5, 11, 3, 5, 2, 3, 4, 5, 3, 8, 4, -1, -1, -1, -1 },
  { 9, 4, 5, 2, 10, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 2, 10, 0, 10, 8, 4, 5, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 4, 5, 0, 5, 1, 2, 10, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 5, 1, 2, 8, 5, 2, 10, 8, 4, 5, 8, -1, -1, -1, -1 },
  { 11, 10, 3, 11, 3, 1, 9, 4, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 5, 9, 0, 1, 8, 8, 1, 11, 8, 11, 10, -1, -1, -1, -1 },
  { 5, 0, 4, 5, 10, 0, 5, 11, 10, 10, 3, 0, -1, -1, -1, -1 },
  { 5, 8, 4, 5, 11, 8, 11, 10, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 8, 7, 5, 9, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 0, 3, 9, 3, 5, 5, 3, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 8, 7, 0, 7, 1, 1, 7, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 3, 5, 3, 7, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 8, 7, 9, 7, 5, 11, 2, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 2, 1, 9, 0, 5, 5, 0, 3, 5, 3, 7, -1, -1, -1, -1 },
  { 8, 2, 0, 8, 5, 2, 8, 7, 5, 11, 2, 5, -1, -1, -1, -1 },
  { 2, 5, 11, 2, 3, 5, 3, 7, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 5, 9, 7, 9, 8, 3, 2, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 7, 5, 9, 2, 7, 9, 0, 2, 2, 10, 7, -1, -1, -1, -1 },
  { 2, 10, 3, 0, 8, 1, 1, 8, 7, 1, 7, 5, -1, -1, -1, -1 },
  { 10, 1, 2, 10, 7, 1, 7, 5, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 8, 5, 8, 7, 5, 11, 3, 1, 11, 10, 3, -1, -1, -1, -1 },
  { 5, 0, 7, 5, 9, 0, 7, 0, 10, 1, 11, 0, 10, 0, 11, -1 },
  { 10, 0, 11, 10, 3, 0, 11, 0, 5, 8, 7, 0, 5, 0, 7, -1 },
  { 10, 5, 11, 7, 5, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 5, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, 5, 6, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 1, 0, 5, 6, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 3, 8, 1, 8, 9, 5, 6, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 5, 6, 2, 1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 5, 6, 1, 6, 2, 3, 8, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 5, 6, 9, 6, 0, 0, 6, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 8, 9, 5, 2, 8, 5, 6, 2, 3, 8, 2, -1, -1, -1, -1 },
  { 2, 10, 3, 11, 5, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 8, 0, 10, 0, 2, 11, 5, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 9, 1, 2, 10, 3, 5, 6, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 6, 11, 1, 2, 9, 9, 2, 10, 9, 10, 8, -1, -1, -1, -1 },
  { 6, 10, 3, 6, 3, 5, 5, 3, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 10, 8, 0, 5, 10, 0, 1, 5, 5, 6, 10, -1, -1, -1, -1 },
  { 3, 6, 10, 0, 6, 3, 0, 5, 6, 0, 9, 5, -1, -1, -1, -1 },
  { 6, 9, 5, 6, 10, 9, 10, 8, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 6, 11, 4, 8, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 0, 3, 4, 3, 7, 6, 11, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 0, 9, 5, 6, 11, 8, 7, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 5, 6, 1, 7, 9, 1, 3, 7, 7, 4, 9, -1, -1, -1, -1 },
  { 6, 2, 1, 6, 1, 5, 4, 8, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 5, 2, 5, 6, 2, 3, 4, 0, 3, 7, 4, -1, -1, -1, -1 },
  { 8, 7, 4, 9, 5, 0, 0, 5, 6, 0, 6, 2, -1, -1, -1, -1 },
  { 7, 9, 3, 7, 4, 9, 3, 9, 2, 5, 6, 9, 2, 9, 6, -1 },
  { 3, 2, 10, 7, 4, 8, 11, 5, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 6, 11, 4, 2, 7, 4, 0, 2, 2, 10, 7, -1, -1, -1, -1 },
  { 0, 9, 1, 4, 8, 7, 2, 10, 3, 5, 6, 11, -1, -1, -1, -1 },
  { 9, 1, 2, 9, 2, 10, 9, 10, 4, 7, 4, 10, 5, 6, 11, -1 },
  { 8, 7, 4, 3, 5, 10, 3, 1, 5, 5, 6, 10, -1, -1, -1, -1 },
  { 5, 10, 1, 5, 6, 10, 1, 10, 0, 7, 4, 10, 0, 10, 4, -1 },
  { 0, 9, 5, 0, 5, 6, 0, 6, 3, 10, 3, 6, 8, 7, 4, -1 },
  { 6, 9, 5, 6, 10, 9, 4, 9, 7, 7, 9, 10, -1, -1, -1, -1 },
  { 11, 9, 4, 6, 11, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 6, 11, 4, 11, 9, 0, 3, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 1, 0, 11, 0, 6, 6, 0, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 1, 3, 8, 6, 1, 8, 4, 6, 6, 11, 1, -1, -1, -1, -1 },
  { 1, 9, 4, 1, 4, 2, 2, 4, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 8, 0, 1, 9, 2, 2, 9, 4, 2, 4, 6, -1, -1, -1, -1 },
  { 0, 4, 2, 4, 6, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 2, 3, 8, 4, 2, 4, 6, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 9, 4, 11, 4, 6, 10, 3, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 2, 8, 2, 10, 8, 4, 11, 9, 4, 6, 11, -1, -1, -1, -1 },
  { 3, 2, 10, 0, 6, 1, 0, 4, 6, 6, 11, 1, -1, -1, -1, -1 },
  { 6, 1, 4, 6, 11, 1, 4, 1, 8, 2, 10, 1, 8, 1, 10, -1 },
  { 9, 4, 6, 9, 6, 3, 9, 3, 1, 10, 3, 6, -1, -1, -1, -1 },
  { 8, 1, 10, 8, 0, 1, 10, 1, 6, 9, 4, 1, 6, 1, 4, -1 },
  { 3, 6, 10, 3, 0, 6, 0, 4, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 6, 8, 4, 10, 8, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 6, 11, 7, 11, 8, 8, 11, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 7, 0, 7, 11, 0, 11, 9, 6, 11, 7, -1, -1, -1, -1 },
  { 11, 7, 6, 1, 7, 11, 1, 8, 7, 1, 0, 8, -1, -1, -1, -1 },
  { 11, 7, 6, 11, 1, 7, 1, 3, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 6, 2, 1, 8, 6, 1, 9, 8, 8, 7, 6, -1, -1, -1, -1 },
  { 2, 9, 6, 2, 1, 9, 6, 9, 7, 0, 3, 9, 7, 9, 3, -1 },
  { 7, 0, 8, 7, 6, 0, 6, 2, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 2, 3, 6, 2, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 10, 3, 11, 8, 6, 11, 9, 8, 8, 7, 6, -1, -1, -1, -1 },
  { 2, 7, 0, 2, 10, 7, 0, 7, 9, 6, 11, 7, 9, 7, 11, -1 },
  { 1, 0, 8, 1, 8, 7, 1, 7, 11, 6, 11, 7, 2, 10, 3, -1 },
  { 10, 1, 2, 10, 7, 1, 11, 1, 6, 6, 1, 7, -1, -1, -1, -1 },
  { 8, 6, 9, 8, 7, 6, 9, 6, 1, 10, 3, 6, 1, 6, 3, -1 },
  { 0, 1, 9, 10, 7, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 0, 8, 7, 6, 0, 3, 0, 10, 10, 0, 6, -1, -1, -1, -1 },
  { 7, 6, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 10, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 8, 0, 10, 6, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 9, 1, 10, 6, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 9, 1, 8, 1, 3, 10, 6, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 2, 1, 6, 7, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, 3, 8, 0, 6, 7, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 0, 9, 2, 9, 11, 6, 7, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 6, 7, 10, 2, 3, 11, 11, 3, 8, 11, 8, 9, -1, -1, -1, -1 },
  { 7, 3, 2, 6, 7, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 7, 8, 0, 7, 0, 6, 6, 0, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 6, 7, 2, 7, 3, 0, 9, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 2, 6, 1, 6, 8, 1, 8, 9, 8, 6, 7, -1, -1, -1, -1 },
  { 11, 6, 7, 11, 7, 1, 1, 7, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 6, 7, 1, 11, 7, 1, 7, 8, 1, 8, 0, -1, -1, -1, -1 },
  { 0, 7, 3, 0, 11, 7, 0, 9, 11, 6, 7, 11, -1, -1, -1, -1 },
  { 7, 11, 6, 7, 8, 11, 8, 9, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 6, 4, 8, 10, 6, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 10, 6, 3, 6, 0, 0, 6, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 10, 6, 8, 6, 4, 9, 1, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 6, 4, 9, 3, 6, 9, 1, 3, 10, 6, 3, -1, -1, -1, -1 },
  { 6, 4, 8, 6, 8, 10, 2, 1, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, 3, 10, 0, 0, 10, 6, 0, 6, 4, -1, -1, -1, -1 },
  { 4, 8, 10, 4, 10, 6, 0, 9, 2, 2, 9, 11, -1, -1, -1, -1 },
  { 11, 3, 9, 11, 2, 3, 9, 3, 4, 10, 6, 3, 4, 3, 6, -1 },
  { 8, 3, 2, 8, 2, 4, 4, 2, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 2, 4, 4, 2, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 0, 9, 2, 4, 3, 2, 6, 4, 4, 8, 3, -1, -1, -1, -1 },
  { 1, 4, 9, 1, 2, 4, 2, 6, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 3, 1, 8, 1, 6, 8, 6, 4, 6, 1, 11, -1, -1, -1, -1 },
  { 11, 0, 1, 11, 6, 0, 6, 4, 0, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 3, 6, 4, 8, 3, 6, 3, 11, 0, 9, 3, 11, 3, 9, -1 },
  { 11, 4, 9, 6, 4, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 5, 9, 7, 10, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, 4, 5, 9, 10, 6, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 1, 0, 5, 0, 4, 7, 10, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 6, 7, 8, 4, 3, 3, 4, 5, 3, 5, 1, -1, -1, -1, -1 },
  { 9, 4, 5, 11, 2, 1, 7, 10, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 6, 7, 10, 1, 11, 2, 0, 3, 8, 4, 5, 9, -1, -1, -1, -1 },
  { 7, 10, 6, 5, 11, 4, 4, 11, 2, 4, 2, 0, -1, -1, -1, -1 },
  { 3, 8, 4, 3, 4, 5, 3, 5, 2, 11, 2, 5, 10, 6, 7, -1 },
  { 7, 3, 2, 7, 2, 6, 5, 9, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 4, 5, 0, 6, 8, 0, 2, 6, 6, 7, 8, -1, -1, -1, -1 },
  { 3, 2, 6, 3, 6, 7, 1, 0, 5, 5, 0, 4, -1, -1, -1, -1 },
  { 6, 8, 2, 6, 7, 8, 2, 8, 1, 4, 5, 8, 1, 8, 5, -1 },
  { 9, 4, 5, 11, 6, 1, 1, 6, 7, 1, 7, 3, -1, -1, -1, -1 },
  { 1, 11, 6, 1, 6, 7, 1, 7, 0, 8, 0, 7, 9, 4, 5, -1 },
  { 4, 11, 0, 4, 5, 11, 0, 11, 3, 6, 7, 11, 3, 11, 7, -1 },
  { 7, 11, 6, 7, 8, 11, 5, 11, 4, 4, 11, 8, -1, -1, -1, -1 },
  { 6, 5, 9, 6, 9, 10, 10, 9, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 10, 6, 0, 3, 6, 0, 6, 5, 0, 5, 9, -1, -1, -1, -1 },
  { 0, 8, 10, 0, 10, 5, 0, 5, 1, 5, 10, 6, -1, -1, -1, -1 },
  { 6, 3, 10, 6, 5, 3, 5, 1, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 11, 2, 9, 10, 5, 9, 8, 10, 10, 6, 5, -1, -1, -1, -1 },
  { 0, 3, 10, 0, 10, 6, 0, 6, 9, 5, 9, 6, 1, 11, 2, -1 },
  { 10, 5, 8, 10, 6, 5, 8, 5, 0, 11, 2, 5, 0, 5, 2, -1 },
  { 6, 3, 10, 6, 5, 3, 2, 3, 11, 11, 3, 5, -1, -1, -1, -1 },
  { 5, 9, 8, 5, 8, 2, 5, 2, 6, 3, 2, 8, -1, -1, -1, -1 },
  { 9, 6, 5, 9, 0, 6, 0, 2, 6, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 8, 5, 1, 0, 8, 5, 8, 6, 3, 2, 8, 6, 8, 2, -1 },
  { 1, 6, 5, 2, 6, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 6, 3, 1, 11, 6, 3, 6, 8, 5, 9, 6, 8, 6, 9, -1 },
  { 11, 0, 1, 11, 6, 0, 9, 0, 5, 5, 0, 6, -1, -1, -1, -1 },
  { 0, 8, 3, 5, 11, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 6, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 11, 5, 7, 10, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 11, 5, 10, 5, 7, 8, 0, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 7, 10, 5, 10, 11, 1, 0, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 11, 5, 7, 11, 7, 10, 9, 1, 8, 8, 1, 3, -1, -1, -1, -1 },
  { 10, 2, 1, 10, 1, 7, 7, 1, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, 1, 7, 2, 1, 5, 7, 7, 10, 2, -1, -1, -1, -1 },
  { 9, 5, 7, 9, 7, 2, 9, 2, 0, 2, 7, 10, -1, -1, -1, -1 },
  { 7, 2, 5, 7, 10, 2, 5, 2, 9, 3, 8, 2, 9, 2, 8, -1 },
  { 2, 11, 5, 2, 5, 3, 3, 5, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 0, 2, 8, 2, 5, 8, 5, 7, 11, 5, 2, -1, -1, -1, -1 },
  { 9, 1, 0, 5, 3, 11, 5, 7, 3, 3, 2, 11, -1, -1, -1, -1 },
  { 9, 2, 8, 9, 1, 2, 8, 2, 7, 11, 5, 2, 7, 2, 5, -1 },
  { 1, 5, 3, 3, 5, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 7, 8, 0, 1, 7, 1, 5, 7, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 3, 0, 9, 5, 3, 5, 7, 3, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 7, 8, 5, 7, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 4, 8, 5, 8, 11, 11, 8, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 5, 4, 0, 5, 0, 10, 5, 10, 11, 10, 0, 3, -1, -1, -1, -1 },
  { 0, 9, 1, 8, 11, 4, 8, 10, 11, 11, 5, 4, -1, -1, -1, -1 },
  { 11, 4, 10, 11, 5, 4, 10, 4, 3, 9, 1, 4, 3, 4, 1, -1 },
  { 2, 1, 5, 2, 5, 8, 2, 8, 10, 4, 8, 5, -1, -1, -1, -1 },
  { 0, 10, 4, 0, 3, 10, 4, 10, 5, 2, 1, 10, 5, 10, 1, -1 },
  { 0, 5, 2, 0, 9, 5, 2, 5, 10, 4, 8, 5, 10, 5, 8, -1 },
  { 9, 5, 4, 2, 3, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 11, 5, 3, 2, 5, 3, 5, 4, 3, 4, 8, -1, -1, -1, -1 },
  { 5, 2, 11, 5, 4, 2, 4, 0, 2, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 2, 11, 3, 11, 5, 3, 5, 8, 4, 8, 5, 0, 9, 1, -1 },
  { 5, 2, 11, 5, 4, 2, 1, 2, 9, 9, 2, 4, -1, -1, -1, -1 },
  { 8, 5, 4, 8, 3, 5, 3, 1, 5, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 5, 4, 1, 5, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 8, 5, 4, 8, 3, 5, 9, 5, 0, 0, 5, 3, -1, -1, -1, -1 },
  { 9, 5, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 7, 10, 4, 10, 9, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 3, 8, 4, 7, 9, 9, 7, 10, 9, 10, 11, -1, -1, -1, -1 },
  { 1, 10, 11, 1, 4, 10, 1, 0, 4, 7, 10, 4, -1, -1, -1, -1 },
  { 3, 4, 1, 3, 8, 4, 1, 4, 11, 7, 10, 4, 11, 4, 10, -1 },
  { 4, 7, 10, 9, 4, 10, 9, 10, 2, 9, 2, 1, -1, -1, -1, -1 },
  { 9, 4, 7, 9, 7, 10, 9, 10, 1, 2, 1, 10, 0, 3, 8, -1 },
  { 10, 4, 7, 10, 2, 4, 2, 0, 4, -1, -1, -1, -1, -1, -1, -1 },
  { 10, 4, 7, 10, 2, 4, 8, 4, 3, 3, 4, 2, -1, -1, -1, -1 },
  { 2, 11, 9, 2, 9, 7, 2, 7, 3, 7, 9, 4, -1, -1, -1, -1 },
  { 9, 7, 11, 9, 4, 7, 11, 7, 2, 8, 0, 7, 2, 7, 0, -1 },
  { 3, 11, 7, 3, 2, 11, 7, 11, 4, 1, 0, 11, 4, 11, 0, -1 },
  { 1, 2, 11, 8, 4, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 1, 9, 4, 7, 1, 7, 3, 1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 1, 9, 4, 7, 1, 0, 1, 8, 8, 1, 7, -1, -1, -1, -1 },
  { 4, 3, 0, 7, 3, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 4, 7, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 8, 11, 11, 8, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 9, 0, 3, 10, 9, 10, 11, 9, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 11, 1, 0, 8, 11, 8, 10, 11, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 11, 1, 10, 11, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 10, 2, 1, 9, 10, 9, 8, 10, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 9, 0, 3, 10, 9, 1, 9, 2, 2, 9, 10, -1, -1, -1, -1 },
  { 0, 10, 2, 8, 10, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 3, 10, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 8, 3, 2, 11, 8, 11, 9, 8, -1, -1, -1, -1, -1, -1, -1 },
  { 9, 2, 11, 0, 2, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 2, 8, 3, 2, 11, 8, 0, 8, 1, 1, 8, 11, -1, -1, -1, -1 },
  { 1, 2, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 1, 8, 3, 9, 8, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 1, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { 0, 8, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 }
};

const unsigned char MeshGenerator::m_edgeVertices[12][2] = {
  { 0, 1 }, { 1, 2 }, { 3, 2 }, { 0, 3 }, { 4, 5 }, { 5, 6 },
  { 7, 6 }, { 4, 7 }, { 0, 4 }, { 1, 5 }, { 3, 7 }, { 2, 6 }
};

} // namespace Avogadro::QtGui
