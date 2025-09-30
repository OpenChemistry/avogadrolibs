/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_MESHGENERATOR_H
#define AVOGADRO_QTGUI_MESHGENERATOR_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <QtCore/QThread>

namespace Avogadro {

namespace Core {
class Cube;
class Mesh;
} // namespace Core

namespace QtGui {

/**
 * @class MeshGenerator meshgenerator.h <avogadro/qtgui/meshgenerator.h>
 * @brief Class that can generate Mesh objects from Cube objects.
 * @author Marcus D. Hanwell
 * @author Perminder Singh
 *
 * This class implements a method of generating an isosurface Mesh from
 * volumetric data using the marching cubes algorithm. In the case of the
 * MeshGenerator class it expects a Cube as an input and an isosurface value.
 * The tables and the basic code is taken from the public domain code written
 * by Cory Bloyd (marchingsource.cpp) and available at,
 * http://local.wasp.uwa.edu.au/~pbourke/geometry/polygonise/
 *
 * You must first initialize the class and then call run() to actually
 * polygonize the isosurface. Connect to the classes finished() signal to
 * do something once the polygonization is complete.
 */

class AVOGADROQTGUI_EXPORT MeshGenerator : public QThread
{
  Q_OBJECT
public:
  /**
   * Constructor.
   */
  explicit MeshGenerator(QObject* parent = nullptr);

  /**
   * Constructor. Can be used to initialize the MeshGenerator.
   * @param cube The source Cube with the volumetric data.
   * @param mesh The Mesh that will hold the isosurface.
   * @param iso The iso value of the surface.
   * @param passes Number of smoothing passes to perform.
   */
  MeshGenerator(const Core::Cube* cube, Core::Mesh* mesh, float iso,
                int passes = 6, bool reverse = false,
                QObject* parent = nullptr);

  /**
   * Destructor.
   */
  ~MeshGenerator() override;

  /**
   * Initialization function, set up the MeshGenerator ready to find an
   * isosurface of the supplied Cube.
   * @param cube The source Cube with the volumetric data.
   * @param mesh The Mesh that will hold the isosurface.
   * @param iso The iso value of the surface.
   * @param passes Number of smoothing passes to perform.
   */
  bool initialize(const Core::Cube* cube, Core::Mesh* mesh, float iso,
                  int passes = 6, bool reverse = false);

  /**
   * Use this function to begin Mesh generation. Uses an asynchronous thread,
   * and so avoids locking the user interface while the isosurface is found.
   */
  void run() override;

  /**
   * It holds the range and starting offsets of isosurface-intersected
   * edges along the x, y, and z axes for each grid cell.
   */
  struct gridEdge
  {
    gridEdge() : xl(0), xr(0), xstart(0), ystart(0), zstart(0) {}

    // trim values
    // set on pass 1
    int xl;
    int xr;

    // modified on pass 2
    // set on pass 3
    int xstart;
    int ystart;
    int zstart;
  };

  /**
   * Handles duplicate vertices (Not implemented). Placeholder for future
   * functionality.
   */
  unsigned long duplicate(const Vector3i& c, const Vector3f& pos);

  /**
   * @name Flying Edges
   * Methods to implement the "flying edges" method for isosurface mesh
   * generation. Flying edges: A high-performance scalable isocontouring
   * algorithm Schroeder; Maynard; Geveci; 2015 IEEE 5th Symposium on Large Data
   * Analysis and Visualization (LDAV)
   * [10.1109/LDAV.2015.7348069](https://doi.org/10.1109/LDAV.2015.7348069)
   * Alternate (non-VTK) implementation at
   * https://github.com/sandialabs/miniIsosurface/blob/master/flyingEdges/
   * @{
   */

  /**
   * Pass 1 for flying edges. Pass1 detects and records
   * where the isosurface intersects each row of grid edges
   * along the x-axis.
   */
  void FlyingEdgesAlgorithmPass1();

  /**
   * Pass2 assigns case identifiers to each grid cell based on
   * intersected edges and tallies the number of triangles needed
   * for mesh construction.
   */
  void FlyingEdgesAlgorithmPass2();

  /**
   * Pass3 computes cumulative offsets for triangles
   * and vertices and allocates memory for the mesh structures.
   */
  void FlyingEdgesAlgorithmPass3();

  /**
   * Calculates normals, triangles and vertices.
   */
  void FlyingEdgesAlgorithmPass4();

  /**@}*/

  /**
   * @return The Cube being used by the class.
   */
  const Core::Cube* cube() const { return m_cube; }

  /**
   * Determines the x-range (xl to xr) where isosurface intersections
   * occur, optimizing calculations within this range.
   */
  inline void calcTrimValues(int& xl, int& xr, int const& j,
                             int const& k) const;

  /**
   * Indicates which edges intersects the isosurface.
   */
  inline unsigned char calcCubeCase(unsigned char const& ec0,
                                    unsigned char const& ec1,
                                    unsigned char const& ec2,
                                    unsigned char const& ec3) const;

  /**
   * @return The Mesh being generated by the class.
   */
  Core::Mesh* mesh() const { return m_mesh; }

  /**
   * Clears the contents of the MeshGenerator.
   */
  void clear();

  /**
   * @return The minimum value of the progress value.
   */
  int progressMinimum() { return m_progmin; }

  /**
   * @return The maximum value of the progress value.
   */
  int progressMaximum() { return m_progmax; }

signals:

  /**
   * The current value of the calculation's progress.
   */
  void progressValueChanged(int);

protected:
  /**
   * isCutEdge checks whether the grid edge at position (i, j, k) is
   * intersected by the isosurface based on edge case conditions.
   * @return Boolean if it's intersected or not.
   */
  bool isCutEdge(int const& i, int const& j, int const& k) const;

  /**
   * It computes the 3D intersection point on a cube edge via interpolation.
   */
  inline std::array<float, 3> interpolateOnCube(
    std::array<std::array<float, 3>, 8> const& pts,
    std::array<float, 8> const& isovals, unsigned char const& edge) const;

  /**
   * It linearly interpolates between two 3D points, a and b, using
   * the given weight to determine the intermediate position.
   */
  inline std::array<float, 3> interpolate(std::array<float, 3> const& a,
                                          std::array<float, 3> const& b,
                                          float const& weight) const;

  /**
   * calcCaseEdge determines an edge case code (0–3) based on two boolean edge
   * comparisons.
   */
  inline unsigned char calcCaseEdge(bool const& prevEdge,
                                    bool const& currEdge) const;

  float m_iso;              /** The value of the isosurface. */
  int m_passes;             /** Number of smoothing passes to perform. */
  bool m_reverseWinding;    /** Whether the winding and normals are reversed. */
  const Core::Cube* m_cube; /** The cube that we are generating a Mesh from. */
  Core::Mesh* m_mesh;       /** The mesh that is being generated. */
  Vector3f m_stepSize;      /** The step size vector for cube. */
  Vector3f m_min;           /** The minimum point in the cube. */
  Vector3i m_dim;           /** The dimensions of the cube. */

  Core::Array<Vector3f> m_normals, m_vertices;
  std::vector<gridEdge> gridEdges; // size (m_dim.y() * m_dim.z())
  std::vector<unsigned char>
    cubeCases; // size ((m_dim.x() - 1) * (m_dim.y() - 1) * (m_dim.z() - 1))
  std::vector<int> triCounter; // size ((m_dim.y() - 1) * (m_dim.z() - 1))
  std::vector<unsigned char>
    edgeCases; // size ((m_dim.x() - 1) * (m_dim.y()) * (m_dim.z()))
  Core::Array<Vector3f> m_triangles; // triangles of a mesh
  int m_progmin;
  int m_progmax;

  /**
   * These are the lookup tables for flying edges.
   * Reference :
   * https://github.com/sandialabs/miniIsosurface/blob/master/flyingEdges/util/MarchingCubesTables.h
   */
  static const unsigned char m_numTris[256];
  static const bool m_isCut[256][12];
  static const signed char m_caseTriangles[256][16];
  static const unsigned char m_edgeVertices[12][2];
};

} // End namespace QtGui
} // End namespace Avogadro

#endif // AVOGADRO_QTGUI_MESHGENERATOR_H
