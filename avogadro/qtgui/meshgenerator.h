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
}

namespace QtGui {

/**
 * @class MeshGenerator meshgenerator.h <avogadro/qtgui/meshgenerator.h>
 * @brief Class that can generate Mesh objects from Cube objects.
 * @author Marcus D. Hanwell
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
   * @return True if the MeshGenerator was successfully initialized.
   */
  MeshGenerator(const Core::Cube* cube, Core::Mesh* mesh, float iso,
                int passes = 6, bool reverse = false, QObject* parent = nullptr);

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

    struct gridEdge
    {
        gridEdge()
          : xl(0),
            xr(0),
            xstart(0),
            ystart(0),
            zstart(0)
        {}

        // trim values
        // set on pass 1
        size_t xl;
        size_t xr;

        // modified on pass 2
        // set on pass 3
        size_t xstart;
        size_t ystart;
        size_t zstart;
    };



  void FlyingEdgesAlgorithmPass1();
  void FlyingEdgesAlgorithmPass2();
  void FlyingEdgesAlgorithmPass3();
  void FlyingEdgesAlgorithmPass4();

  /**
   * @return The Cube being used by the class.
   */
  const Core::Cube* cube() const { return m_cube; }

  inline void calcTrimValues(
  size_t& xl, size_t& xr, size_t const& j, size_t const& k) const;


  inline unsigned char
  calcCubeCase(unsigned char const& ec0, unsigned char const& ec1,
               unsigned char const& ec2, unsigned char const& ec3) const;

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
   * Get the normal to the supplied point. This operation is quite expensive
   * and so should be avoided wherever possible.
   * @param pos The position of the vertex whose normal is needed.
   * @return The normal vector for the supplied point.
   */
  Vector3f normal(const Vector3f& pos);

  /**
   * Get the offset, i.e. the approximate point of intersection of the surface
   * between two points.
   * @param val1 The position of the vertex whose normal is needed.
   * @return The normal vector for the supplied point.
   */
  float offset(float val1, float val2);

  unsigned long duplicate(const Vector3i& c, const Vector3f& pos);

  /**
   * Perform a marching cubes step on a single cube.
   */
  bool marchingCube(const Vector3i& pos);

  bool isCutEdge(size_t const& i, size_t const& j, size_t const& k) const;

  inline std::array<float, 3> interpolateOnCube(
    std::array<std::array<float, 3>, 8> const& pts,
    std::array<float, 8> const& isovals,
    unsigned char const& edge) const;
  
  inline std::array<float, 3> interpolate(
    std::array<float, 3> const& a,
    std::array<float, 3> const& b,
    float const& weight) const;

  inline unsigned char calcCaseEdge(bool const& prevEdge, bool const& currEdge) const;   

  float m_iso;              /** The value of the isosurface. */
  int m_passes;             /** Number of smoothing passes to perform. */
  bool m_reverseWinding;    /** Whether the winding and normals are reversed. */
  const Core::Cube* m_cube; /** The cube that we are generating a Mesh from. */
  Core::Mesh* m_mesh;       /** The mesh that is being generated. */
  Vector3f m_stepSize;      /** The step size vector for cube. */
  Vector3f m_min;           /** The minimum point in the cube. */
  Vector3i m_dim;           /** The dimensions of the cube. */

  std::array<std::array<float, 3>, 8> cube_t;
  std::array<float, 8> scalarCube_t;

  Core::Array<Vector3f> m_vertices, m_normals;
  Core::Array<unsigned int> m_indices;
  std::vector<gridEdge> gridEdges;
  std::vector<unsigned char> cubeCases;    // size (nx-1)*(ny-1)*(nz-1)

  std::vector<size_t> triCounter;  // size of (ny-1)*(nz-1)
  std::vector<unsigned char> edgeCases; 
  Core::Array<Vector3f> points;  //
  Core::Array<Vector3f> normals; // The output
  Core::Array<Vector3f> tris;     
  int m_progmin;
  int m_progmax;

  /**
   * These are the tables of constants for the marching cubes and tetrahedra
   * algorithms. They are taken from the public domain source at
   * http://local.wasp.uwa.edu.au/~pbourke/geometry/polygonise/
   */
  static const unsigned char numTris[256]; 
  static const bool isCut[256][12];  
  static const char caseTriangles[256][16];
  static const unsigned char edgeVertices[12][2];     
};

} // End namespace QtGui
} // End namespace Avogadro

#endif // AVOGADRO_QTGUI_MESHGENERATOR_H
