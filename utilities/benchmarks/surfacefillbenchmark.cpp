/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Benchmark for the grid fill behind the van der Waals and solvent-accessible
// surfaces (edtfill.cpp), and for the mesh extraction and smoothing that
// follow.
//
// For each molecule x resolution x surface type it reports the median of
// several runs of
//   - fillBinarySpheres():   the +1/-1 field the surfaces used to use
//   - fillDistanceSpheres(): the signed distance field they use now
//   - MeshGenerator (Flying Edges) with 0 smoothing passes on each field,
//     with the number of triangles produced
//   - Mesh::smooth(1) on a fresh copy of the binary mesh (1 pass is the old
//     GUI default, "Light"); the copy is not timed.
// The totals compare fill + extraction + 1 smoothing pass on the binary
// field with fill + extraction on the distance field (no smoothing).
// The grid is built the way Surfaces::calculateEDT() builds it.
//
// A second table compares the solvent-excluded surface: the old erosion of the
// binary solvent-accessible grid (fillBinarySpheres() plus a port of the
// former Surfaces::performEDTStep()) with fillSolventExcluded(), the exact
// distance transform, each with the Flying Edges triangle count at iso 0.

#include <avogadro/core/cube.h>
#include <avogadro/core/array.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/meshgenerator.h>

#include "benchmark_common.h"
#include "edtfill.h"
#include "surfaceresolution.h"

#include <QtConcurrent/QtConcurrent>
#include <QtCore/QCoreApplication>
#include <QtCore/QThreadPool>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Benchmarks::parseDouble;
using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Benchmarks::readMoleculeFromPath;
using Avogadro::Benchmarks::resolvePath;
using Avogadro::Core::Cube;
using Avogadro::Core::Mesh;
using Avogadro::Core::Molecule;
using Avogadro::QtGui::MeshGenerator;
using Avogadro::QtPlugins::EdtSphere;
using Clock = std::chrono::steady_clock;

constexpr double SolventProbeRadius = 1.4; // as in surfaces.cpp

struct MoleculeSpec
{
  const char* label;
  const char* file; // relative to the data root
};

const MoleculeSpec Molecules[] = {
  { "caffeine", "data/cjson/caffeine.cjson" },
  { "tyr-33", "data/pdb/tyr-33-conf1.pdb" },
  { "crambin", "data/pdb/1CRN.pdb" },
  { "4HHB", "data/pdb/4HHB.pdb" },
};

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t repeats = 5;
  double maxVoxels = 300.0e6;
  double sesOldMaxVoxels = 100.0e6;
  std::vector<double> resolutions = { 0.1, 0.2, 0.3, 0.5, 0.0 }; // 0 = auto
  std::vector<std::string> molecules;                            // empty = all
  std::string csvPath;
};

void usage(const char* program)
{
  std::cout
    << "Usage: " << program << " [options]\n\n"
    << "Times the VdW/SAS grid fill (binary vs signed distance) and the\n"
    << "Flying Edges extraction and mesh smoothing on the resulting\n"
    << "fields.\n\n"
    << "Options:\n"
    << "  --data-root DIR     Directory holding data/ (default: avogadrodata)\n"
    << "  --repeats N         Timed runs per measurement, after one warm-up\n"
    << "                      (default 5)\n"
    << "  --max-voxels M      Skip grids larger than M voxels (default 3e8)\n"
    << "  --resolution R      Only this spacing in Angstrom (repeatable;\n"
    << "                      0 = the plugin's automatic choice)\n"
    << "  --molecule NAME     Only this molecule (repeatable): caffeine,\n"
    << "                      tyr-33, crambin, 4HHB\n"
    << "  --ses-old-max-voxels M  Skip the old solvent-excluded erosion on\n"
    << "                      grids larger than M voxels (default 1e8)\n"
    << "  --csv PATH          Also write the results as CSV\n"
    << "  --help              Show this message\n";
}

bool parseArguments(int argc, char** argv, Options& options)
{
  bool resolutionsGiven = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto value = [&]() -> const char* {
      return (i + 1 < argc) ? argv[++i] : nullptr;
    };
    if (arg == "--help" || arg == "-h") {
      usage(argv[0]);
      std::exit(0);
    } else if (arg == "--data-root") {
      const char* v = value();
      if (v == nullptr)
        return false;
      options.dataRoot = v;
    } else if (arg == "--repeats") {
      const char* v = value();
      std::size_t n = 0;
      if (v == nullptr || !parseUnsigned(v, n) || n < 1 || n > 1000)
        return false;
      options.repeats = n;
    } else if (arg == "--max-voxels") {
      const char* v = value();
      double d = 0.0;
      if (v == nullptr || !parseDouble(v, d) || d < 1.0)
        return false;
      options.maxVoxels = d;
    } else if (arg == "--ses-old-max-voxels") {
      const char* v = value();
      double d = 0.0;
      if (v == nullptr || !parseDouble(v, d) || d < 1.0)
        return false;
      options.sesOldMaxVoxels = d;
    } else if (arg == "--resolution") {
      const char* v = value();
      double d = 0.0;
      if (v == nullptr || !parseDouble(v, d) || d < 0.0)
        return false;
      if (!resolutionsGiven)
        options.resolutions.clear();
      resolutionsGiven = true;
      options.resolutions.push_back(d);
    } else if (arg == "--molecule") {
      const char* v = value();
      if (v == nullptr)
        return false;
      options.molecules.push_back(v);
    } else if (arg == "--csv") {
      const char* v = value();
      if (v == nullptr)
        return false;
      options.csvPath = v;
    } else {
      return false;
    }
  }
  return true;
}

// Milliseconds since @p start.
double elapsedMs(Clock::time_point start)
{
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
    .count();
}

// The voxels of @p cube above zero: the inside of a surface.
std::vector<char> insideSet(const Cube& cube)
{
  std::vector<char> set(cube.data()->size());
  for (std::size_t i = 0; i < set.size(); ++i)
    set[i] = (*cube.data())[i] > 0.0f ? 1 : 0;
  return set;
}

// True if some voxel in the 3x3x3 block around (x, y, z) is on the other side
// of the surface than (x, y, z) itself.
bool onBoundary(const std::vector<char>& set, const Vector3i& dims, int x,
                int y, int z)
{
  const std::size_t here =
    (static_cast<std::size_t>(x) * dims(1) + y) * dims(2) + z;
  for (int dx = -1; dx <= 1; ++dx) {
    for (int dy = -1; dy <= 1; ++dy) {
      for (int dz = -1; dz <= 1; ++dz) {
        const int nx = x + dx, ny = y + dy, nz = z + dz;
        if (nx < 0 || ny < 0 || nz < 0 || nx >= dims(0) || ny >= dims(1) ||
            nz >= dims(2))
          continue;
        const std::size_t there =
          (static_cast<std::size_t>(nx) * dims(1) + ny) * dims(2) + nz;
        if (set[there] != set[here])
          return true;
      }
    }
  }
  return false;
}

// How the inside of the new surface differs from the old one. The new field
// measures to the SAS surface rather than to voxel centers, so the sets differ
// by sub-voxel shifts: a differing voxel must lie within one voxel of the
// boundary of one of them (stray counts voxels that do not).
struct SetComparison
{
  std::size_t oldInside = 0, newInside = 0, differing = 0, stray = 0;
};

SetComparison compareInsideSets(const std::vector<char>& oldSet,
                                const std::vector<char>& newSet,
                                const Vector3i& dims)
{
  SetComparison result;
  for (int x = 0; x < dims(0); ++x) {
    for (int y = 0; y < dims(1); ++y) {
      for (int z = 0; z < dims(2); ++z) {
        const std::size_t i =
          (static_cast<std::size_t>(x) * dims(1) + y) * dims(2) + z;
        result.oldInside += oldSet[i];
        result.newInside += newSet[i];
        if (oldSet[i] == newSet[i])
          continue;
        ++result.differing;
        if (!onBoundary(oldSet, dims, x, y, z) &&
            !onBoundary(newSet, dims, x, y, z))
          ++result.stray;
      }
    }
  }
  return result;
}

double median(std::vector<double> values)
{
  if (values.empty())
    return 0.0;
  std::sort(values.begin(), values.end());
  const std::size_t n = values.size();
  return (n % 2 == 1) ? values[n / 2]
                      : 0.5 * (values[n / 2 - 1] + values[n / 2]);
}

// Median milliseconds of @p repeats runs of @p work, after one warm-up.
template <typename Work>
double timeMedian(std::size_t repeats, Work&& work)
{
  work();
  std::vector<double> times;
  for (std::size_t i = 0; i < repeats; ++i) {
    const auto start = Clock::now();
    work();
    times.push_back(elapsedMs(start));
  }
  return median(times);
}

struct MeshTiming
{
  double ms = 0.0;
  std::size_t triangles = 0;
};

// Flying Edges extraction only (no smoothing passes). The last extracted mesh
// is returned through @p out (extracted untimed) for the smoothing timing.
MeshTiming timeExtract(const Cube& cube, std::size_t repeats, Mesh& out)
{
  MeshTiming result;
  MeshGenerator generator;
  result.ms = timeMedian(repeats, [&]() {
    Mesh mesh;
    generator.initialize(&cube, &mesh, 0.0f, 0);
    generator.start();
    generator.wait();
    result.triangles = mesh.triangles().size();
  });
  // One untimed extraction to hand back the mesh.
  generator.initialize(&cube, &out, 0.0f, 0);
  generator.start();
  generator.wait();
  return result;
}

// Median milliseconds of Mesh::smooth(@p passes), applied to a fresh copy of
// @p base each run; the copy is excluded from the timing.
double timeSmooth(const Mesh& base, int passes, std::size_t repeats)
{
  {
    Mesh warm(base);
    warm.smooth(passes);
  }
  std::vector<double> times;
  for (std::size_t i = 0; i < repeats; ++i) {
    Mesh mesh(base);
    const auto start = Clock::now();
    mesh.smooth(passes);
    times.push_back(elapsedMs(start));
  }
  return median(times);
}

// The erosion that turned the binary solvent-accessible grid into the
// solvent-excluded one (the former Surfaces::performEDTStep()): every inside
// voxel within the probe radius of an outside voxel that touches an inside
// voxel is set to -1.
void erodeSolventAccessible(Cube& cube, double probe)
{
  const Vector3 spacing = cube.spacing();
  const float probeRadius = static_cast<float>(probe);
  Avogadro::Core::Array<Vector3> relativePositions;
  std::vector<Vector3i> insideIndices;
  const Vector3i size = cube.dimensions();
  relativePositions.reserve(static_cast<std::size_t>(size(0)) * size(1) * 4);
  insideIndices.reserve(static_cast<std::size_t>(size(0)) * size(1) * size(2));
  for (int z = 0; z < size(2); z++) {
    int zp = std::max(z - 1, 0);
    int zn = std::min(z + 1, size(2) - 1);
    for (int y = 0; y < size(1); y++) {
      int yp = std::max(y - 1, 0);
      int yn = std::min(y + 1, size(1) - 1);
      for (int x = 0; x < size(0); x++) {
        if (cube.value(x, y, z) > 0.0) {
          insideIndices.emplace_back(x, y, z);
          continue;
        }
        int xp = std::max(x - 1, 0);
        int xn = std::min(x + 1, size(0) - 1);
        if (cube.value(xp, y, z) > 0.0 || cube.value(xn, y, z) > 0.0 ||
            cube.value(x, yp, z) > 0.0 || cube.value(x, yn, z) > 0.0 ||
            cube.value(x, y, zp) > 0.0 || cube.value(x, y, zn) > 0.0) {
          relativePositions.push_back(Vector3(x, y, z).cwiseProduct(spacing));
        }
      }
    }
  }
  Avogadro::Core::NeighborPerceiver perceiver(relativePositions, probeRadius);
  QFuture<void> future = QtConcurrent::map(insideIndices, [&](Vector3i& in) {
    thread_local Avogadro::Core::Array<Avogadro::Index> neighbors;
    const Vector3 pos = in.cast<double>().cwiseProduct(spacing);
    perceiver.getNeighborsInclusiveInPlace(neighbors, pos);
    for (Avogadro::Index neighbor : neighbors) {
      const Vector3& npos = relativePositions[neighbor];
      if ((npos - pos).norm() <= probeRadius) {
        cube.setValue(in(0), in(1), in(2), -1.0f);
        break;
      }
    }
  });
  future.waitForFinished();
}

struct SesRow
{
  std::string molecule;
  std::size_t atoms = 0;
  std::string requested;
  double spacing = 0.0;
  std::size_t voxels = 0;
  bool haveOld = false;
  double oldFill = 0.0;  // fillBinarySpheres()
  double oldErode = 0.0; // erodeSolventAccessible()
  double newFill = 0.0;  // fillSolventExcluded()
  std::size_t oldTriangles = 0, newTriangles = 0;
  SetComparison sets; // the old and new inside sets, when haveOld
};

void printSesHeader(std::ostream& out)
{
  out << std::left << std::setw(9) << "molecule" << std::right << std::setw(6)
      << "atoms" << std::setw(7) << "res" << std::setw(8) << "spacing"
      << std::setw(11) << "voxels" << std::setw(10) << "bin-fill"
      << std::setw(10) << "erode" << std::setw(10) << "old-ses" << std::setw(10)
      << "new-ses" << std::setw(8) << "speedup" << std::setw(11) << "tri-old"
      << std::setw(11) << "tri-new" << std::setw(11) << "in-old"
      << std::setw(11) << "in-new" << std::setw(9) << "differ" << std::setw(7)
      << "stray"
      << "\n";
}

void printSesRow(std::ostream& out, const SesRow& r)
{
  const double oldTotal = r.oldFill + r.oldErode;
  out << std::left << std::setw(9) << r.molecule << std::right << std::setw(6)
      << r.atoms << std::setw(7) << r.requested << std::fixed
      << std::setprecision(3) << std::setw(8) << r.spacing << std::setw(11)
      << r.voxels << std::setprecision(1);
  if (r.haveOld) {
    out << std::setw(10) << r.oldFill << std::setw(10) << r.oldErode
        << std::setw(10) << oldTotal << std::setw(10) << r.newFill
        << std::setprecision(1) << std::setw(7)
        << (r.newFill > 0.0 ? oldTotal / r.newFill : 0.0) << "x"
        << std::setw(11) << r.oldTriangles;
  } else {
    out << std::setw(10) << "-" << std::setw(10) << "-" << std::setw(10) << "-"
        << std::setw(10) << r.newFill << std::setw(8) << "-" << std::setw(11)
        << "-";
  }
  out << std::setw(11) << r.newTriangles;
  if (r.haveOld) {
    out << std::setw(11) << r.sets.oldInside << std::setw(11)
        << r.sets.newInside << std::setw(9) << r.sets.differing << std::setw(7)
        << r.sets.stray;
  }
  out << "\n";
}

struct Row
{
  std::string molecule;
  std::size_t atoms = 0;
  std::string type;
  std::string requested; // "auto" or the number
  double resolution = 0.0;
  double spacing = 0.0;
  std::size_t voxels = 0;
  double binaryFill = 0.0, distanceFill = 0.0;
  MeshTiming binaryExtract, distanceExtract;
  double binarySmooth1 = 0.0; // Mesh::smooth(1) on the binary mesh

  double totalBinary() const
  {
    return binaryFill + binaryExtract.ms + binarySmooth1;
  }
  double totalDistance() const { return distanceFill + distanceExtract.ms; }
};

// The requested resolution as printed in the table: "auto" for 0.
std::string resolutionLabel(double requested)
{
  if (requested <= 0.0)
    return "auto";
  std::ostringstream text;
  text << requested;
  return text.str();
}

struct SurfaceKind
{
  const char* name;
  double probe; // Angstrom; 0 for the van der Waals surface
};

const SurfaceKind SurfaceKinds[] = {
  { "vdw", 0.0 },
  { "sas", SolventProbeRadius },
};

void printHeader(std::ostream& out)
{
  out << std::left << std::setw(9) << "molecule" << std::right << std::setw(6)
      << "atoms"
      << " " << std::left << std::setw(4) << "type" << std::right
      << std::setw(7) << "res" << std::setw(8) << "spacing" << std::setw(11)
      << "voxels" << std::setw(10) << "fill-bin" << std::setw(10) << "fill-dist"
      << std::setw(7) << "ratio" << std::setw(10) << "fe-bin" << std::setw(10)
      << "tri-bin" << std::setw(10) << "fe-dist" << std::setw(10) << "tri-dist"
      << std::setw(13) << "smooth1-bin" << std::setw(11) << "tot-b1"
      << std::setw(11) << "tot-d0" << std::setw(7) << "ratio"
      << "\n";
}

void printRow(std::ostream& out, const Row& r)
{
  const double totalBinary = r.totalBinary();
  const double totalDistance = r.totalDistance();
  out << std::left << std::setw(9) << r.molecule << std::right << std::setw(6)
      << r.atoms << " " << std::left << std::setw(4) << r.type << std::right
      << std::setw(7) << r.requested << std::fixed << std::setprecision(3)
      << std::setw(8) << r.spacing << std::setw(11) << r.voxels
      << std::setprecision(1) << std::setw(10) << r.binaryFill << std::setw(10)
      << r.distanceFill << std::setprecision(2) << std::setw(7)
      << (r.binaryFill > 0.0 ? r.distanceFill / r.binaryFill : 0.0)
      << std::setprecision(1) << std::setw(10) << r.binaryExtract.ms
      << std::setw(10) << r.binaryExtract.triangles << std::setw(10)
      << r.distanceExtract.ms << std::setw(10) << r.distanceExtract.triangles
      << std::setw(13) << r.binarySmooth1 << std::setw(11) << totalBinary
      << std::setw(11) << totalDistance << std::setprecision(2) << std::setw(7)
      << (totalBinary > 0.0 ? totalDistance / totalBinary : 0.0) << "\n";
}

void writeCsv(std::ostream& out, const std::vector<Row>& rows)
{
  out << "molecule,atoms,type,requested_res,spacing,voxels,fill_binary_ms,"
         "fill_distance_ms,fe_binary_ms,tri_binary,fe_distance_ms,"
         "tri_distance,smooth1_binary_ms,tot_b1_ms,tot_d0_ms\n";
  for (const Row& r : rows) {
    out << r.molecule << ',' << r.atoms << ',' << r.type << ',' << r.requested
        << ',' << r.spacing << ',' << r.voxels << ',' << r.binaryFill << ','
        << r.distanceFill << ',' << r.binaryExtract.ms << ','
        << r.binaryExtract.triangles << ',' << r.distanceExtract.ms << ','
        << r.distanceExtract.triangles << ',' << r.binarySmooth1 << ','
        << r.totalBinary() << ',' << r.totalDistance() << '\n';
  }
}

bool wanted(const Options& options, const std::string& label)
{
  if (options.molecules.empty())
    return true;
  return std::find(options.molecules.begin(), options.molecules.end(), label) !=
         options.molecules.end();
}

} // namespace

int main(int argc, char** argv)
{
  QCoreApplication app(argc, argv);
  Options options;
  if (!parseArguments(argc, argv, options)) {
    usage(argv[0]);
    return 2;
  }

  std::cout << "Threads: " << QThreadPool::globalInstance()->maxThreadCount()
            << ", repeats: " << options.repeats
            << " (median, after one warm-up)\n"
            << "Times in ms. fill = grid fill; fe = Flying Edges extraction "
               "(0 smoothing passes); smooth1 = Mesh::smooth(1) on a copy of "
               "the binary mesh; bin/dist = binary/distance field; tot-b1 = "
               "fill-bin + fe-bin + smooth1-bin; tot-d0 = fill-dist + "
               "fe-dist.\n\n";
  printHeader(std::cout);

  std::vector<Row> rows;
  std::vector<SesRow> sesRows;
  for (const MoleculeSpec& spec : Molecules) {
    if (!wanted(options, spec.label))
      continue;
    Molecule molecule;
    const auto path = resolvePath(options.dataRoot, spec.file);
    if (!readMoleculeFromPath(path, molecule) || molecule.atomCount() == 0) {
      std::cerr << "Could not read " << path << "\n";
      continue;
    }

    for (const SurfaceKind& kind : SurfaceKinds) {
      const char* type = kind.name;
      const double probe = kind.probe;
      std::vector<EdtSphere> spheres;
      Vector3 low = molecule.atomPositions3d()[0];
      Vector3 high = low;
      double maxRadius = probe;
      for (std::size_t i = 0; i < molecule.atomCount(); ++i) {
        const Vector3 position = molecule.atomPositions3d()[i];
        low = low.cwiseMin(position);
        high = high.cwiseMax(position);
        const double radius =
          Avogadro::Core::Elements::radiusVDW(molecule.atomicNumber(i)) + probe;
        maxRadius = std::max(maxRadius, radius);
        spheres.emplace_back(position, radius);
      }
      // As in Surfaces::calculateEDT().
      const double padding = static_cast<float>(maxRadius + probe + 0.2);
      const Vector3 pad = Vector3::Constant(padding);

      for (double requested : options.resolutions) {
        double resolution = requested;
        if (resolution <= 0.0) {
          resolution = Avogadro::QtPlugins::automaticSurfaceResolution(
            molecule.atomCount(), Vector3((high - low) + 2.0 * pad), 0.05f);
        }
        Cube cube;
        const Vector3 cubeMin = low - pad;
        const Vector3 cubeMax = high + pad;
        const Vector3 extent = cubeMax - cubeMin;
        const double estimate = (extent.x() / resolution) *
                                (extent.y() / resolution) *
                                (extent.z() / resolution);
        if (estimate > options.maxVoxels) {
          std::cerr << "skip " << spec.label << ' ' << type << " res "
                    << resolution << ": ~" << static_cast<long long>(estimate)
                    << " voxels\n";
          continue;
        }
        if (!cube.setLimits(cubeMin, cubeMax, static_cast<float>(resolution))) {
          std::cerr << "skip " << spec.label << " res " << resolution
                    << ": no grid\n";
          continue;
        }

        Row row;
        row.molecule = spec.label;
        row.atoms = molecule.atomCount();
        row.type = type;
        row.requested = resolutionLabel(requested);
        row.resolution = resolution;
        row.spacing = cube.spacing().maxCoeff();
        const Vector3i dims = cube.dimensions();
        row.voxels = static_cast<std::size_t>(dims(0)) * dims(1) * dims(2);

        row.binaryFill = timeMedian(options.repeats, [&]() {
          Avogadro::QtPlugins::fillBinarySpheres(cube, spheres);
        });
        Mesh binaryMesh;
        row.binaryExtract = timeExtract(cube, options.repeats, binaryMesh);
        row.binarySmooth1 = timeSmooth(binaryMesh, 1, options.repeats);

        row.distanceFill = timeMedian(options.repeats, [&]() {
          Avogadro::QtPlugins::fillDistanceSpheres(cube, spheres);
        });
        Mesh distanceMesh;
        row.distanceExtract = timeExtract(cube, options.repeats, distanceMesh);

        printRow(std::cout, row);
        std::cout.flush();
        rows.push_back(row);
      }
    }

    // Solvent-excluded surface: old erosion vs the distance transform.
    {
      std::vector<EdtSphere> spheres;
      Vector3 low = molecule.atomPositions3d()[0];
      Vector3 high = low;
      double maxRadius = SolventProbeRadius;
      for (std::size_t i = 0; i < molecule.atomCount(); ++i) {
        const Vector3 position = molecule.atomPositions3d()[i];
        low = low.cwiseMin(position);
        high = high.cwiseMax(position);
        const double radius =
          Avogadro::Core::Elements::radiusVDW(molecule.atomicNumber(i)) +
          SolventProbeRadius;
        maxRadius = std::max(maxRadius, radius);
        spheres.emplace_back(position, radius);
      }
      const double padding =
        static_cast<float>(maxRadius + SolventProbeRadius + 0.2);
      const Vector3 pad = Vector3::Constant(padding);
      for (double requested : options.resolutions) {
        double resolution = requested;
        if (resolution <= 0.0) {
          resolution = Avogadro::QtPlugins::automaticSurfaceResolution(
            molecule.atomCount(), Vector3((high - low) + 2.0 * pad), 0.05f);
        }
        Cube cube;
        const Vector3 extent = (high - low) + 2.0 * pad;
        const double estimate = (extent.x() / resolution) *
                                (extent.y() / resolution) *
                                (extent.z() / resolution);
        if (estimate > options.maxVoxels ||
            !cube.setLimits(Vector3(low - pad), Vector3(high + pad),
                            static_cast<float>(resolution)))
          continue;
        SesRow row;
        row.molecule = spec.label;
        row.atoms = molecule.atomCount();
        row.requested = resolutionLabel(requested);
        row.spacing = cube.spacing().maxCoeff();
        const Vector3i dims = cube.dimensions();
        row.voxels = static_cast<std::size_t>(dims(0)) * dims(1) * dims(2);

        row.newFill = timeMedian(options.repeats, [&]() {
          Avogadro::QtPlugins::fillSolventExcluded(cube, spheres,
                                                   SolventProbeRadius);
        });
        Mesh newMesh;
        row.newTriangles =
          timeExtract(cube, 1, newMesh).triangles; // count only

        if (static_cast<double>(row.voxels) <= options.sesOldMaxVoxels) {
          row.haveOld = true;
          const std::vector<char> newSet = insideSet(cube);
          // The erosion is timed separately from the binary fill it follows;
          // the fill is rerun for every erosion because that is destructive.
          std::vector<double> fills, erodes;
          for (std::size_t i = 0; i < options.repeats + 1; ++i) {
            auto start = Clock::now();
            Avogadro::QtPlugins::fillBinarySpheres(cube, spheres);
            const double fill = elapsedMs(start);
            start = Clock::now();
            erodeSolventAccessible(cube, SolventProbeRadius);
            const double erode = elapsedMs(start);
            if (i > 0) { // the first run is the warm-up
              fills.push_back(fill);
              erodes.push_back(erode);
            }
          }
          row.oldFill = median(fills);
          row.oldErode = median(erodes);
          Mesh oldMesh;
          row.oldTriangles = timeExtract(cube, 1, oldMesh).triangles;
          row.sets = compareInsideSets(insideSet(cube), newSet, dims);
        }
        sesRows.push_back(row);
      }
    }
  }

  if (!sesRows.empty()) {
    std::cout << "\nSolvent-excluded surface (times in ms): bin-fill = "
                 "fillBinarySpheres(); erode = the former performEDTStep(); "
                 "old-ses = bin-fill + erode; new-ses = fillSolventExcluded(); "
                 "tri = Flying Edges triangles at iso 0 (0 smoothing).\n\n";
    printSesHeader(std::cout);
    for (const SesRow& r : sesRows)
      printSesRow(std::cout, r);
  }

  if (rows.empty()) {
    std::cerr << "No measurements: every molecule or grid was skipped\n";
    return 1;
  }

  if (!options.csvPath.empty()) {
    std::ofstream csv(options.csvPath);
    if (!csv) {
      std::cerr << "Could not write " << options.csvPath << "\n";
      return 1;
    }
    writeCsv(csv, rows);
  }
  return 0;
}
