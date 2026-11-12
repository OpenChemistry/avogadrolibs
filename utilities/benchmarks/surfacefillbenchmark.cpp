/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Benchmark for the grid fill behind the van der Waals and solvent-accessible
// surfaces (edtfill.cpp), and for the marching-cubes pass that follows.
//
// For each molecule x resolution x surface type it reports the median of
// several runs of
//   - fillBinarySpheres():   the +1/-1 field the surfaces used to use
//   - fillDistanceSpheres(): the signed distance field they use now
//   - MeshGenerator on the binary field with 0 and 1 smoothing passes (1 is
//     the GUI default, "Light") and on the distance field with 0 passes,
//     with the number of triangles each produces.
// The grid is built the way Surfaces::calculateEDT() builds it.

#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/meshgenerator.h>

#include "benchmark_common.h"
#include "edtfill.h"
#include "surfaceresolution.h"

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
  std::vector<double> resolutions = { 0.1, 0.2, 0.3, 0.5, 0.0 }; // 0 = auto
  std::vector<std::string> molecules;                            // empty = all
  std::string csvPath;
};

void usage(const char* program)
{
  std::cout
    << "Usage: " << program << " [options]\n\n"
    << "Times the VdW/SAS grid fill (binary vs signed distance) and the\n"
    << "marching-cubes pass on the resulting fields.\n\n"
    << "Options:\n"
    << "  --data-root DIR     Directory holding data/ (default: avogadrodata)\n"
    << "  --repeats N         Timed runs per measurement, after one warm-up\n"
    << "                      (default 5)\n"
    << "  --max-voxels M      Skip grids larger than M voxels (default 3e8)\n"
    << "  --resolution R      Only this spacing in Angstrom (repeatable;\n"
    << "                      0 = the plugin's automatic choice)\n"
    << "  --molecule NAME     Only this molecule (repeatable): caffeine,\n"
    << "                      tyr-33, crambin, 4HHB\n"
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
    const std::chrono::duration<double, std::milli> elapsed =
      Clock::now() - start;
    times.push_back(elapsed.count());
  }
  return median(times);
}

struct MeshTiming
{
  double ms = 0.0;
  std::size_t triangles = 0;
};

MeshTiming timeMesh(const Cube& cube, int passes, std::size_t repeats)
{
  MeshTiming result;
  MeshGenerator generator;
  result.ms = timeMedian(repeats, [&]() {
    Mesh mesh;
    generator.initialize(&cube, &mesh, 0.0f, passes);
    generator.start();
    generator.wait();
    result.triangles = mesh.triangles().size();
  });
  return result;
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
  MeshTiming binary0, binary1, distance0;
};

void printHeader(std::ostream& out)
{
  out << std::left << std::setw(9) << "molecule" << std::right << std::setw(6)
      << "atoms"
      << " " << std::left << std::setw(4) << "type" << std::right
      << std::setw(7) << "res" << std::setw(8) << "spacing" << std::setw(11)
      << "voxels" << std::setw(10) << "fill-bin" << std::setw(10) << "fill-dist"
      << std::setw(7) << "ratio" << std::setw(10) << "mc-b0" << std::setw(10)
      << "tri-b0" << std::setw(10) << "mc-b1" << std::setw(10) << "tri-b1"
      << std::setw(10) << "mc-d0" << std::setw(10) << "tri-d0" << std::setw(11)
      << "tot-b1" << std::setw(11) << "tot-d0" << std::setw(7) << "ratio"
      << "\n";
}

void printRow(std::ostream& out, const Row& r)
{
  const double totalBinary = r.binaryFill + r.binary1.ms;
  const double totalDistance = r.distanceFill + r.distance0.ms;
  out << std::left << std::setw(9) << r.molecule << std::right << std::setw(6)
      << r.atoms << " " << std::left << std::setw(4) << r.type << std::right
      << std::setw(7) << r.requested << std::fixed << std::setprecision(3)
      << std::setw(8) << r.spacing << std::setw(11) << r.voxels
      << std::setprecision(1) << std::setw(10) << r.binaryFill << std::setw(10)
      << r.distanceFill << std::setprecision(2) << std::setw(7)
      << (r.binaryFill > 0.0 ? r.distanceFill / r.binaryFill : 0.0)
      << std::setprecision(1) << std::setw(10) << r.binary0.ms << std::setw(10)
      << r.binary0.triangles << std::setw(10) << r.binary1.ms << std::setw(10)
      << r.binary1.triangles << std::setw(10) << r.distance0.ms << std::setw(10)
      << r.distance0.triangles << std::setw(11) << totalBinary << std::setw(11)
      << totalDistance << std::setprecision(2) << std::setw(7)
      << (totalBinary > 0.0 ? totalDistance / totalBinary : 0.0) << "\n";
}

void writeCsv(std::ostream& out, const std::vector<Row>& rows)
{
  out << "molecule,atoms,type,requested_res,spacing,voxels,fill_binary_ms,"
         "fill_distance_ms,mesh_binary0_ms,tri_binary0,mesh_binary1_ms,"
         "tri_binary1,mesh_distance0_ms,tri_distance0\n";
  for (const Row& r : rows) {
    out << r.molecule << ',' << r.atoms << ',' << r.type << ',' << r.requested
        << ',' << r.spacing << ',' << r.voxels << ',' << r.binaryFill << ','
        << r.distanceFill << ',' << r.binary0.ms << ',' << r.binary0.triangles
        << ',' << r.binary1.ms << ',' << r.binary1.triangles << ','
        << r.distance0.ms << ',' << r.distance0.triangles << '\n';
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
            << "Times in ms. fill = grid fill; mc = marching cubes; b0/b1 = "
               "binary field, 0/1 smoothing passes; d0 = distance field, 0 "
               "passes; tot = fill + mc.\n\n";
  printHeader(std::cout);

  std::vector<Row> rows;
  for (const MoleculeSpec& spec : Molecules) {
    if (!wanted(options, spec.label))
      continue;
    Molecule molecule;
    const auto path = resolvePath(options.dataRoot, spec.file);
    if (!readMoleculeFromPath(path, molecule) || molecule.atomCount() == 0) {
      std::cerr << "Could not read " << path << "\n";
      continue;
    }

    for (const char* type : { "vdw", "sas" }) {
      const double probe =
        (std::string(type) == "sas") ? SolventProbeRadius : 0.0;
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
        row.requested = (requested <= 0.0) ? "auto" : [&]() {
          std::ostringstream text;
          text << requested;
          return text.str();
        }();
        row.resolution = resolution;
        row.spacing = cube.spacing().maxCoeff();
        const Vector3i dims = cube.dimensions();
        row.voxels = static_cast<std::size_t>(dims(0)) * dims(1) * dims(2);

        // Cheaper to repeat small grids; a long grid is run fewer times.
        std::size_t repeats = options.repeats;

        row.binaryFill = timeMedian(repeats, [&]() {
          Avogadro::QtPlugins::fillBinarySpheres(cube, spheres);
        });
        row.binary0 = timeMesh(cube, 0, repeats);
        row.binary1 = timeMesh(cube, 1, repeats);

        row.distanceFill = timeMedian(repeats, [&]() {
          Avogadro::QtPlugins::fillDistanceSpheres(cube, spheres);
        });
        row.distance0 = timeMesh(cube, 0, repeats);

        printRow(std::cout, row);
        std::cout.flush();
        rows.push_back(row);
      }
    }
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
