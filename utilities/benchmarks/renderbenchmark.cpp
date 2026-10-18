/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Offscreen benchmark of the scene-building and rendering path. It plays a
// trajectory through the same steps GLWidget takes for every frame and reports
// CPU and GPU time per stage, so rendering changes can be measured.
//
// With --surface it also runs the Surfaces plugin's van der Waals,
// solvent-accessible or solvent-excluded calculation first, and reports what
// that cost (time, grid, peak memory, mesh size and quality) before rendering
// the resulting mesh with the "Surfaces" display type.

#include <avogadro/core/array.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtplugins/pluginmanager.h>
#include <avogadro/rendering/bufferobject.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include "benchmark_common.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QEventLoop>
#include <QtCore/QTimer>
#include <QtCore/QVariantMap>
#include <QtGui/QImage>
#include <QtGui/QOffscreenSurface>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLFunctions>
#include <QtGui/QSurfaceFormat>
#include <QtOpenGL/QOpenGLFramebufferObject>
#include <QtWidgets/QApplication>

#include <Eigen/Geometry>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#endif

namespace {

using Avogadro::Vector3;
using Avogadro::Benchmarks::parseDouble;
using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Core::Array;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::ScenePlugin;
using Avogadro::Rendering::BufferObject;
using Avogadro::Rendering::GLRenderer;
using Avogadro::Rendering::GroupNode;
using Clock = std::chrono::steady_clock;

// RWLayerManager keeps addMolecule() protected; this is the one public-API
// way to make a molecule the active one for the plugins' layer state.
class MoleculeActivator : public Avogadro::QtGui::RWLayerManager
{
public:
  void activate(const Avogadro::Core::Molecule* mol) { addMolecule(mol); }
};

enum class Mode
{
  Rebuild,
  Render
};

struct Options
{
  std::string file;
  std::size_t water = 0;
  std::size_t width = 1920;
  std::size_t height = 1080;
  std::size_t warmup = 5;
  std::size_t frames = 100;
  std::size_t sets = 4;
  std::size_t seed = 12345;
  std::vector<std::string> styles;
  Mode mode = Mode::Rebuild;
  std::string jsonPath;
  // Surface calculation (empty surface = none).
  std::string surface;              // vdw, sas or ses
  double surfaceResolution = 0.0;   // Angstrom; 0 lets the plugin choose
  int smoothing = 1;                // GUI default ("Light") is one pass
  std::size_t surfaceTimeout = 600; // seconds
  double maxMemoryGb = 12.0;
  std::string saveImage;
  double zoom = 1.0;
  bool listStyles = false;
  bool help = false;
};

struct Stats
{
  double median = 0.0;
  double p95 = 0.0;
  double max = 0.0;
};

// Named series of per-frame measurements, kept in first-seen order.
class Series
{
public:
  void add(const std::string& name, double value)
  {
    auto it = m_index.find(name);
    if (it == m_index.end()) {
      it = m_index.emplace(name, m_names.size()).first;
      m_names.push_back(name);
      m_values.emplace_back();
    }
    m_values[it->second].push_back(value);
  }

  const std::vector<std::string>& names() const { return m_names; }

  Stats stats(std::size_t i) const
  {
    Stats result;
    std::vector<double> sorted = m_values[i];
    if (sorted.empty())
      return result;
    std::sort(sorted.begin(), sorted.end());
    const std::size_t n = sorted.size();
    result.median =
      (n % 2 == 0) ? (sorted[n / 2 - 1] + sorted[n / 2]) * 0.5 : sorted[n / 2];
    result.p95 = sorted[std::min(
      static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(n))) - 1,
      n - 1)];
    result.max = sorted.back();
    return result;
  }

  double last(std::size_t i) const
  {
    return m_values[i].empty() ? 0.0 : m_values[i].back();
  }

private:
  std::map<std::string, std::size_t> m_index;
  std::vector<std::string> m_names;
  std::vector<std::vector<double>> m_values;
};

std::string lower(std::string text)
{
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
}

void printUsage(const char* argv0)
{
  std::cout
    << "Usage: " << argv0 << " [options]\n\n"
    << "Offscreen benchmark of scene building and rendering.\n\n"
    << "Molecule (one of):\n"
    << "  --file PATH      Read any format FileFormatManager supports\n"
    << "  --water N        Synthetic water box of about N atoms\n\n"
    << "Options:\n"
    << "  --mode MODE      rebuild (default): rebuild the scene every frame\n"
    << "                   render: build once, rotate the camera, render only\n"
    << "  --style NAME     Display type to enable (repeatable, case\n"
    << "                   insensitive; default \"Ball and Stick\")\n"
    << "  --list-styles    Print the available display types and exit\n"
    << "  --size WxH       Framebuffer size (default 1920x1080)\n"
    << "  --frames F       Timed frames (default 100)\n"
    << "  --warmup W       Untimed frames after the cold frame (default 5)\n"
    << "  --sets K         Coordinate sets to synthesize when the molecule "
       "has\n"
    << "                   fewer than two (default 4)\n"
    << "  --seed S         Random seed (default 12345)\n"
    << "  --json PATH      Also write the results as JSON\n"
    << "  --save-image P   Save the final frame as a PNG\n"
    << "  --zoom F         Dolly in after framing so the nearest surface "
       "looks\n"
    << "                   F times larger (default 1)\n"
    << "\nSurface (adds the Surfaces display type to --style):\n"
    << "  --surface TYPE   vdw, sas or ses: calculate it before rendering\n"
    << "  --surface-resolution R\n"
    << "                   Grid spacing in Angstrom (default: the plugin's\n"
    << "                   automatic choice)\n"
    << "  --smoothing N    Mesh smoothing passes (default 1, the GUI's\n"
    << "                   \"Light\"; the RPC default is 0)\n"
    << "  --surface-timeout S\n"
    << "                   Give up after S seconds (default 600)\n"
    << "  --max-memory-gb G\n"
    << "                   Refuse a surface whose estimated peak memory\n"
    << "                   exceeds G (default 12)\n"
    << "  --help           Show this message\n";
}

bool parseSize(const std::string& text, std::size_t& w, std::size_t& h)
{
  const auto x = text.find_first_of("xX");
  if (x == std::string::npos)
    return false;
  return parseUnsigned(text.substr(0, x), w) &&
         parseUnsigned(text.substr(x + 1), h) && w > 0 && h > 0;
}

bool parseArguments(int argc, char** argv, Options& options)
{
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto next = [&](std::string& out) {
      if (i + 1 >= argc) {
        std::cerr << "Missing value for " << arg << "\n";
        return false;
      }
      out = argv[++i];
      return true;
    };
    std::string value;
    if (arg == "--help" || arg == "-h") {
      options.help = true;
    } else if (arg == "--list-styles") {
      options.listStyles = true;
    } else if (arg == "--file") {
      if (!next(options.file))
        return false;
    } else if (arg == "--style") {
      if (!next(value))
        return false;
      options.styles.push_back(value);
    } else if (arg == "--json") {
      if (!next(options.jsonPath))
        return false;
    } else if (arg == "--save-image") {
      if (!next(options.saveImage))
        return false;
    } else if (arg == "--surface") {
      if (!next(value))
        return false;
      value = lower(value);
      if (value != "vdw" && value != "sas" && value != "ses") {
        std::cerr << "--surface expects vdw, sas or ses\n";
        return false;
      }
      options.surface = value;
    } else if (arg == "--surface-resolution" || arg == "--zoom" ||
               arg == "--max-memory-gb") {
      double d = 0.0;
      if (!next(value) || !parseDouble(value, d) || !std::isfinite(d) ||
          d <= 0.0) {
        std::cerr << arg << " expects a positive number\n";
        return false;
      }
      if (arg == "--surface-resolution")
        options.surfaceResolution = d;
      else if (arg == "--zoom")
        options.zoom = d;
      else
        options.maxMemoryGb = d;
    } else if (arg == "--smoothing") {
      std::size_t n = 0;
      if (!next(value) || !parseUnsigned(value, n) || n > 19) {
        std::cerr << "--smoothing expects 0 to 19\n";
        return false;
      }
      options.smoothing = static_cast<int>(n);
    } else if (arg == "--surface-timeout") {
      std::size_t n = 0;
      if (!next(value) || !parseUnsigned(value, n) || n == 0) {
        std::cerr << "--surface-timeout expects seconds\n";
        return false;
      }
      options.surfaceTimeout = n;
    } else if (arg == "--mode") {
      if (!next(value))
        return false;
      if (value == "rebuild")
        options.mode = Mode::Rebuild;
      else if (value == "render")
        options.mode = Mode::Render;
      else {
        std::cerr << "Unknown mode: " << value << "\n";
        return false;
      }
    } else if (arg == "--size") {
      if (!next(value) || !parseSize(value, options.width, options.height)) {
        std::cerr << "--size expects WxH\n";
        return false;
      }
    } else if (arg == "--water" || arg == "--frames" || arg == "--warmup" ||
               arg == "--sets" || arg == "--seed") {
      if (!next(value))
        return false;
      std::size_t n = 0;
      if (!parseUnsigned(value, n)) {
        std::cerr << "Invalid number for " << arg << ": " << value << "\n";
        return false;
      }
      if (arg == "--water")
        options.water = n;
      else if (arg == "--frames")
        options.frames = n;
      else if (arg == "--warmup")
        options.warmup = n;
      else if (arg == "--sets")
        options.sets = n;
      else
        options.seed = n;
    } else {
      std::cerr << "Unknown argument: " << arg << "\n";
      return false;
    }
  }
  return true;
}

double elapsedMs(Clock::time_point start, Clock::time_point stop)
{
  return std::chrono::duration<double, std::milli>(stop - start).count();
}

// A cubic box of rigid water molecules, oxygens on a 3.1 A lattice with a
// random orientation each, so no two atoms sit closer than a bond length.
void buildWaterBox(Molecule& mol, std::size_t atomTarget, std::mt19937& rng)
{
  constexpr double spacing = 3.1;
  constexpr double bondLength = 0.9572;
  constexpr double angle = 104.52 * 3.14159265358979323846 / 180.0;
  const std::size_t waters = std::max<std::size_t>(1, atomTarget / 3);
  const std::size_t side =
    static_cast<std::size_t>(std::ceil(std::cbrt(static_cast<double>(waters))));

  const Vector3 h1(bondLength * std::sin(angle / 2.0),
                   bondLength * std::cos(angle / 2.0), 0.0);
  const Vector3 h2(-h1.x(), h1.y(), 0.0);
  std::normal_distribution<double> gauss(0.0, 1.0);

  for (std::size_t n = 0; n < waters; ++n) {
    const Vector3 o(spacing * static_cast<double>(n % side),
                    spacing * static_cast<double>((n / side) % side),
                    spacing * static_cast<double>(n / (side * side)));
    Eigen::Quaterniond q(gauss(rng), gauss(rng), gauss(rng), gauss(rng));
    if (q.norm() < 1.0e-9)
      q = Eigen::Quaterniond::Identity();
    q.normalize();

    auto oxygen = mol.addAtom(8);
    oxygen.setPosition3d(o);
    auto hydrogenA = mol.addAtom(1);
    hydrogenA.setPosition3d(o + q * h1);
    auto hydrogenB = mol.addAtom(1);
    hydrogenB.setPosition3d(o + q * h2);
    mol.addBond(oxygen, hydrogenA, 1);
    mol.addBond(oxygen, hydrogenB, 1);
  }
}

// Make sure there are at least two coordinate sets by Gaussian jitter.
void ensureCoordinateSets(Molecule& mol, std::size_t sets, std::mt19937& rng)
{
  if (mol.coordinate3dCount() >= 2 || sets < 2)
    return;
  const Array<Vector3> base = mol.atomPositions3d();
  std::normal_distribution<double> jitter(0.0, 0.05);
  for (std::size_t k = 1; k < sets; ++k) {
    Array<Vector3> positions = base;
    for (Vector3& p : positions)
      p += Vector3(jitter(rng), jitter(rng), jitter(rng));
    mol.setCoordinate3d(positions, k);
  }
}

std::string jsonEscape(const std::string& text)
{
  std::string out;
  for (char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      out += ' ';
    } else {
      out += c;
    }
  }
  return out;
}

// Everything measured about the surface calculation.
struct SurfaceReport
{
  bool requested = false;
  // "ok", "refused", "failed", "timeout" or "empty".
  std::string status = "none";
  std::string message;
  std::string type;
  bool automatic = true;
  double resolution = 0.0; // what the plugin used
  int smoothing = 0;
  double estimateGb = 0.0;     // guard's estimate of peak memory
  double estimateVoxels = 0.0; // guard's estimate of the grid size
  double computeMs = 0.0;
  Avogadro::Vector3i dims = Avogadro::Vector3i::Zero();
  double voxels = 0.0;
  Vector3 spacing = Vector3::Zero();
  std::size_t vertices = 0;
  std::size_t triangles = 0;
  double meshMB = 0.0;
  double edgeMeanA = 0.0;       // mean triangle edge, Angstrom
  double pxPerAngstrom = 0.0;   // at the focus plane of the framed view
  double edgeMeanPxFocus = 0.0; // ... in pixels there
  double edgeMeanPxNear = 0.0;  // ... at the nearest surface (larger)
  double rssBeforeMB = 0.0;
  double rssAfterMB = 0.0;
};

struct Report
{
  std::string vendor, renderer, version;
  Options options;
  std::size_t atoms = 0;
  std::size_t bonds = 0;
  std::size_t coordinateSets = 0;
  double loadMs = 0.0;
  std::vector<std::string> styles;
  bool gpuTiming = false;
  SurfaceReport surface;
  double zoomApplied = 1.0;
  Series cold;
  Series timed;
};

// Peak resident set size of this process so far, in MB. ru_maxrss is bytes on
// macOS and kilobytes elsewhere.
double peakRssMB()
{
#ifdef _WIN32
  return 0.0;
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0)
    return 0.0;
#ifdef __APPLE__
  return static_cast<double>(usage.ru_maxrss) / 1048576.0;
#else
  return static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
#endif
}

// Solvent probe radius of Surfaces (SolventProbeRadius in surfaces.cpp).
constexpr double surfaceProbeRadius = 1.4;

// What Surfaces::resolution() picks when the caller gives none and there is
// no dialog: 0.02 * N^(1/3) A, clamped to [0.05, 0.5]. The real value is read
// back from the command result; this only feeds the memory guard.
double automaticResolution(std::size_t atomCount)
{
  const double r = 0.02 * std::cbrt(static_cast<double>(atomCount));
  return std::clamp(r, 0.05, 0.5);
}

struct SurfaceEstimate
{
  double resolution = 0.0;
  double voxels = 0.0;
  double bytes = 0.0;
  bool gridTooLarge = false; // Cube::setLimits would refuse (> INT_MAX)
};

// Estimate the grid and peak memory of a surface calculation the way
// Surfaces::calculateEDT() sizes it: the atoms' bounding box padded by
// (largest radius + probe + 0.2) on every side, divided into cells of
// `resolution`. The float cube costs 4 B/voxel; the solvent-excluded pass
// also reserves a 12 B Vector3i per voxel, so 16 B/voxel. The mesh is the
// dominant term for van der Waals surfaces, and was calibrated on measured
// runs (2MS2 and 1AON, peak RSS): mesh generation peaks at about 130 B per
// triangle (flying edges output, normals, smoothing adjacency), and a
// protein's triangle count is about 2 * f * (summed atomic sphere areas) /
// res^2, with f = 0.5 for van der Waals and solvent-accessible and 0.2 for
// solvent-excluded (smoother). Both are rough, but they track the
// measurements within about 1.5x, where a naive 4 B/voxel was 4x low.
SurfaceEstimate estimateSurface(const Molecule& mol, const std::string& type,
                                double resolution)
{
  SurfaceEstimate e;
  e.resolution =
    resolution > 0.0 ? resolution : automaticResolution(mol.atomCount());
  const double probe = (type == "vdw") ? 0.0 : surfaceProbeRadius;
  const Array<Vector3>& positions = mol.atomPositions3d();
  if (positions.empty())
    return e;
  Vector3 lo = positions[0];
  Vector3 hi = positions[0];
  double maxRadius = probe;
  double sphereArea = 0.0;
  for (std::size_t i = 0; i < positions.size(); ++i) {
    lo = lo.cwiseMin(positions[i]);
    hi = hi.cwiseMax(positions[i]);
    const double radius =
      Avogadro::Core::Elements::radiusVDW(mol.atomicNumber(i)) + probe;
    maxRadius = std::max(maxRadius, radius);
    sphereArea += 4.0 * 3.14159265358979323846 * radius * radius;
  }
  const double padding = maxRadius + probe + 0.2;
  const Vector3 extent = (hi - lo).array() + 2.0 * padding;
  e.voxels = 1.0;
  for (int k = 0; k < 3; ++k)
    e.voxels *= std::floor(extent[k] / e.resolution);
  e.gridTooLarge = e.voxels >= 2147483647.0;
  const double bytesPerVoxel = (type == "ses") ? 16.0 : 4.0;
  const double triangles = 2.0 * (type == "ses" ? 0.2 : 0.5) * sphereArea /
                           (e.resolution * e.resolution);
  e.bytes = e.voxels * bytesPerVoxel + triangles * 130.0;
  return e;
}

// Mean length of the triangle edges, in Angstrom. Mesh::triangles() stores
// the three vertex indices of each triangle in a Vector3f.
double meanEdgeLength(const Avogadro::Core::Mesh& mesh)
{
  const auto& vertices = mesh.vertices();
  const auto& triangles = mesh.triangles();
  double sum = 0.0;
  std::size_t count = 0;
  for (const Avogadro::Vector3f& t : triangles) {
    const std::size_t i[3] = { static_cast<std::size_t>(t[0]),
                               static_cast<std::size_t>(t[1]),
                               static_cast<std::size_t>(t[2]) };
    if (i[0] >= vertices.size() || i[1] >= vertices.size() ||
        i[2] >= vertices.size())
      continue;
    for (int k = 0; k < 3; ++k) {
      sum +=
        static_cast<double>((vertices[i[k]] - vertices[i[(k + 1) % 3]]).norm());
      ++count;
    }
  }
  return count ? sum / static_cast<double>(count) : 0.0;
}

// Run one Surfaces command and wait for it, spinning the event loop. The
// plugin has no dialog here, so smoothing comes from the "smoothing" option
// (the dialog would otherwise decide).
bool runSurfaceCommand(Avogadro::QtGui::ExtensionPlugin* plugin,
                       const Options& options, SurfaceReport& r)
{
  const char* command =
    options.surface == "vdw"
      ? "renderVanDerWaals"
      : (options.surface == "sas" ? "renderSolventAccessible"
                                  : "renderSolventExcluded");
  QVariantMap args;
  if (options.surfaceResolution > 0.0)
    args["resolution"] = options.surfaceResolution;
  args["smoothing"] = options.smoothing;

  QEventLoop loop;
  QTimer timeout;
  timeout.setSingleShot(true);
  bool done = false;
  bool failed = false;
  bool timedOut = false;
  QString message;
  QVariantMap result;
  QObject::connect(plugin, &Avogadro::QtGui::ExtensionPlugin::commandFinished,
                   &loop, [&](const QString& m, const QVariantMap& res) {
                     done = true;
                     message = m;
                     result = res;
                     loop.quit();
                   });
  QObject::connect(plugin, &Avogadro::QtGui::ExtensionPlugin::commandFailed,
                   &loop, [&](const QString& m) {
                     done = true;
                     failed = true;
                     message = m;
                     loop.quit();
                   });
  QObject::connect(&timeout, &QTimer::timeout, &loop, [&]() {
    timedOut = true;
    loop.quit();
  });

  const Clock::time_point start = Clock::now();
  if (!plugin->handleCommand(command, args)) {
    r.status = "failed";
    r.message = "the Surfaces plugin rejected the command";
    return false;
  }
  if (!done) {
    timeout.start(static_cast<int>(
      std::min<std::size_t>(options.surfaceTimeout, 2000000) * 1000));
    loop.exec();
  }
  r.computeMs = elapsedMs(start, Clock::now());
  if (timedOut && !done) {
    r.status = "timeout";
    r.message = "no result after " + std::to_string(options.surfaceTimeout) +
                " s; the calculation may still be running";
    return false;
  }
  if (failed) {
    r.status = "failed";
    r.message = message.toStdString();
    return false;
  }
  if (result.contains("resolution"))
    r.resolution = result.value("resolution").toDouble();
  return true;
}

void printTable(const Report& r)
{
  std::cout << "\n"
            << std::left << std::setw(34) << "section (ms)" << std::right
            << std::setw(10) << "cold" << std::setw(10) << "median"
            << std::setw(10) << "p95" << std::setw(10) << "max"
            << "\n";
  std::cout << std::fixed << std::setprecision(3);
  for (std::size_t i = 0; i < r.timed.names().size(); ++i) {
    const std::string& name = r.timed.names()[i];
    const Stats s = r.timed.stats(i);
    double cold = 0.0;
    for (std::size_t j = 0; j < r.cold.names().size(); ++j)
      if (r.cold.names()[j] == name)
        cold = r.cold.last(j);
    std::cout << std::left << std::setw(34) << name << std::right
              << std::setw(10) << cold << std::setw(10) << s.median
              << std::setw(10) << s.p95 << std::setw(10) << s.max << "\n";
  }
}

void writeJson(const Report& r, const std::string& path)
{
  std::ofstream out(path);
  if (!out) {
    std::cerr << "Cannot write " << path << "\n";
    return;
  }
  out << std::setprecision(6);
  out << "{\n  \"gl_vendor\": \"" << jsonEscape(r.vendor) << "\",\n"
      << "  \"gl_renderer\": \"" << jsonEscape(r.renderer) << "\",\n"
      << "  \"gl_version\": \"" << jsonEscape(r.version) << "\",\n"
      << "  \"width\": " << r.options.width << ",\n"
      << "  \"height\": " << r.options.height << ",\n"
      << "  \"mode\": \""
      << (r.options.mode == Mode::Rebuild ? "rebuild" : "render") << "\",\n"
      << "  \"atoms\": " << r.atoms << ",\n"
      << "  \"bonds\": " << r.bonds << ",\n"
      << "  \"coordinate_sets\": " << r.coordinateSets << ",\n"
      << "  \"load_ms\": " << r.loadMs << ",\n"
      << "  \"warmup\": " << r.options.warmup << ",\n"
      << "  \"frames\": " << r.options.frames << ",\n"
      << "  \"gpu_timing\": " << (r.gpuTiming ? "true" : "false") << ",\n"
      << "  \"zoom\": " << r.zoomApplied << ",\n";
  if (r.surface.requested) {
    const SurfaceReport& s = r.surface;
    out << "  \"surface\": {\n"
        << "    \"status\": \"" << s.status << "\",\n"
        << "    \"message\": \"" << jsonEscape(s.message) << "\",\n"
        << "    \"type\": \"" << s.type << "\",\n"
        << "    \"resolution_automatic\": " << (s.automatic ? "true" : "false")
        << ",\n"
        << "    \"resolution\": " << s.resolution << ",\n"
        << "    \"smoothing\": " << s.smoothing << ",\n"
        << "    \"estimate_gb\": " << s.estimateGb << ",\n"
        << "    \"estimate_voxels\": " << s.estimateVoxels << ",\n"
        << "    \"compute_ms\": " << s.computeMs << ",\n"
        << "    \"dims\": [" << s.dims[0] << ", " << s.dims[1] << ", "
        << s.dims[2] << "],\n"
        << "    \"voxels\": " << s.voxels << ",\n"
        << "    \"spacing\": [" << s.spacing[0] << ", " << s.spacing[1] << ", "
        << s.spacing[2] << "],\n"
        << "    \"vertices\": " << s.vertices << ",\n"
        << "    \"triangles\": " << s.triangles << ",\n"
        << "    \"mesh_mb\": " << s.meshMB << ",\n"
        << "    \"mean_edge_angstrom\": " << s.edgeMeanA << ",\n"
        << "    \"pixels_per_angstrom_focus\": " << s.pxPerAngstrom << ",\n"
        << "    \"mean_edge_px_focus\": " << s.edgeMeanPxFocus << ",\n"
        << "    \"mean_edge_px_nearest\": " << s.edgeMeanPxNear << ",\n"
        << "    \"peak_rss_before_mb\": " << s.rssBeforeMB << ",\n"
        << "    \"peak_rss_after_mb\": " << s.rssAfterMB << "\n  },\n";
  }
  out << "  \"styles\": [";
  for (std::size_t i = 0; i < r.styles.size(); ++i)
    out << (i ? ", " : "") << "\"" << jsonEscape(r.styles[i]) << "\"";
  out << "],\n  \"sections\": {\n";
  for (std::size_t i = 0; i < r.timed.names().size(); ++i) {
    const std::string& name = r.timed.names()[i];
    const Stats s = r.timed.stats(i);
    double cold = 0.0;
    for (std::size_t j = 0; j < r.cold.names().size(); ++j)
      if (r.cold.names()[j] == name)
        cold = r.cold.last(j);
    out << "    \"" << jsonEscape(name) << "\": {\"cold\": " << cold
        << ", \"median\": " << s.median << ", \"p95\": " << s.p95
        << ", \"max\": " << s.max << "}"
        << (i + 1 < r.timed.names().size() ? "," : "") << "\n";
  }
  out << "  }\n}\n";
}

} // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parseArguments(argc, argv, options)) {
    printUsage(argv[0]);
    return 2;
  }
  if (options.help) {
    printUsage(argv[0]);
    return 0;
  }

  // Same default format as avogadroapp's main(): 4.0 core, macOS gives 4.1.
  QSurfaceFormat format;
  format.setVersion(4, 0);
  format.setProfile(QSurfaceFormat::CoreProfile);
  format.setDepthBufferSize(24);
  format.setStencilBufferSize(8);
  QSurfaceFormat::setDefaultFormat(format);

  // Qt would claim --style for itself; the options were parsed above, so hand
  // it only the program name.
  int qtArgc = 1;
  QApplication app(qtArgc, argv);

  // Load the scene plugins before anything else needs them.
  auto* pluginManager = Avogadro::QtPlugins::PluginManager::instance();
  pluginManager->load();
  QList<Avogadro::QtGui::ScenePluginFactory*> factories =
    pluginManager->pluginFactories<Avogadro::QtGui::ScenePluginFactory>();
  std::vector<ScenePlugin*> available;
  for (auto* factory : factories) {
    if (ScenePlugin* plugin = factory->createInstance(&app))
      available.push_back(plugin);
  }
  if (options.listStyles) {
    for (ScenePlugin* plugin : available)
      std::cout << plugin->name().toStdString() << "\n";
    return 0;
  }

  if (options.file.empty() && options.water == 0) {
    std::cerr << "Give --file PATH or --water N.\n";
    printUsage(argv[0]);
    return 2;
  }
  if (options.frames == 0) {
    std::cerr << "--frames must be at least 1.\n";
    return 2;
  }
  const bool wantSurface = !options.surface.empty();
  if (options.styles.empty() && !wantSurface)
    options.styles.push_back("Ball and Stick");
  // The mesh is drawn by the "Surfaces" display type; add it to any other
  // styles asked for, or use it alone.
  if (wantSurface &&
      std::none_of(options.styles.begin(), options.styles.end(),
                   [](const std::string& n) { return lower(n) == "surfaces"; }))
    options.styles.push_back("Surfaces");

  std::vector<ScenePlugin*> plugins;
  for (const std::string& wanted : options.styles) {
    ScenePlugin* match = nullptr;
    for (ScenePlugin* plugin : available)
      if (lower(plugin->name().toStdString()) == lower(wanted))
        match = plugin;
    if (!match) {
      std::cerr << "Unknown style \"" << wanted << "\"; see --list-styles.\n";
      return 2;
    }
    if (std::find(plugins.begin(), plugins.end(), match) == plugins.end())
      plugins.push_back(match);
  }

  // The Surfaces extension plugin, which does the calculation.
  Avogadro::QtGui::ExtensionPlugin* surfacePlugin = nullptr;
  if (wantSurface) {
    for (auto* factory :
         pluginManager
           ->pluginFactories<Avogadro::QtGui::ExtensionPluginFactory>()) {
      Avogadro::QtGui::ExtensionPlugin* plugin = factory->createInstance(&app);
      if (plugin && QString::fromLatin1(plugin->metaObject()->className())
                      .endsWith(QLatin1String("::Surfaces"))) {
        surfacePlugin = plugin;
        break;
      }
      delete plugin;
    }
    if (!surfacePlugin) {
      std::cerr << "The Surfaces extension plugin was not found.\n";
      return 1;
    }
  }

  // Offscreen context and framebuffer.
  QOffscreenSurface surface;
  surface.setFormat(QSurfaceFormat::defaultFormat());
  surface.create();
  QOpenGLContext context;
  context.setFormat(QSurfaceFormat::defaultFormat());
  if (!context.create() || !context.makeCurrent(&surface)) {
    std::cerr << "Could not create an OpenGL context.\n";
    return 1;
  }
  const int width = static_cast<int>(options.width);
  const int height = static_cast<int>(options.height);
  QOpenGLFramebufferObjectFormat fboFormat;
  fboFormat.setAttachment(QOpenGLFramebufferObject::CombinedDepthStencil);
  QOpenGLFramebufferObject fbo(width, height, fboFormat);
  if (!fbo.isValid() || !fbo.bind()) {
    std::cerr << "Could not create a " << width << "x" << height
              << " framebuffer.\n";
    return 1;
  }
  QOpenGLFunctions* gl = context.functions();
  gl->glViewport(0, 0, width, height);

  GLRenderer renderer;
  renderer.initialize();
  if (!renderer.isValid()) {
    std::cerr << "Renderer is not valid: " << renderer.error() << "\n";
    return 1;
  }
  renderer.setPixelRatio(1.0f);
  renderer.resize(width, height);

  Report report;
  report.options = options;
  auto glString = [&](GLenum name) {
    const GLubyte* s = gl->glGetString(name);
    return std::string(s ? reinterpret_cast<const char*>(s) : "unknown");
  };
  report.vendor = glString(GL_VENDOR);
  report.renderer = glString(GL_RENDERER);
  report.version = glString(GL_VERSION);

  // Build the molecule.
  std::mt19937 rng(static_cast<std::mt19937::result_type>(options.seed));
  Molecule mol;
  const Clock::time_point loadStart = Clock::now();
  if (!options.file.empty()) {
    Avogadro::Core::Molecule core;
    if (!Avogadro::Io::FileFormatManager::instance().readFile(core,
                                                              options.file)) {
      std::cerr << "Could not read " << options.file << "\n";
      return 1;
    }
    mol = Molecule(core);
  } else {
    buildWaterBox(mol, options.water, rng);
  }
  report.loadMs = elapsedMs(loadStart, Clock::now());
  ensureCoordinateSets(mol, options.sets, rng);
  report.atoms = mol.atomCount();
  report.bonds = mol.bondCount();
  report.coordinateSets = std::max<std::size_t>(1, mol.coordinate3dCount());

  // Enable the chosen plugins for the molecule's layer; the layer state is
  // keyed by whichever molecule is "active".
  MoleculeActivator().activate(&mol);
  for (ScenePlugin* plugin : plugins) {
    plugin->setEnabled(true);
    report.styles.push_back(plugin->name().toStdString());
  }

  std::string styleList;
  for (const std::string& s : report.styles)
    styleList += (styleList.empty() ? "" : ", ") + s;
  std::cout << "GL_VENDOR:   " << report.vendor << "\n"
            << "GL_RENDERER: " << report.renderer << "\n"
            << "GL_VERSION:  " << report.version << "\n"
            << "Size:        " << width << "x" << height << "\n"
            << "Molecule:    " << report.atoms << " atoms, " << report.bonds
            << " bonds, " << report.coordinateSets << " coordinate set(s); "
            << (options.file.empty() ? "generated" : "loaded") << " in "
            << std::fixed << std::setprecision(1) << report.loadMs << " ms\n"
            << "Styles:      " << styleList << "\n"
            << "Mode:        "
            << (options.mode == Mode::Rebuild ? "rebuild" : "render") << ", "
            << options.warmup << " warmup + " << options.frames
            << " timed frames\n";
#ifndef NDEBUG
  std::cout << "WARNING: NDEBUG is not defined; this is not a release build "
               "and the timings are not representative.\n";
#endif

  // Surface calculation. Done before the scene is built: the Surfaces display
  // type draws whatever meshes the molecule holds when it is processed.
  //
  // The mesh is calculated once and never recalculated. Surfaces::
  // moleculeChanged() only drops its cached pointers (the molecule itself
  // deletes the cubes and meshes) on a structural change, and coordinate-set
  // switches in the rebuild mode do not emit one, so in either mode the mesh
  // simply stays where it was computed. Use --mode render to time rendering
  // alone; rebuild mode re-uploads the same mesh each frame.
  SurfaceReport& sr = report.surface;
  if (wantSurface) {
    sr.requested = true;
    sr.type = options.surface;
    sr.automatic = options.surfaceResolution <= 0.0;
    sr.smoothing = options.smoothing;
    const SurfaceEstimate estimate =
      estimateSurface(mol, options.surface, options.surfaceResolution);
    sr.estimateVoxels = estimate.voxels;
    sr.estimateGb = estimate.bytes / 1.0e9;
    sr.resolution = estimate.resolution;
    std::cout << std::fixed << std::setprecision(3)
              << "Surface:     " << options.surface << ", "
              << (sr.automatic ? "automatic" : "requested") << " resolution "
              << estimate.resolution << " A, smoothing " << options.smoothing
              << " pass(es)\n"
              << "Estimate:    " << std::setprecision(0) << estimate.voxels
              << " voxels, " << std::setprecision(2) << sr.estimateGb
              << " GB peak (limit " << options.maxMemoryGb << " GB)\n";

    auto abort = [&](const std::string& status, const std::string& message,
                     int code) {
      sr.status = status;
      sr.message = message;
      std::cerr << "SURFACE " << status << ": " << message << "\n";
      if (!options.jsonPath.empty())
        writeJson(report, options.jsonPath);
      // A timed-out calculation is still running on worker threads that
      // use the molecule, so tearing everything down would race with it.
      if (status == "timeout") {
        std::cout.flush();
        std::cerr.flush();
        std::_Exit(code);
      }
      return code;
    };
    auto gigabytes = [](double value) {
      std::ostringstream text;
      text << std::fixed << std::setprecision(2) << value;
      return text.str();
    };
    if (estimate.gridTooLarge)
      return abort("refused",
                   "the grid would exceed INT_MAX voxels, which "
                   "Cube::setLimits rejects (and the plugin would then "
                   "silently produce an empty surface)",
                   3);
    if (sr.estimateGb > options.maxMemoryGb)
      return abort("refused",
                   "estimated peak memory " + gigabytes(sr.estimateGb) +
                     " GB exceeds --max-memory-gb " +
                     gigabytes(options.maxMemoryGb),
                   3);

    surfacePlugin->setMolecule(&mol);
    sr.rssBeforeMB = peakRssMB();
    const bool ok = runSurfaceCommand(surfacePlugin, options, sr);
    sr.rssAfterMB = peakRssMB();
    if (!ok)
      return abort(sr.status, sr.message, 1);

    // Read the result back from the molecule.
    if (mol.cubeCount() > 0) {
      const Avogadro::Core::Cube* cube = mol.cube(mol.cubeCount() - 1);
      sr.dims = cube->dimensions();
      sr.voxels = static_cast<double>(sr.dims[0]) * sr.dims[1] * sr.dims[2];
      sr.spacing = cube->spacing();
    }
    if (mol.meshCount() > 0) {
      const Avogadro::Core::Mesh* mesh = mol.mesh(mol.meshCount() - 1);
      sr.vertices = mesh->vertices().size();
      sr.triangles = mesh->triangles().size();
      sr.meshMB = static_cast<double>(mesh->vertices().size() * 12 +
                                      mesh->normals().size() * 12 +
                                      mesh->triangles().size() * 12 +
                                      mesh->colors().size() * 12) /
                  1.0e6;
      sr.edgeMeanA = meanEdgeLength(*mesh);
    }
    if (sr.voxels <= 0.0 || sr.triangles == 0)
      return abort("empty",
                   "the calculation finished but the grid has " +
                     std::to_string(static_cast<long long>(sr.voxels)) +
                     " voxels and the mesh " + std::to_string(sr.triangles) +
                     " triangles (Cube::setLimits probably failed)",
                   1);
    sr.status = "ok";
    std::cout << std::fixed << std::setprecision(3)
              << "Surface done: " << std::setprecision(1) << sr.computeMs
              << " ms, resolution used " << std::setprecision(3)
              << sr.resolution << " A\n"
              << "  grid " << sr.dims[0] << "x" << sr.dims[1] << "x"
              << sr.dims[2] << " = " << std::setprecision(0) << sr.voxels
              << " voxels, spacing " << std::setprecision(4) << sr.spacing[0]
              << " A\n"
              << "  mesh " << sr.vertices << " vertices, " << sr.triangles
              << " triangles, " << std::setprecision(1) << sr.meshMB
              << " MB, mean edge " << std::setprecision(3) << sr.edgeMeanA
              << " A\n"
              << "  peak RSS " << std::setprecision(0) << sr.rssBeforeMB
              << " MB before, " << sr.rssAfterMB << " MB after\n";
  }

  renderer.setTimingEnabled(true);
  renderer.setTimingSynchronous(true);

  // Bounds for the framing proxy: the atoms' box plus a margin for the
  // surface, which stands off the atoms by up to a vdW radius plus the probe.
  Avogadro::Vector3f proxyCenter = Avogadro::Vector3f::Zero();
  float proxyRadius = 1.0f;
  if (wantSurface && mol.atomCount() > 0) {
    const Array<Vector3>& positions = mol.atomPositions3d();
    Vector3 lo = positions[0];
    Vector3 hi = positions[0];
    for (const Vector3& p : positions) {
      lo = lo.cwiseMin(p);
      hi = hi.cwiseMax(p);
    }
    proxyCenter = (0.5 * (lo + hi)).cast<float>();
    proxyRadius = static_cast<float>(0.5 * (hi - lo).norm() + 3.0);
  }

  const std::size_t sets = report.coordinateSets;
  std::size_t frameNumber = 0;

  // Duplicates GLWidget::updateScene() (avogadro/qtopengl/glwidget.cpp, minus
  // the tool drawing) so each stage can be timed. Keep in sync with it.
  auto buildScene = [&](Series& series) {
    GroupNode& node = renderer.scene().rootNode();
    Clock::time_point t = Clock::now();
    node.clear();
    auto* moleculeNode = new GroupNode(&node);
    series.add("scene clear", elapsedMs(t, Clock::now()));
    for (ScenePlugin* plugin : plugins) {
      auto* engineNode = new GroupNode(moleculeNode);
      t = Clock::now();
      plugin->process(mol, *engineNode);
      series.add("process: " + plugin->name().toStdString(),
                 elapsedMs(t, Clock::now()));
    }
    // Scene::center() and radius() (GeometryVisitor) look only at spheres,
    // curves and lines, never at meshes, so a scene of surfaces alone is
    // framed as if empty (origin, radius 6) and the camera ends up in the
    // wrong place. Stand in for the molecule's extent with a pair of fully
    // transparent spheres at its extremes.
    if (!options.surface.empty()) {
      auto* proxyNode = new Avogadro::Rendering::GeometryNode;
      moleculeNode->addChild(proxyNode);
      auto* proxy = new Avogadro::Rendering::SphereGeometry;
      proxy->setOpacity(0.0f);
      proxyNode->addDrawable(proxy);
      const Avogadro::Vector3f offset(proxyRadius, 0.0f, 0.0f);
      proxy->addSphere(proxyCenter - offset, Avogadro::Vector3ub(0, 0, 0),
                       0.1f);
      proxy->addSphere(proxyCenter + offset, Avogadro::Vector3ub(0, 0, 0),
                       0.1f);
    }
    t = Clock::now();
    renderer.resetGeometry();
    series.add("resetGeometry", elapsedMs(t, Clock::now()));
  };

  auto renderFrame = [&](Series& series) {
    // The renderer's initialize()/resize() leave its own offscreen buffer
    // bound, and render() presents to whatever is bound when it starts, so
    // bind ours again or --save-image captures an empty framebuffer.
    fbo.bind();
    renderer.render();
    const Clock::time_point t = Clock::now();
    gl->glFinish();
    series.add("glFinish wait", elapsedMs(t, Clock::now()));
    const auto& timings = renderer.timings();
    report.gpuTiming = timings.gpuTimingAvailable;
    for (const auto& pass : timings.passes) {
      series.add("render " + pass.name + " cpu", pass.cpuMs);
      if (timings.gpuTimingAvailable)
        series.add("render " + pass.name + " gpu", pass.gpuMs);
    }
    series.add("render total cpu", timings.totalCpuMs());
    if (timings.gpuTimingAvailable)
      series.add("render total gpu", timings.totalGpuMs());
    series.add("uploaded MB",
               static_cast<double>(timings.bufferBytesUploaded) / 1.0e6);
  };

  auto rotateCamera = [&]() {
    auto& camera = renderer.camera();
    const Avogadro::Vector3f center = camera.focus();
    const Avogadro::Vector3f yAxis =
      camera.modelView().linear().row(1).transpose().normalized();
    camera.translate(center);
    camera.rotate(0.02f, yAxis);
    camera.translate(-center);
  };

  auto runFrame = [&](Series& series) {
    const Clock::time_point start = Clock::now();
    if (options.mode == Mode::Rebuild) {
      mol.setCoordinate3d(static_cast<int>(frameNumber % sets));
      buildScene(series);
    } else {
      rotateCamera();
    }
    renderFrame(series);
    series.add("frame total", elapsedMs(start, Clock::now()));
    ++frameNumber;
  };

  // Cold frame: build (always) and render once; also frames the camera.
  {
    const Clock::time_point start = Clock::now();
    const std::uint64_t before = BufferObject::totalBytesUploaded();
    buildScene(report.cold);
    renderer.resetCamera();
    renderFrame(report.cold);
    report.cold.add("frame total", elapsedMs(start, Clock::now()));

    // The projection is only set up by render(), so measure the framed view
    // now. Pixels per Angstrom come from projecting the focus point and a
    // point 1 A to its right. Triangles lie at varying depths, so this is
    // exact only for those at the focus plane (the middle of the molecule);
    // the nearest surface is roughly distance / (distance - radius) times
    // larger, which is the "nearest" figure.
    auto& camera = renderer.camera();
    const Avogadro::Vector3f focus = camera.focus();
    const Avogadro::Vector3f right =
      camera.modelView().linear().row(0).transpose().normalized();
    const Avogadro::Vector3f a = camera.project(focus);
    const Avogadro::Vector3f b = camera.project(focus + right);
    sr.pxPerAngstrom = static_cast<double>((b - a).head<2>().norm());
    float nearFactor = 1.0f;
    const float distance = camera.distance(focus);
    const float radius = renderer.scene().radius();
    if (camera.projectionType() == Avogadro::Rendering::Perspective &&
        distance > radius)
      nearFactor = distance / (distance - radius);
    sr.edgeMeanPxFocus = sr.edgeMeanA * sr.pxPerAngstrom;
    sr.edgeMeanPxNear = sr.edgeMeanPxFocus * static_cast<double>(nearFactor);

    // Close-up: dolly toward the focus, but never past the nearest point of
    // the scene's bounding sphere, so a zoom of F magnifies the front surface
    // by F instead of flying inside the molecule.
    if (options.zoom > 1.0 &&
        camera.projectionType() == Avogadro::Rendering::Perspective) {
      const float zoom = static_cast<float>(options.zoom);
      const float newDistance = radius + (distance - radius) / zoom;
      camera.preTranslate(Avogadro::Vector3f::UnitZ() *
                          (distance - newDistance));
      report.zoomApplied = options.zoom;
    }
    ++frameNumber;
    if (BufferObject::totalBytesUploaded() == before) {
      std::cerr << "ERROR: the first frame uploaded 0 bytes; the chosen "
                   "styles produced no geometry.\n";
      return 1;
    }
  }

  for (std::size_t i = 0; i < options.warmup; ++i) {
    Series discard;
    runFrame(discard);
  }
  for (std::size_t i = 0; i < options.frames; ++i)
    runFrame(report.timed);

  if (!report.timed.names().empty() && !report.gpuTiming)
    std::cout << "NOTE: GPU timer queries unavailable; GPU columns omitted.\n";
  printTable(report);
  std::cout << "\n(cold = first frame: build + render, includes tessellation "
               "and first-use shader setup)\n";
  if (wantSurface)
    std::cout << std::fixed << std::setprecision(2)
              << "\nSurface mesh: mean edge " << sr.edgeMeanA
              << " A = " << sr.edgeMeanPxFocus
              << " px at the framed focus plane (" << sr.edgeMeanPxNear
              << " px at the nearest surface), " << sr.pxPerAngstrom
              << " px/A\n";
  if (!options.saveImage.empty()) {
    gl->glFinish();
    if (fbo.toImage().save(QString::fromStdString(options.saveImage)))
      std::cout << "Saved " << options.saveImage << "\n";
    else
      std::cerr << "Could not save " << options.saveImage << "\n";
  }
  if (!options.jsonPath.empty())
    writeJson(report, options.jsonPath);

  // Tear down with the context current so GL objects are released properly.
  renderer.scene().rootNode().clear();
  return 0;
}
