/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Offscreen benchmark of the scene-building and rendering path. It plays a
// trajectory through the same steps GLWidget takes for every frame and reports
// CPU and GPU time per stage, so rendering changes can be measured.

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtplugins/pluginmanager.h>
#include <avogadro/rendering/bufferobject.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>

#include "benchmark_common.h"

#include <QtCore/QCoreApplication>
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
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

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

std::string lower(std::string text)
{
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return text;
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
  Series cold;
  Series timed;
};

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
      << "  \"styles\": [";
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
  if (options.styles.empty())
    options.styles.push_back("Ball and Stick");

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

  renderer.setTimingEnabled(true);
  renderer.setTimingSynchronous(true);

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
    t = Clock::now();
    renderer.resetGeometry();
    series.add("resetGeometry", elapsedMs(t, Clock::now()));
  };

  auto renderFrame = [&](Series& series) {
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
  if (!options.jsonPath.empty())
    writeJson(report, options.jsonPath);

  // Tear down with the context current so GL objects are released properly.
  renderer.scene().rootNode().clear();
  return 0;
}
