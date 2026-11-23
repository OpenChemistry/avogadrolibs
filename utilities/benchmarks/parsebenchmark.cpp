/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Benchmarks the text parsing path of the XYZ, FCHK and cube readers. Input
// files are read into memory once and only FileFormat::readString() is timed,
// so disk I/O is excluded. Synthetic inputs come from an explicit integer
// generator and fixed-precision snprintf output, so they are byte-identical
// across platforms and runs. A result checksum is printed for each input so a
// parser change can be shown to give identical results.

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>

#include "benchmark_common.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Benchmarks::resolvePath;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::Molecule;
using Clock = std::chrono::steady_clock;

enum class Kind
{
  Xyz,
  Traj,
  Fchk,
  Cube,
  Split
};

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::string workDir;
  std::string caseName = "all";
  std::size_t warmup = 1;
  std::size_t iterations = 5;
  std::size_t xyzAtoms = 500000;
  std::size_t trajAtoms = 1000;
  std::size_t trajFrames = 500;
  std::size_t cubePoints = 200;
  bool keepFiles = false;
  std::vector<std::string> files;
};

struct Input
{
  std::string caseName;
  std::string label;
  Kind kind = Kind::Xyz;
  std::string text;
};

struct Checksum
{
  std::size_t atoms = 0;
  unsigned long long atomicNumberSum = 0;
  double coordSum = 0.0;
  std::size_t frames = 0;
  std::size_t values = 0; // cube values or split tokens
  double valueSum = 0.0;
  std::size_t basisFunctions = 0;
  std::size_t moRows = 0;
  std::size_t moCols = 0;
  double moSum = 0.0;
};

struct Result
{
  Input* input = nullptr;
  std::string caseName;
  bool ok = false;
  std::string error;
  std::vector<double> samplesMs;
  Checksum checksum;
  std::size_t count = 0; // frames, grid points or lines
};

void printUsage(const char* argv0)
{
  std::cout
    << "Usage: " << argv0 << " [options]\n\n"
    << "Benchmarks XYZ, FCHK and cube parsing (readString only).\n\n"
    << "Options:\n"
    << "  --case NAME        xyz|traj|fchk|cube|split|all (default all)\n"
    << "  --data-root PATH   Data root, files under data/ (default: "
    << AVOGADRO_BENCHMARK_DATA_ROOT << ")\n"
    << "  --warmup N         Untimed reads per input (default 1)\n"
    << "  --iterations N     Timed reads per input (default 5)\n"
    << "  --xyz-atoms N      Atoms in the single-frame XYZ (default 500000)\n"
    << "  --traj-atoms N     Atoms per trajectory frame (default 1000)\n"
    << "  --traj-frames N    Trajectory frames (default 500)\n"
    << "  --cube-points N    Cube grid points per axis (default 200)\n"
    << "  --file PATH        Extra input (.xyz, .fchk/.fch, .cube/.cub)\n"
    << "  --work-dir PATH    Directory for synthetic files\n"
    << "  --keep-files       Do not delete synthetic files\n"
    << "  --help             Show this help\n";
}

bool parseArgs(int argc, char** argv, Options& o)
{
  struct Size
  {
    const char* name;
    std::size_t* value;
  };
  const Size sizes[] = {
    { "--warmup", &o.warmup },          { "--iterations", &o.iterations },
    { "--xyz-atoms", &o.xyzAtoms },     { "--traj-atoms", &o.trajAtoms },
    { "--traj-frames", &o.trajFrames }, { "--cube-points", &o.cubePoints }
  };
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return false;
    }
    if (arg == "--keep-files") {
      o.keepFiles = true;
      continue;
    }
    bool matched = false;
    for (const auto& s : sizes) {
      if (arg != s.name)
        continue;
      matched = true;
      if (i + 1 >= argc || !parseUnsigned(argv[i + 1], *s.value)) {
        std::cerr << "Invalid value for " << arg << "\n";
        return false;
      }
      ++i;
    }
    if (matched)
      continue;
    std::string* target = nullptr;
    if (arg == "--data-root")
      target = &o.dataRoot;
    else if (arg == "--work-dir")
      target = &o.workDir;
    else if (arg == "--case")
      target = &o.caseName;
    if (arg == "--file") {
      if (i + 1 >= argc) {
        std::cerr << "Missing value for --file\n";
        return false;
      }
      o.files.emplace_back(argv[++i]);
      continue;
    }
    if (target == nullptr) {
      std::cerr << "Unknown option: " << arg << "\n";
      return false;
    }
    if (i + 1 >= argc) {
      std::cerr << "Missing value for " << arg << "\n";
      return false;
    }
    *target = argv[++i];
  }

  const std::vector<std::string> cases = { "xyz",  "traj",  "fchk",
                                           "cube", "split", "all" };
  if (std::find(cases.begin(), cases.end(), o.caseName) == cases.end()) {
    std::cerr << "Unknown case: " << o.caseName << "\n";
    return false;
  }
  if (o.iterations == 0 || o.xyzAtoms == 0 || o.trajAtoms == 0 ||
      o.trajFrames == 0 || o.cubePoints == 0) {
    std::cerr << "Counts must be greater than zero\n";
    return false;
  }
  if (o.workDir.empty())
    o.workDir =
      (fs::temp_directory_path() / "avogadro-parsebenchmark").string();
  return true;
}

// splitmix64: a tiny, fully specified generator.
class Rng
{
public:
  explicit Rng(std::uint64_t seed) : m_state(seed) {}
  std::uint64_t next()
  {
    m_state += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = m_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  // Uniform-ish value in [lo, hi) with 1e-6 resolution.
  double range(double lo, double hi)
  {
    const double u = static_cast<double>(next() % 1000000ULL) / 1.0e6;
    return lo + (hi - lo) * u;
  }

private:
  std::uint64_t m_state;
};

const char* const kSymbols[] = { "C", "H", "O", "N" };
const int kNumbers[] = { 6, 1, 8, 7 };

void appendXyzFrame(std::string& out, std::size_t atoms, std::size_t frame,
                    Rng& rng)
{
  char line[160];
  out += std::to_string(atoms);
  out += "\nframe " + std::to_string(frame) + "\n";
  // A jittered cubic lattice with 4 A spacing: no atoms bond, so the time in
  // the readers' bond perception stays linear (uniform random positions in a
  // box are far denser than any molecule and make it quadratic).
  std::size_t side = 1;
  while (side * side * side < atoms)
    ++side;
  const double center = 2.0 * static_cast<double>(side);
  for (std::size_t i = 0; i < atoms; ++i) {
    const auto e = static_cast<std::size_t>(rng.next() % 4);
    const double x =
      4.0 * static_cast<double>(i % side) - center + rng.range(-0.4, 0.4);
    const double y = 4.0 * static_cast<double>((i / side) % side) - center +
                     rng.range(-0.4, 0.4);
    const double z = 4.0 * static_cast<double>(i / (side * side)) - center +
                     rng.range(-0.4, 0.4);
    std::snprintf(line, sizeof(line), "%-2s %12.6f %12.6f %12.6f\n",
                  kSymbols[e], x, y, z);
    out += line;
  }
}

std::string makeXyz(std::size_t atoms, std::size_t frames)
{
  Rng rng(0x5EED0001ULL);
  std::string out;
  out.reserve(atoms * frames * 48 + 64);
  for (std::size_t f = 0; f < frames; ++f)
    appendXyzFrame(out, atoms, f, rng);
  return out;
}

std::string makeCube(std::size_t n)
{
  Rng rng(0x5EED0002ULL);
  char line[160];
  const std::size_t atoms = 10;
  std::string out;
  out.reserve(n * n * n * 14 + n * n * 8 + 1024);
  out += "Synthetic cube\nGenerated by parsebenchmark\n";
  const double step = 0.25;
  std::snprintf(line, sizeof(line), "%5d %12.6f %12.6f %12.6f\n",
                static_cast<int>(atoms), -2.0, -2.0, -2.0);
  out += line;
  for (int axis = 0; axis < 3; ++axis) {
    std::snprintf(line, sizeof(line), "%5d %12.6f %12.6f %12.6f\n",
                  static_cast<int>(n), axis == 0 ? step : 0.0,
                  axis == 1 ? step : 0.0, axis == 2 ? step : 0.0);
    out += line;
  }
  for (std::size_t i = 0; i < atoms; ++i) {
    const auto e = static_cast<std::size_t>(rng.next() % 4);
    std::snprintf(line, sizeof(line), "%5d %12.6f %12.6f %12.6f %12.6f\n",
                  kNumbers[e], static_cast<double>(kNumbers[e]),
                  rng.range(0.0, 8.0), rng.range(0.0, 8.0),
                  rng.range(0.0, 8.0));
    out += line;
  }
  for (std::size_t i = 0; i < n * n; ++i) {
    for (std::size_t k = 0; k < n; ++k) {
      std::snprintf(line, sizeof(line), "%13.5E", rng.range(-1.0, 1.0) * 0.05);
      out += line;
      if ((k + 1) % 6 == 0 || k + 1 == n)
        out += '\n';
    }
  }
  return out;
}

bool readFile(const fs::path& path, std::string& text)
{
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in)
    return false;
  std::ostringstream buffer;
  buffer << in.rdbuf();
  text = buffer.str();
  return true;
}

// Writes synthetic text to the work directory, then reads it back so the
// benchmark input is exactly what is on disk.
bool stageSynthetic(const Options& o, const std::string& name,
                    std::string& text, std::vector<fs::path>& created)
{
  std::error_code ec;
  fs::create_directories(o.workDir, ec);
  const fs::path path = fs::path(o.workDir) / name;
  {
    std::ofstream out(path, std::ios::out | std::ios::binary);
    if (!out)
      return false;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out)
      return false;
  }
  created.push_back(path);
  std::string back;
  if (!readFile(path, back))
    return false;
  text.swap(back);
  return true;
}

std::string lowerExtension(const fs::path& path)
{
  std::string ext = path.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return ext;
}

bool readInto(Kind kind, const std::string& text, Molecule& mol,
              std::string& error)
{
  bool ok = false;
  switch (kind) {
    case Kind::Xyz:
    case Kind::Traj: {
      Avogadro::Io::XyzFormat format;
      ok = format.readString(text, mol);
      if (!ok)
        error = format.error();
      break;
    }
    case Kind::Fchk: {
      Avogadro::QuantumIO::GaussianFchk format;
      ok = format.readString(text, mol);
      if (!ok)
        error = format.error();
      break;
    }
    case Kind::Cube: {
      Avogadro::QuantumIO::GaussianCube format;
      ok = format.readString(text, mol);
      if (!ok)
        error = format.error();
      break;
    }
    case Kind::Split:
      break;
  }
  return ok;
}

Checksum checksumOf(const Molecule& mol)
{
  Checksum c;
  c.atoms = mol.atomCount();
  for (const auto z : mol.atomicNumbers())
    c.atomicNumberSum += z;
  const std::size_t sets = mol.coordinate3dCount();
  c.frames = sets;
  if (sets == 0) {
    for (const auto& p : mol.atomPositions3d())
      c.coordSum += p.x() + p.y() + p.z();
  } else {
    for (std::size_t s = 0; s < sets; ++s)
      for (const auto& p : mol.coordinate3d(s))
        c.coordSum += p.x() + p.y() + p.z();
  }
  if (mol.cubeCount() > 0) {
    const auto* values = mol.cube(0)->data();
    c.values = values->size();
    for (const float v : *values)
      c.valueSum += static_cast<double>(v);
  }
  if (const auto* gaussian = dynamic_cast<const GaussianSet*>(mol.basisSet())) {
    c.basisFunctions = gaussian->molecularOrbitalCount();
    const auto mo = gaussian->moMatrix();
    c.moRows = static_cast<std::size_t>(mo.rows());
    c.moCols = static_cast<std::size_t>(mo.cols());
    for (Eigen::Index j = 0; j < mo.cols(); ++j)
      for (Eigen::Index i = 0; i < mo.rows(); ++i)
        c.moSum += mo(i, j);
  }
  return c;
}

// Tokenizing variants for the "split" case. Each takes the whole XYZ text and
// returns a checksum; add a new entry to the table to compare another path.
struct SplitSum
{
  std::size_t tokens = 0;
  std::size_t lines = 0;
  double coordSum = 0.0;
};

SplitSum splitCurrent(const std::string& text)
{
  SplitSum sum;
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t end = text.find('\n', pos);
    if (end == std::string::npos)
      end = text.size();
    const std::string line = text.substr(pos, end - pos);
    pos = end + 1;
    const auto tokens = Avogadro::Core::split(line, ' ');
    sum.tokens += tokens.size();
    ++sum.lines;
    if (tokens.size() < 4)
      continue;
    for (std::size_t i = 1; i < 4; ++i)
      sum.coordSum +=
        Avogadro::Core::lexicalCast<double>(tokens[i]).value_or(0.0);
  }
  return sum;
}

struct SplitVariant
{
  const char* name;
  std::function<SplitSum(const std::string&)> run;
};

std::vector<SplitVariant> splitVariants()
{
  return { { "split+lexicalCast", splitCurrent } };
}

double toMs(Clock::time_point a, Clock::time_point b)
{
  return std::chrono::duration<double, std::milli>(b - a).count();
}

Result runReader(Input& input, const Options& o)
{
  Result r;
  r.input = &input;
  r.caseName = input.caseName;
  std::unique_ptr<Molecule> last;
  for (std::size_t i = 0; i < o.warmup + o.iterations; ++i) {
    auto mol = std::make_unique<Molecule>();
    std::string error;
    const auto start = Clock::now();
    const bool ok = readInto(input.kind, input.text, *mol, error);
    const auto stop = Clock::now();
    if (!ok) {
      r.error = error.empty() ? "read failed" : error;
      return r;
    }
    if (i >= o.warmup)
      r.samplesMs.push_back(toMs(start, stop));
    last = std::move(mol);
  }
  r.checksum = checksumOf(*last);
  r.count = input.kind == Kind::Cube
              ? r.checksum.values
              : std::max<std::size_t>(r.checksum.frames, 1);
  r.ok = true;
  return r;
}

Result runSplit(Input& input, const SplitVariant& variant, const Options& o)
{
  Result r;
  r.input = &input;
  r.caseName = std::string("split:") + variant.name;
  SplitSum sum;
  for (std::size_t i = 0; i < o.warmup + o.iterations; ++i) {
    const auto start = Clock::now();
    sum = variant.run(input.text);
    const auto stop = Clock::now();
    if (i >= o.warmup)
      r.samplesMs.push_back(toMs(start, stop));
  }
  r.checksum.atoms = sum.lines;
  r.checksum.values = sum.tokens;
  r.checksum.coordSum = sum.coordSum;
  r.count = sum.lines;
  r.ok = true;
  return r;
}

struct Stats
{
  double best = 0.0, median = 0.0, mean = 0.0;
};

Stats computeStats(std::vector<double> s)
{
  Stats st;
  if (s.empty())
    return st;
  std::sort(s.begin(), s.end());
  st.best = s.front();
  const std::size_t n = s.size();
  st.median = n % 2 == 0 ? (s[n / 2 - 1] + s[n / 2]) * 0.5 : s[n / 2];
  st.mean = std::accumulate(s.begin(), s.end(), 0.0) / static_cast<double>(n);
  return st;
}

} // namespace

int main(int argc, char** argv)
{
  Options o;
  if (!parseArgs(argc, argv, o))
    return 1;

  const bool all = o.caseName == "all";
  const auto wants = [&](const char* name) {
    return all || o.caseName == name;
  };

  std::vector<Input> inputs;
  std::vector<fs::path> created;
  std::vector<std::string> skipped;
  int exitCode = 0;

  auto addSynthetic = [&](const char* caseName, const std::string& name,
                          Kind kind, std::string text) {
    if (!stageSynthetic(o, name, text, created)) {
      std::cerr << "Unable to stage " << name << " in " << o.workDir << "\n";
      exitCode = 3;
      return;
    }
    inputs.push_back({ caseName, name, kind, std::move(text) });
  };
  auto addData = [&](const char* caseName, const std::string& rel, Kind kind) {
    std::string text;
    const fs::path path = resolvePath(o.dataRoot, rel);
    if (!readFile(path, text)) {
      skipped.push_back("Skipping " + path.string() + " (not found)");
      return;
    }
    inputs.push_back({ caseName, path.filename().string(), kind, text });
  };

  std::string xyzText;
  if (wants("xyz") || wants("split")) {
    xyzText = makeXyz(o.xyzAtoms, 1);
    std::string staged = xyzText;
    const std::string name = "synthetic-" + std::to_string(o.xyzAtoms) + ".xyz";
    if (wants("xyz"))
      addSynthetic("xyz", name, Kind::Xyz, staged);
    if (wants("split"))
      inputs.push_back({ "split", name, Kind::Split, xyzText });
  }
  if (wants("traj"))
    addSynthetic("traj",
                 "synthetic-" + std::to_string(o.trajAtoms) + "x" +
                   std::to_string(o.trajFrames) + ".xyz",
                 Kind::Traj, makeXyz(o.trajAtoms, o.trajFrames));
  if (wants("fchk")) {
    addData("fchk", "data/fchk/c60.fchk", Kind::Fchk);
    addData("fchk", "data/fchk/c240.fchk", Kind::Fchk);
  }
  if (wants("cube")) {
    addSynthetic("cube", "synthetic-" + std::to_string(o.cubePoints) + ".cube",
                 Kind::Cube, makeCube(o.cubePoints));
    addData("cube", "data/cube/benzene-homo.cube", Kind::Cube);
  }
  for (const auto& f : o.files) {
    const fs::path path = resolvePath(o.dataRoot, f);
    const std::string ext = lowerExtension(path);
    Kind kind;
    if (ext == ".xyz")
      kind = Kind::Xyz;
    else if (ext == ".fchk" || ext == ".fch")
      kind = Kind::Fchk;
    else if (ext == ".cube" || ext == ".cub")
      kind = Kind::Cube;
    else {
      std::cerr << "Unrecognized extension for " << f << "\n";
      exitCode = 3;
      continue;
    }
    std::string text;
    if (!readFile(path, text)) {
      std::cerr << "Unable to read " << path.string() << "\n";
      exitCode = 3;
      continue;
    }
    inputs.push_back({ "file", path.filename().string(), kind, text });
  }

  for (const auto& s : skipped)
    std::cout << s << "\n";

  std::cout << "Parse benchmark: warmup " << o.warmup << ", iterations "
            << o.iterations << ", data root " << o.dataRoot << "\n";

  std::vector<Result> results;
  const auto variants = splitVariants();
  for (auto& input : inputs) {
    std::cout << "  running " << input.label << " (" << input.caseName << ")..."
              << std::flush;
    if (input.kind == Kind::Split) {
      for (const auto& v : variants) {
        results.push_back(runSplit(input, v, o));
      }
    } else {
      results.push_back(runReader(input, o));
    }
    std::cout << " done\n";
  }

  std::cout << "\n"
            << std::left << std::setw(26) << "Case" << std::setw(28) << "File"
            << std::right << std::setw(9) << "MB" << std::setw(10) << "Atoms"
            << std::setw(12) << "Frm/Pts" << std::setw(11) << "Best ms"
            << std::setw(11) << "Median ms" << std::setw(11) << "Mean ms"
            << std::setw(10) << "MB/s"
            << "\n"
            << std::string(128, '-') << "\n";
  for (const auto& r : results) {
    const auto& in = *r.input;
    if (!r.ok) {
      std::cout << std::left << std::setw(26) << r.caseName << std::setw(28)
                << in.label << "  ERROR: " << r.error << "\n";
      exitCode = 2;
      continue;
    }
    const Stats st = computeStats(r.samplesMs);
    const double mb = static_cast<double>(in.text.size()) / 1.0e6;
    const double mbps = st.best > 0.0 ? mb / (st.best / 1000.0) : 0.0;
    std::cout << std::left << std::setw(26) << r.caseName << std::setw(28)
              << in.label << std::right << std::fixed << std::setprecision(2)
              << std::setw(9) << mb << std::setw(10) << r.checksum.atoms
              << std::setw(12) << r.count << std::setprecision(1)
              << std::setw(11) << st.best << std::setw(11) << st.median
              << std::setw(11) << st.mean << std::setw(10) << mbps << "\n";
  }

  std::cout << "\nChecksums\n";
  char buf[512];
  for (const auto& r : results) {
    if (!r.ok)
      continue;
    const auto& c = r.checksum;
    const auto& in = *r.input;
    if (in.kind == Kind::Split) {
      std::snprintf(buf, sizeof(buf), "lines=%zu tokens=%zu coordSum=%.17g",
                    c.atoms, c.values, c.coordSum);
    } else {
      int n = std::snprintf(buf, sizeof(buf),
                            "atoms=%zu sumZ=%llu coordSum=%.17g frames=%zu",
                            c.atoms, c.atomicNumberSum, c.coordSum, c.frames);
      if (in.kind == Kind::Cube && n > 0 &&
          static_cast<std::size_t>(n) < sizeof(buf))
        std::snprintf(buf + n, sizeof(buf) - static_cast<std::size_t>(n),
                      " cubeValues=%zu cubeSum=%.17g", c.values, c.valueSum);
      if (in.kind == Kind::Fchk && n > 0 &&
          static_cast<std::size_t>(n) < sizeof(buf))
        std::snprintf(buf + n, sizeof(buf) - static_cast<std::size_t>(n),
                      " basisFns=%zu moMatrix=%zux%zu moSum=%.17g",
                      c.basisFunctions, c.moRows, c.moCols, c.moSum);
    }
    std::cout << "  " << r.caseName << " " << in.label << ": " << buf << "\n";
  }

  if (!o.keepFiles) {
    std::error_code ec;
    for (const auto& p : created)
      fs::remove(p, ec);
    fs::remove(o.workDir, ec); // only succeeds if empty
  } else if (!created.empty()) {
    std::cout << "\nKept synthetic files in " << o.workDir << "\n";
  }
  return exitCode;
}
