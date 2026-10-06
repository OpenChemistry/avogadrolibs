/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiancube.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>

namespace Avogadro::QuantumIO {

namespace {
constexpr int kMaxCubeDim = 1024;
constexpr int kMaxAtomCount = 1000000;
constexpr unsigned int kMaxCubeCount = 128;
constexpr size_t kMaxCubeValues = 64ull * 1024 * 1024;       // 64M values
constexpr size_t kMaxTotalCubeValues = 128ull * 1024 * 1024; // 128M values

bool hasMinimumRemainingBytes(std::istream& in, size_t minBytes)
{
  auto pos = in.tellg();
  if (pos == std::streampos(-1))
    return true;

  in.clear();
  in.seekg(0, std::ios::end);
  auto end = in.tellg();
  in.seekg(pos);
  if (end == std::streampos(-1))
    return true;

  const size_t remaining = static_cast<size_t>(end - pos);
  return remaining >= minBytes;
}

/**
 * Reads the grid values of a cube file one at a time.
 *
 * Extracting straight into a float discards valid files: strtof reports an
 * underflow to subnormal as ERANGE, and the extractor turns that into failbit
 * even though the value parsed correctly. Codes such as Q-Chem write the
 * decaying tail of a density with exponents past FLT_MIN ("1.505124610E-39"),
 * which would abort the read a handful of values from the end.
 *
 * Parse each token with Core::parseFloat instead. It is the parser behind
 * Core::lexicalCast<float>, so a range error is handled the same way here --
 * underflow gives zero or a subnormal, overflow is clamped -- but it works
 * on the token in place, which matters for a loop that runs once per grid
 * point. It is also independent of the C locale: strtod is not, and Qt sets
 * that locale from the environment, so under a comma-decimal locale every
 * cube file failed to read.
 *
 * CP2K writes the grid with Fortran E13.5 edit descriptors, which leave no
 * separator in front of a negative number and use three digit exponents:
 * " 0.26189E-002-0.85098E-002-0.14043E-001". A whitespace token can therefore
 * hold several values. When a number stops short at a '+' or '-', the rest of
 * the token is kept for the next call, but only if the number just parsed
 * has an explicit exponent letter (E, e, D or d). Fortran drops the letter
 * when the exponent needs three digits ("0.12345-102" is 1.2345e-103 in
 * Ew.d output), so a sign after a bare mantissa is ambiguous: splitting it
 * would silently shift every later value. It is rejected instead.
 */
class CubeValueReader
{
public:
  explicit CubeValueReader(std::istream& stream) : m_in(stream) {}

  bool read(float& value)
  {
    if (m_pos == m_end) {
      if (!(m_in >> m_token))
        return false;
      m_pos = m_token.data();
      m_end = m_pos + m_token.size();
    }

    // Reject anything that is not a number, or that stopped short of the end
    // of the token other than at a run-together sign ("1.5abc", the "*******"
    // some codes emit on overflow). The literals "nan" and "inf" have no
    // meaning on a grid and are refused by the parser.
    const char* stop = Core::parseFloat(m_pos, m_end, value);
    if (stop == nullptr)
      return false;
    if (stop != m_end) {
      const char next = *stop;
      if (next != '+' && next != '-')
        return false;
      bool hasExponent = false;
      for (const char* c = m_pos; c != stop; ++c)
        if (*c == 'E' || *c == 'e' || *c == 'D' || *c == 'd')
          hasExponent = true;
      if (!hasExponent)
        return false;
    }
    m_pos = stop;
    return true;
  }

private:
  std::istream& m_in;
  std::string m_token;
  const char* m_pos = nullptr;
  const char* m_end = nullptr;
};
/**
 * Where a skewed cube is resampled to.
 *
 * Core::Cube stores an origin and one spacing per axis, so it can only hold a
 * grid whose axes are aligned with x, y and z. The format allows each voxel
 * axis to be an arbitrary vector (CP2K writes the cell vectors of a
 * triclinic cell this way), and silently keeping only the diagonal of each
 * vector draws a sheared isosurface. Until Cube carries a full 3x3 step
 * matrix, such a grid is resampled onto an axis-aligned one while it is read.
 */
struct ResamplePlan
{
  Matrix3 inverseSteps; // maps a position offset to fractional grid indices
  Vector3 origin;       // position of source grid point (0, 0, 0), in Angstrom
  Vector3 targetMin;    // position of target grid point (0, 0, 0)
  Vector3i targetDim;   // number of target points along x, y, z
  double targetSpacing; // isotropic target spacing, in Angstrom
};

// A step vector counts as lying along its own axis when its other components
// are no larger than this fraction of its length. Real files are rounded to
// six decimals, so this only separates axis-aligned grids from skewed ones.
constexpr double kAxisAlignedTolerance = 1.0e-6;

// An axis with a single point never steps along its vector, so its step is
// ignored: files often write zero for it (a plane or a line of values).
bool isAxisAligned(const Matrix3& steps, const Vector3i& dim)
{
  for (int i = 0; i < 3; ++i) {
    if (dim(i) == 1)
      continue;
    const double length = steps.col(i).norm();
    if (!(steps(i, i) > 0.0))
      return false;
    for (int j = 0; j < 3; ++j)
      if (j != i && std::abs(steps(j, i)) > kAxisAlignedTolerance * length)
        return false;
  }
  return true;
}

/**
 * Chooses the axis-aligned grid that encloses a skewed one.
 *
 * @param steps Step vectors as columns, in Angstrom.
 * @param dim Number of points along each step vector.
 * @param origin Position of the first grid point, in Angstrom.
 * @param maxPoints Largest number of target points to allow.
 *
 * The target is the bounding box of the eight corners of the source grid.
 * Its spacing is the shortest step, so no resolution is lost, and is
 * increased if that would give more than @p maxPoints points.
 */
/**
 * Replaces the step of each single-point axis with a unit vector (Angstrom)
 * orthogonal to the steps of the other axes, so that whatever the file wrote
 * for it cannot make the matrix singular or change the target spacing.
 */
Matrix3 effectiveSteps(const Matrix3& steps, const Vector3i& dim)
{
  Matrix3 result = steps;
  // Orthonormal basis of the columns fixed so far.
  Vector3 basis[3];
  int count = 0;
  auto residual = [&](Vector3 v) {
    for (int k = 0; k < count; ++k)
      v -= basis[k].dot(v) * basis[k];
    return v;
  };
  for (int i = 0; i < 3; ++i) {
    if (dim(i) == 1)
      continue;
    const Vector3 v = residual(steps.col(i));
    const double length = v.norm();
    if (count < 3 && length > 1.0e-6 * steps.col(i).norm())
      basis[count++] = v / length;
  }
  for (int i = 0; i < 3; ++i) {
    if (dim(i) != 1)
      continue;
    // Prefer this axis' own direction; one of the three always has a
    // residual of at least 1/sqrt(3) against at most two basis vectors.
    Vector3 best = Vector3::Zero();
    for (int k = 0; k < 3; ++k) {
      const Vector3 v = residual(Vector3::Unit((i + k) % 3));
      if (v.norm() > best.norm() + 1.0e-12)
        best = v;
    }
    best.normalize();
    result.col(i) = best;
    if (count < 3)
      basis[count++] = best;
  }
  return result;
}

bool planResample(const Matrix3& fileSteps, const Vector3i& dim,
                  const Vector3& origin, size_t maxPoints, ResamplePlan& plan)
{
  if (!fileSteps.allFinite() || !origin.allFinite())
    return false;
  const Matrix3 steps = effectiveSteps(fileSteps, dim);
  if (!steps.allFinite())
    return false;

  // A (nearly) singular matrix has no inverse to map positions back to the
  // source grid with: the three axes are not independent.
  const double lengths =
    steps.col(0).norm() * steps.col(1).norm() * steps.col(2).norm();
  const double det = steps.determinant();
  if (!std::isfinite(lengths) || !std::isfinite(det) ||
      !(std::abs(det) > 1.0e-6 * lengths))
    return false;

  Vector3 lo = origin;
  Vector3 hi = origin;
  for (int corner = 0; corner < 8; ++corner) {
    Vector3 r = origin;
    for (int i = 0; i < 3; ++i)
      if (corner & (1 << i))
        r += steps.col(i) * static_cast<double>(dim(i) - 1);
    lo = lo.cwiseMin(r);
    hi = hi.cwiseMax(r);
  }
  const Vector3 extent = hi - lo;
  // Only axes with more than one point have a resolution to keep.
  double h = std::numeric_limits<double>::infinity();
  for (int i = 0; i < 3; ++i)
    if (dim(i) > 1)
      h = std::min(h, steps.col(i).norm());
  if (std::isinf(h))
    h = 1.0; // a single point: any spacing will do
  if (!extent.allFinite() || !std::isfinite(h) || !(h > 1.0e-9))
    return false;

  // Grow the spacing until the grid fits. Each pass overshoots slightly so
  // the rounding of the point counts cannot keep it just over the limit.
  const double limit = static_cast<double>(maxPoints);
  Vector3 counts;
  for (int pass = 0; pass < 100; ++pass) {
    for (int i = 0; i < 3; ++i)
      counts(i) = std::floor(extent(i) / h + 1.0e-6) + 1.0;
    const double total = counts(0) * counts(1) * counts(2);
    if (!std::isfinite(total))
      return false;
    if (total <= limit)
      break;
    h *= std::max(1.001, std::cbrt(total / limit) * 1.0001);
    if (pass == 99)
      return false;
  }

  plan.inverseSteps = steps.inverse();
  if (!plan.inverseSteps.allFinite())
    return false;
  plan.origin = origin;
  plan.targetMin = lo;
  plan.targetSpacing = h;
  for (int i = 0; i < 3; ++i)
    plan.targetDim(i) = static_cast<int>(counts(i));
  return true;
}

/**
 * Trilinear resampling of @p source (z fastest, as Core::Cube stores it) onto
 * the grid in @p plan. Target points outside the source grid get zero; the
 * grid is not periodic, since a cube file does not say it is.
 */
void resample(const std::vector<float>& source, const Vector3i& dim,
              const ResamplePlan& plan, std::vector<float>& target)
{
  const size_t ny = static_cast<size_t>(dim(1));
  const size_t nz = static_cast<size_t>(dim(2));
  const Vector3 upper(dim(0) - 1, dim(1) - 1, dim(2) - 1);
  // Allow for rounding at the faces of the source grid, where the target grid
  // often has points exactly on the boundary.
  constexpr double kEdge = 1.0e-7;

  // Fractional source index of a target point is linear in its indices, so
  // only the increments along each target axis are needed.
  const Vector3 stepX = plan.inverseSteps.col(0) * plan.targetSpacing;
  const Vector3 stepY = plan.inverseSteps.col(1) * plan.targetSpacing;
  const Vector3 stepZ = plan.inverseSteps.col(2) * plan.targetSpacing;
  const Vector3 start = plan.inverseSteps * (plan.targetMin - plan.origin);

  size_t out = 0;
  for (int ix = 0; ix < plan.targetDim(0); ++ix) {
    for (int iy = 0; iy < plan.targetDim(1); ++iy) {
      const Vector3 rowStart = start + stepX * ix + stepY * iy;
      for (int iz = 0; iz < plan.targetDim(2); ++iz, ++out) {
        const Vector3 u = rowStart + stepZ * iz;
        if (u(0) < -kEdge || u(1) < -kEdge || u(2) < -kEdge ||
            u(0) > upper(0) + kEdge || u(1) > upper(1) + kEdge ||
            u(2) > upper(2) + kEdge) {
          target[out] = 0.0f;
          continue;
        }
        const Vector3 c = u.cwiseMax(0.0).cwiseMin(upper);
        const size_t i0 =
          std::min(static_cast<size_t>(c(0)), static_cast<size_t>(dim(0) - 1));
        const size_t j0 =
          std::min(static_cast<size_t>(c(1)), static_cast<size_t>(dim(1) - 1));
        const size_t k0 =
          std::min(static_cast<size_t>(c(2)), static_cast<size_t>(dim(2) - 1));
        const size_t i1 = std::min(i0 + 1, static_cast<size_t>(dim(0) - 1));
        const size_t j1 = std::min(j0 + 1, static_cast<size_t>(dim(1) - 1));
        const size_t k1 = std::min(k0 + 1, static_cast<size_t>(dim(2) - 1));
        const double fx = c(0) - static_cast<double>(i0);
        const double fy = c(1) - static_cast<double>(j0);
        const double fz = c(2) - static_cast<double>(k0);

        auto at = [&](size_t i, size_t j, size_t k) {
          return static_cast<double>(source[(i * ny + j) * nz + k]);
        };
        const double c00 = at(i0, j0, k0) * (1.0 - fz) + at(i0, j0, k1) * fz;
        const double c01 = at(i0, j1, k0) * (1.0 - fz) + at(i0, j1, k1) * fz;
        const double c10 = at(i1, j0, k0) * (1.0 - fz) + at(i1, j0, k1) * fz;
        const double c11 = at(i1, j1, k0) * (1.0 - fz) + at(i1, j1, k1) * fz;
        const double c0 = c00 * (1.0 - fy) + c01 * fy;
        const double c1 = c10 * (1.0 - fy) + c11 * fy;
        target[out] = static_cast<float>(c0 * (1.0 - fx) + c1 * fx);
      }
    }
  }
}
} // namespace

GaussianCube::GaussianCube() {}

GaussianCube::~GaussianCube() {}

std::vector<std::string> GaussianCube::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("cube");
  return extensions;
}

std::vector<std::string> GaussianCube::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GaussianCube::read(std::istream& in, Core::Molecule& molecule)
{
  // Variables we will need
  std::string line;
  std::vector<std::string> list;

  int nAtoms;
  Vector3 min;
  Vector3 spacing;
  Vector3i dim;
  Matrix3 steps = Matrix3::Zero(); // voxel step vectors as columns (bohr)

  // Gaussian Cube format is very specific

  // Read and set name
  if (!Core::getLine(in, line)) {
    appendError("Invalid cube header.");
    return false;
  }
  molecule.setData("name", line);

  // Read and skip field title (we may be able to use this to setCubeType in the
  // future)
  if (!Core::getLine(in, line)) {
    appendError("Invalid cube header.");
    return false;
  }

  // Next line contains nAtoms and m_min
  if (!(in >> nAtoms)) {
    appendError("Invalid cube header.");
    return false;
  }
  for (unsigned int i = 0; i < 3; ++i)
    if (!(in >> min(i))) {
      appendError("Invalid cube header.");
      return false;
    }
  if (!Core::getLine(in, line)) { // capture newline before continuing
    appendError("Invalid cube header.");
    return false;
  }

  if (nAtoms == std::numeric_limits<int>::min()) {
    appendError("Invalid atom count in cube file.");
    return false;
  }
  const int atomCount = nAtoms < 0 ? -nAtoms : nAtoms;
  if (atomCount > kMaxAtomCount) {
    appendError("Invalid atom count in cube file.");
    return false;
  }

  // Next 3 lines contains spacing and dim
  for (unsigned int i = 0; i < 3; ++i) {
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube header.");
      return false;
    }
    line = Core::trimmed(line);
    if (line.empty()) {
      appendError("Invalid cube header.");
      return false;
    }
    list = Core::split(line, ' ');
    if (list.size() < 4) {
      appendError("Invalid cube grid specification.");
      return false;
    }
    dim(i) = Core::lexicalCast<int>(list[0]).value_or(0);
    // The three components of the step vector along this grid axis.
    for (unsigned int j = 0; j < 3; ++j)
      steps(j, i) = Core::lexicalCast<double>(list[j + 1]).value_or(0.0);
    spacing(i) = steps(i, i);
    if (dim(i) <= 0 || dim(i) > kMaxCubeDim) {
      appendError("Invalid cube grid dimension.");
      return false;
    }
  }

  const size_t d0 = static_cast<size_t>(dim(0));
  const size_t d1 = static_cast<size_t>(dim(1));
  const size_t d2 = static_cast<size_t>(dim(2));
  const size_t maxSize = std::numeric_limits<size_t>::max();
  if (d0 == 0 || d1 == 0 || d2 == 0 || d0 > maxSize / d1 ||
      d0 * d1 > maxSize / d2) {
    appendError("Invalid cube data dimensions.");
    return false;
  }
  const size_t valueCount = d0 * d1 * d2;
  if (valueCount > kMaxCubeValues) {
    appendError("Cube data exceeds supported size.");
    return false;
  }

  // Geometry block
  Vector3 pos;
  for (int i = 0; i < atomCount; ++i) {
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube atom data.");
      return false;
    }
    line = Core::trimmed(line);
    if (line.empty()) {
      appendError("Invalid cube atom data.");
      return false;
    }
    list = Core::split(line, ' ');
    if (list.size() < 5) {
      appendError("Invalid cube atom data.");
      return false;
    }
    auto atomNum = Core::lexicalCast<short int>(list[0]).value_or(0);
    Core::Atom a = molecule.addAtom(static_cast<unsigned char>(atomNum));
    for (unsigned int j = 2; j < 5; ++j)
      pos(j - 2) = Core::lexicalCast<double>(list[j]).value_or(0.0);
    pos = pos * BOHR_TO_ANGSTROM;
    a.setPosition3d(pos);
  }

  // If the nAtoms were negative there is another line before
  // the data which is necessary, maybe contain 1 or more cubes
  unsigned int nCubes = 1;
  if (nAtoms < 0) {
    if (!(in >> nCubes) || nCubes == 0) {
      appendError("Invalid cube count.");
      return false;
    }
    if (nCubes > kMaxCubeCount) {
      appendError("Invalid cube count.");
      return false;
    }
    if (valueCount > 0 && nCubes > kMaxTotalCubeValues / valueCount) {
      appendError("Cube data exceeds supported size.");
      return false;
    }
    std::vector<unsigned int> moList(nCubes);
    for (unsigned int i = 0; i < nCubes; ++i)
      if (!(in >> moList[i])) {
        appendError("Invalid cube MO list.");
        return false;
      }
    // clear buffer
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube header.");
      return false;
    }
  }

  // Render molecule
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();

  // Cube block, set limits and populate data
  // min and spacing are in bohr units, convert to ANGSTROM
  min *= BOHR_TO_ANGSTROM;
  spacing *= BOHR_TO_ANGSTROM;
  steps *= BOHR_TO_ANGSTROM;

  const size_t cubeCount = static_cast<size_t>(nCubes);
  if (valueCount > 0 && cubeCount > maxSize / valueCount) {
    appendError("Cube data exceeds supported size.");
    return false;
  }
  if (!hasMinimumRemainingBytes(in, valueCount * cubeCount)) {
    appendError("Invalid cube data.");
    return false;
  }

  // Voxel axes that are not along x, y and z (or point backwards) cannot be
  // stored in a Core::Cube as they are: resample them onto an axis-aligned
  // grid (see ResamplePlan). Everything else is read as is.
  const bool skewed = !isAxisAligned(steps, dim);
  // A single-point axis may have a zero step, which Core::Cube rejects; its
  // spacing is never used, so any positive value will do.
  for (int i = 0; i < 3; ++i)
    if (dim(i) == 1 && !(spacing(i) > 0.0))
      spacing(i) = 1.0;
  ResamplePlan plan;
  std::vector<float> source;
  if (skewed) {
    const size_t maxPoints =
      std::min(kMaxCubeValues, kMaxTotalCubeValues / cubeCount);
    if (!planResample(steps, dim, min, maxPoints, plan)) {
      appendError("Invalid cube grid specification: the voxel axes are "
                  "degenerate or the resampled grid is too large.");
      return false;
    }
    source.resize(valueCount);
  }

  for (unsigned int i = 0; i < nCubes; ++i) {
    // Get a cube object from molecule
    Core::Cube* cube = molecule.addCube();
    cube->setCubeType(Core::Cube::Type::FromFile);

    if (skewed) {
      CubeValueReader reader(in);
      for (size_t index = 0; index < valueCount; ++index) {
        if (!reader.read(source[index])) {
          appendError("Invalid cube data.");
          return false;
        }
      }
      if (!cube->setLimits(plan.targetMin, plan.targetDim,
                           Vector3::Constant(plan.targetSpacing))) {
        appendError("Invalid cube grid specification.");
        return false;
      }
      auto* target = cube->data();
      if (!target) {
        appendError("Invalid cube data.");
        return false;
      }
      resample(source, dim, plan, *target);
      if (!cube->setData(*target)) {
        appendError("Invalid cube data.");
        return false;
      }
      // clear buffer, if more than one cube
      if (!Core::getLine(in, line) && i + 1 < nCubes) {
        appendError("Invalid cube data.");
        return false;
      }
      continue;
    }

    cube->setLimits(min, dim, spacing);
    auto* values = cube->data();
    if (!values) {
      appendError("Invalid cube data.");
      return false;
    }
    if (values->size() != valueCount)
      values->resize(valueCount);
    CubeValueReader reader(in);
    for (size_t index = 0; index < valueCount; ++index) {
      if (!reader.read((*values)[index])) {
        appendError("Invalid cube data.");
        return false;
      }
    }
    if (!cube->setData(*values)) {
      appendError("Invalid cube data.");
      return false;
    }
    // clear buffer, if more than one cube
    if (!Core::getLine(in, line) && i + 1 < nCubes) {
      appendError("Invalid cube data.");
      return false;
    }
  }

  return true;
}

void writeFixedFloat(std::ostream& outStream, Real number)
{
  outStream << std::setw(12) << std::fixed << std::right << std::setprecision(6)
            << number;
}

void writeFixedInt(std::ostream& outStream, unsigned int number)
{
  outStream << std::setw(5) << std::fixed << std::right << number;
}

bool GaussianCube::write(std::ostream& outStream, const Core::Molecule& mol)
{
  if (mol.cubeCount() == 0)
    return false; // no cubes to write

  const Core::Cube* cube =
    mol.cube(0); // eventually need to write all the cubes
  Vector3 min = cube->min() * ANGSTROM_TO_BOHR;
  Vector3 spacing = cube->spacing() * ANGSTROM_TO_BOHR;
  Vector3i dim = cube->dimensions(); // number of points in each direction

  // might be useful to use the 2nd line, but it's just a comment
  // e.g. write out the cube type
  outStream << "Gaussian Cube file generated by Avogadro.\n";
  if (mol.data("name").toString().length())
    outStream << mol.data("name").toString() << "\n";
  else
    outStream << "\n";

  // Write out the number of atoms and the minimum coordinates
  size_t numAtoms = mol.atomCount();
  writeFixedInt(outStream, numAtoms);
  writeFixedFloat(outStream, min[0]);
  writeFixedFloat(outStream, min[1]);
  writeFixedFloat(outStream, min[2]);
  writeFixedInt(outStream, 1); // one value per point (i.e., not vector)
  outStream << "\n";

  // now write the size and spacing of the cube
  writeFixedInt(outStream, dim[0]);
  writeFixedFloat(outStream, spacing[0]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, 0.0);
  outStream << "\n";

  writeFixedInt(outStream, dim[1]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, spacing[1]);
  writeFixedFloat(outStream, 0.0);
  outStream << "\n";

  writeFixedInt(outStream, dim[2]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, spacing[2]);
  outStream << "\n";

  for (size_t i = 0; i < numAtoms; ++i) {
    Core::Atom atom = mol.atom(i);
    if (!atom.isValid()) {
      appendError("Internal error: Atom invalid.");
      return false;
    }

    writeFixedInt(outStream, static_cast<int>(atom.atomicNumber()));
    writeFixedFloat(outStream, 0.0); // charge
    writeFixedFloat(outStream, atom.position3d()[0] * ANGSTROM_TO_BOHR);
    writeFixedFloat(outStream, atom.position3d()[1] * ANGSTROM_TO_BOHR);
    writeFixedFloat(outStream, atom.position3d()[2] * ANGSTROM_TO_BOHR);
    outStream << "\n";
  }

  // write the raw cube values
  const std::vector<float>* values = cube->data();
  for (unsigned int i = 0; i < values->size(); ++i) {
    outStream << std::setw(13) << std::right << std::scientific
              << std::setprecision(5) << (*values)[i];
    if (i % 6 == 5)
      outStream << "\n";
  }

  return true;
}

} // namespace Avogadro::QuantumIO
