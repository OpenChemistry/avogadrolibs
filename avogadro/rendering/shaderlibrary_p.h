/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SHADERLIBRARY_P_H
#define AVOGADRO_RENDERING_SHADERLIBRARY_P_H

#include "avogadrorenderingexport.h"

#include <array>
#include <memory>

namespace Avogadro::Rendering {

class ShaderProgram;

/**
 * The shader programs the drawables share. Every id names one vertex and one
 * fragment shader that are built into the library.
 */
enum class ShaderId : unsigned char
{
  Spheres,
  Cylinders,
  Mesh, // Also used by ArrowGeometry.
  Curves,
  TextLabel,
  LineStrip,
  WideLine,
  DashedLine,
  Count // Not a shader: the number of ids.
};

/**
 * @class ShaderLibrary shaderlibrary_p.h
 * @brief Compiles, links and caches the drawables' shader programs for one GL
 * context.
 *
 * Programs are built on first use, so the owning context must be current when
 * program() is called. A program that failed to build is reported once and is
 * not tried again until releaseResources().
 *
 * Private to the rendering library: the header is not installed. The class is
 * exported only so that the unit tests can link against it.
 */
class AVOGADRORENDERING_EXPORT ShaderLibrary
{
public:
  ShaderLibrary();

  /** Calls releaseResources(), which does nothing if there is nothing to
   * release. Release the programs while the context is current. */
  ~ShaderLibrary();

  ShaderLibrary(const ShaderLibrary&) = delete;
  ShaderLibrary& operator=(const ShaderLibrary&) = delete;

  /**
   * The linked program for @p id, built on the first request.
   * @return nullptr if the program could not be built. The compile or link
   * error is printed the first time only.
   */
  ShaderProgram* program(ShaderId id);

  /**
   * Delete every program, and forget failures so that the next request
   * tries again. The GL context the programs belong to must be current.
   */
  void releaseResources();

  /**
   * Forget every program without any GL call, and forget failures. For a
   * context that is gone: its program names mean nothing anywhere else.
   */
  void abandonResources();

private:
  struct Entry
  {
    std::unique_ptr<ShaderProgram> program;
    bool failed = false;
  };
  std::array<Entry, static_cast<std::size_t>(ShaderId::Count)> m_entries;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_SHADERLIBRARY_P_H
