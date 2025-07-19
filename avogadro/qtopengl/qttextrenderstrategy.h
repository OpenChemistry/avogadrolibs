/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_QTTEXTRENDERSTRATEGY_H
#define AVOGADRO_QTGUI_QTTEXTRENDERSTRATEGY_H

#include "avogadroqtopenglexport.h"
#include <avogadro/rendering/textrenderstrategy.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtOpenGL {

/**
 * @class QtTextRenderStrategy qttextrenderstrategy.h
 * <avogadro/qtopengl/qttextrenderstrategy.h>
 * @brief The QtTextRenderStrategy class uses the Qt toolkit to render text.
 */
class AVOGADROQTOPENGL_EXPORT QtTextRenderStrategy
  : public Rendering::TextRenderStrategy
{
public:
  QtTextRenderStrategy();
  ~QtTextRenderStrategy() override;

  TextRenderStrategy* newInstance() const override;

  void boundingBox(const std::string& string,
                   const Rendering::TextProperties& tprop,
                   int bbox[4]) const override;

  void render(const std::string& string, const Rendering::TextProperties& tprop,
              unsigned char* buffer, const Vector2i& dims) const override;

  /**
   * Keep the buffer as a QImage::Format_ARGB32_Premultiplied image. Useful
   * for testing.
   * @note The result buffer may or may not actually be ARGB ordered depending
   * on system endianness. See the QImage docs for more info.
   * @{
   */
  bool preserveArgb() const { return m_preserveArgb; }
  void setPreserveArgb(bool b) { m_preserveArgb = b; }
  /** @} */

private:
  static void argbToRgba(unsigned char* buffer, size_t pixels);
  bool m_preserveArgb;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_QTTEXTRENDERSTRATEGY_H
