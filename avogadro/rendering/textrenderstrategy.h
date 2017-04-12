/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_RENDERING_TEXTRENDERSTRATEGY_H
#define AVOGADRO_RENDERING_TEXTRENDERSTRATEGY_H

#include "avogadrorenderingexport.h"

#include <avogadro/core/vector.h>

#include <string>

namespace Avogadro {
namespace Rendering {
class TextProperties;

/**
 * @class TextRenderStrategy textrenderstrategy.h
 * <avogadro/rendering/textrenderstrategy.h>
 * @brief The TextRenderStrategy class defines an interface for generating
 * text images.
 */
class AVOGADRORENDERING_EXPORT TextRenderStrategy
{
public:
  TextRenderStrategy();
  virtual ~TextRenderStrategy();

  /**
   * Copy the current TextRenderStrategy implementation into an new object.
   */
  virtual TextRenderStrategy* newInstance() const = 0;

  /**
   * @brief Calculate a bounding box.
   * @param string The text.
   * @param tprop The properties.
   * @param bbox The result in pixels (left, right, top, bottom).
   */
  virtual void boundingBox(const std::string& string,
                           const TextProperties& tprop, int bbox[4]) const = 0;

  /**
   * @brief render Render the string.
   * @param string The text.
   * @param tprop The properties.
   * @param buffer The target. Must be dims[0]*dims[1]*4
   * bytes. The buffer will be filled with RGBA image data, with the top
   * scan row at the beginning.
   * @param dims Dimensions in pixels of the target buffer.
   */
  virtual void render(const std::string& string, const TextProperties& tprop,
                      unsigned char* buffer, const Vector2i& dims) const = 0;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTRENDERSTRATEGY_H
