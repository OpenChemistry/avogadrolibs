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

#include <string>

namespace Avogadro {
namespace Rendering {
class TextProperties;

class TextRenderStrategy
{
public:
  TextRenderStrategy() {}
  virtual ~TextRenderStrategy() {}

  virtual TextRenderStrategy* newInstance() const = 0;

  virtual void boundingBox(const std::string &string,
                           const TextProperties &tprop,
                           int bbox[4]) const = 0;

  virtual void render(const std::string &string,
                      const TextProperties &tprop,
                      unsigned char *buffer, size_t dims[2]) const = 0;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTRENDERSTRATEGY_H
