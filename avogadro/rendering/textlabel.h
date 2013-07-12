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

#ifndef AVOGADRO_RENDERING_TEXTLABEL_H
#define AVOGADRO_RENDERING_TEXTLABEL_H

#include "texture2d.h"
#include "avogadrorenderingexport.h"

#include "textproperties.h"

#include <string>

namespace Avogadro {
namespace Rendering {
class TextRenderStrategy;

class AVOGADRORENDERING_EXPORT TextLabel : public Texture2D
{
public:
  TextLabel();
  ~TextLabel();

  void accept(Visitor &) AVO_OVERRIDE;

  void buildTexture(const TextRenderStrategy &);

  void invalidateTexture() { m_rebuildTexture = true; }

  void render(const Camera &camera) AVO_OVERRIDE;

  void setString(const std::string &str);
  std::string string() const { return m_string; }

  void setTextProperties(const TextProperties &prop);
  TextProperties textProperties() const { return m_textProperties; }

private:
  bool m_rebuildTexture;
  std::string m_string;
  TextProperties m_textProperties;

};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABEL_H
