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

#ifndef AVOGADRO_RENDERING_TEXTURE2D_H
#define AVOGADRO_RENDERING_TEXTURE2D_H

#include "drawable.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

class Texture2D : public Drawable
{
public:
  Texture2D();
  ~Texture2D();

  void accept(Visitor &) AVO_OVERRIDE;

  void render(const Camera &camera);

  void setTextureData(const Core::Array<unsigned char> &data,
                      size_t width, size_t height);
  Core::Array<unsigned char> textureData() const;
  void textureSize(size_t size[2]) const;

  void setQuad(const Vector3f quadList[4]);
  void quad(Vector3f quadList[4]) const;

  void setTextureCoordinates(const Vector2f tcoords[4]);
  void textureCoordinates(Vector2f tcoords[4]) const;

protected:
  bool m_geometrySynced;
  bool m_textureSynced;
  Core::Array<unsigned char> m_textureData;
  size_t m_textureSize[2];
  std::vector<Vector3f> m_quad;
  std::vector<Vector2f> m_textureCoordinates;

private:
  void prepareGl();

private:
  class Private;
  Private *d;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTURE2D_H
