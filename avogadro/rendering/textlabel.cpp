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

#include "textlabel.h"

#include "quadplacementstrategy.h"
#include "textrenderstrategy.h"
#include "visitor.h"

#include <iostream>

namespace Avogadro {
namespace Rendering {

TextLabel::TextLabel()
  : m_rebuildTexture(true)
{
}

TextLabel::~TextLabel()
{
}

void TextLabel::accept(Visitor &v)
{
  v.visit(*this);
}

void TextLabel::buildTexture(const TextRenderStrategy &tren)
{
  if (!m_rebuildTexture)
    return;

  // Determine the required size of the texture:
  int bbox[4];
  tren.boundingBox(m_string, m_textProperties, bbox);
  m_textDimensions = Vector2f(static_cast<float>(bbox[1] - bbox[0] + 1),
                              static_cast<float>(bbox[3] - bbox[2] + 1));

  // Update the dimensions in our placement strategy
  if (m_quadPlacementStrategy) {
    // If this isn't an overlay, scale the text down by a factor of 72.
    if (m_renderPass == OverlayPass)
      m_quadPlacementStrategy->setDimensions(m_textDimensions);
    else
      m_quadPlacementStrategy->setDimensions(m_textDimensions / 72.f);
  }

  // Enlarge each dimension to the next highest power of two:
  m_textureSize[0] = 16;
  m_textureSize[1] = 16;
  for (int i = 0; i < 2; ++i) {
    while (m_textureSize[i] < m_textDimensions[i])
      m_textureSize[i] *= 2;
  }

  // Allocate memory
  const int bytesPerPixel = 4; // RGBA format
  m_textureData.resize(m_textureSize[0] * m_textureSize[1] * bytesPerPixel);

  // Render image to texture buffer
  if (m_textureData.size() > 0)
    tren.render(m_string, m_textProperties, &m_textureData[0], m_textureSize);

  // Update the texture coordinates
  float denoms[2] = { static_cast<float>(2 * m_textureSize[0]),
                      static_cast<float>(2 * m_textureSize[1]) };
  float uMin = 1.f / denoms[0];
  float vMin = 1.f / denoms[1];
  float uMax = ((2.f * m_textDimensions[0]) - 1.f) / denoms[0];
  float vMax = ((2.f * m_textDimensions[1]) - 1.f) / denoms[1];
  m_textureCoordinates.resize(4);
  m_textureCoordinates[0] = Vector2f(uMin, vMin);
  m_textureCoordinates[1] = Vector2f(uMax, vMin);
  m_textureCoordinates[2] = Vector2f(uMin, vMax);
  m_textureCoordinates[3] = Vector2f(uMax, vMax);

  // Let texture2D know that we changed the texture.
  m_textureSynced = false;

  // Mark our cache as clean
  m_rebuildTexture = false;
}

void TextLabel::render(const Camera &camera)
{
  // Only render the texture if we've generated it.
  if (!m_rebuildTexture)
    Texture2D::render(camera);
  else
    std::cerr << "No texture generated for label: " << m_string << std::endl;
}

void TextLabel::setString(const std::string &str)
{
  if (str != m_string) {
    m_rebuildTexture = true;
    m_string = str;
  }
}

void TextLabel::setTextProperties(const TextProperties &prop)
{
  if (m_textProperties != prop) {
    m_rebuildTexture = true;
    m_textProperties = prop;
  }
}

} // namespace Rendering
} // namespace Avogadro
