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

#include "textlabel2d.h"

#include "visitor.h"

namespace Avogadro {
namespace Rendering {

TextLabel2D::TextLabel2D()
{
  setRenderPass(Rendering::Overlay2DPass);
}

TextLabel2D::~TextLabel2D()
{
}

void TextLabel2D::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void TextLabel2D::setAnchor(const Vector2i& windowCoords)
{
  setAnchorInternal(Vector3f(static_cast<float>(windowCoords.x()),
                             static_cast<float>(windowCoords.y()), 0.f));
}

Vector2i TextLabel2D::anchor() const
{
  return getAnchorInternal().head<2>().cast<int>();
}

} // namespace Rendering
} // namespace Avogadro
