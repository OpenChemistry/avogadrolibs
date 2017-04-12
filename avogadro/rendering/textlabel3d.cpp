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

#include "textlabel3d.h"

#include "visitor.h"

namespace Avogadro {
namespace Rendering {

TextLabel3D::TextLabel3D()
{
  setRenderPass(TranslucentPass);
}

TextLabel3D::~TextLabel3D()
{
}

void TextLabel3D::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void TextLabel3D::setAnchor(const Vector3f& position)
{
  setAnchorInternal(position);
}

Vector3f TextLabel3D::anchor() const
{
  return getAnchorInternal();
}

void TextLabel3D::setRadius(float r)
{
  setRadiusInternal(r);
}

float TextLabel3D::radius() const
{
  return getRadiusInternal();
}

} // namespace Rendering
} // namespace Avogadro
