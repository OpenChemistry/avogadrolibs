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

#ifndef AVOGADRO_QTGUI_QTTEXTRENDERSTRATEGY_H
#define AVOGADRO_QTGUI_QTTEXTRENDERSTRATEGY_H

#include <avogadro/rendering/textrenderstrategy.h>
#include "avogadroqtguiexport.h"

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT QtTextRenderStrategy
    : public Rendering::TextRenderStrategy
{
public:
  QtTextRenderStrategy();
  ~QtTextRenderStrategy() AVO_OVERRIDE;

  TextRenderStrategy* newInstance() const AVO_OVERRIDE;

  void boundingBox(const std::string &string,
                   const Rendering::TextProperties &tprop,
                   int bbox[4]) const AVO_OVERRIDE;

  void render(const std::string &string, const Rendering::TextProperties &tprop,
              unsigned char *buffer, size_t dims[2]) const AVO_OVERRIDE;

private:
  static void argbToRgba(unsigned char *buffer, size_t pixels);
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_QTTEXTRENDERSTRATEGY_H
