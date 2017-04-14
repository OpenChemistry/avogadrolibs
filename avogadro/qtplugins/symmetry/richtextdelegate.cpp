/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "richtextdelegate.h"

namespace Avogadro {
namespace QtPlugins {

QSize RichTextDelegate::sizeHint(const QStyleOptionViewItem& o,
                                 const QModelIndex& index) const
{
  QStyleOptionViewItemV4 ov4 = o;
  initStyleOption(&ov4, index);
  QTextDocument doc;
  doc.setHtml(ov4.text);
  doc.setTextWidth(ov4.rect.width());
  return QSize(doc.idealWidth(), doc.size().height());
}

void RichTextDelegate::paint(QPainter* p, const QStyleOptionViewItem& o,
                             const QModelIndex& index) const
{
  QStyleOptionViewItemV4 ov4 = o;
  initStyleOption(&ov4, index);

  p->save();

  QTextDocument doc;
  doc.setHtml(ov4.text);

  ov4.text = "";
  ov4.widget->style()->drawControl(QStyle::CE_ItemViewItem, &ov4, p);

  p->translate(ov4.rect.left(), ov4.rect.top());
  QRect clip(0, 0, ov4.rect.width(), ov4.rect.height());
  doc.drawContents(p, clip);
  p->restore();
}
}
}
