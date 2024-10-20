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

namespace Avogadro::QtGui {

// See for example
// https://gist.github.com/jniemann66/dbc298b35a840bf3f1a2206ea6284c7b
// and  https://stackoverflow.com/a/66412883/131896

RichTextDelegate::RichTextDelegate(QObject* parent_)
  : QStyledItemDelegate(parent_)
{
}

RichTextDelegate::~RichTextDelegate(){};

QSize RichTextDelegate::sizeHint(const QStyleOptionViewItem& o,
                                 const QModelIndex& index) const
{
  if (o.text.isEmpty()) {
    // This is nothing this function is supposed to handle
    return QStyledItemDelegate::sizeHint(o, index);
  }

  QStyleOptionViewItem ov = o;
  initStyleOption(&ov, index);

  QTextDocument doc;
  doc.setHtml(ov.text);
  doc.setTextWidth(ov.rect.width());
  doc.setDefaultFont(ov.font);
  doc.setDocumentMargin(1);

  return QSize(doc.idealWidth(), doc.size().height());
}

void RichTextDelegate::paint(QPainter* p, const QStyleOptionViewItem& o,
                             const QModelIndex& index) const
{
  if (o.text.isEmpty()) {
    // no need to do anything if the text is empty
    QStyledItemDelegate::paint(p, o, index);

    return;
  }

  QStyleOptionViewItem ov = o;
  initStyleOption(&ov, index);

  p->save();

  QTextDocument doc;
  doc.setHtml(ov.text);

  QTextOption textOption;
  textOption.setWrapMode(ov.features & QStyleOptionViewItem::WrapText
                           ? QTextOption::WordWrap
                           : QTextOption::ManualWrap);
  textOption.setTextDirection(ov.direction);
  doc.setDefaultTextOption(textOption);
  doc.setDefaultFont(ov.font);
  doc.setDocumentMargin(1);
  doc.setTextWidth(ov.rect.width());
  doc.adjustSize();

  ov.text = "";
  ov.widget->style()->drawControl(QStyle::CE_ItemViewItem, &ov, p);

  p->translate(ov.rect.left(), ov.rect.top());
  QRect clip(0, 0, ov.rect.width(), ov.rect.height());
  doc.drawContents(p, clip);
  p->restore();
}

} // namespace Avogadro::QtGui
