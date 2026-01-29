/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "richtextdelegate.h"

#include <cmath>

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
  QStyleOptionViewItem ov = o;
  initStyleOption(&ov, index);

  // Check after initStyleOption populates ov.text from the model
  if (ov.text.isEmpty()) {
    return QStyledItemDelegate::sizeHint(o, index);
  }

  QTextDocument doc;
  doc.setHtml(ov.text);
  doc.setTextWidth(ov.rect.width());
  doc.setDefaultFont(ov.font);

  return QSize(std::ceil(doc.idealWidth()), std::ceil(doc.size().height()));
}

void RichTextDelegate::paint(QPainter* p, const QStyleOptionViewItem& o,
                             const QModelIndex& index) const
{
  QStyleOptionViewItem ov = o;
  initStyleOption(&ov, index);

  p->save();

  QTextDocument doc;
  doc.setHtml(ov.text);
  doc.setDefaultFont(ov.font);

  ov.text = "";
  ov.widget->style()->drawControl(QStyle::CE_ItemViewItem, &ov, p);

  // Calculate position based on alignment
  QSizeF docSize = doc.size();
  qreal x = ov.rect.left();
  qreal y = ov.rect.top();

  // Get alignment from the style option (populated from Qt::TextAlignmentRole)
  Qt::Alignment alignment = ov.displayAlignment;

  // Horizontal alignment
  if (alignment & Qt::AlignHCenter) {
    x += (ov.rect.width() - docSize.width()) / 2.0;
  } else if (alignment & Qt::AlignRight) {
    x += ov.rect.width() - docSize.width();
  }

  // Vertical alignment
  if (alignment & Qt::AlignVCenter) {
    y += (ov.rect.height() - docSize.height()) / 2.0;
  } else if (alignment & Qt::AlignBottom) {
    y += ov.rect.height() - docSize.height();
  }

  p->translate(x, y);
  QRect clip(0, 0, ov.rect.width(), ov.rect.height());
  doc.drawContents(p, clip);
  p->restore();
}

} // namespace Avogadro::QtGui
