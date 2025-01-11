/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_RICHTEXTDELEGATE_H
#define AVOGADRO_QTPLUGINS_RICHTEXTDELEGATE_H

#include <QPainter>
#include <QStyledItemDelegate>
#include <QTextDocument>

#include "avogadroqtguiexport.h"

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT RichTextDelegate : public QStyledItemDelegate
{
  Q_OBJECT

public:
  explicit RichTextDelegate(QObject* parent = 0);
  ~RichTextDelegate() override;

  QSize sizeHint(const QStyleOptionViewItem& o,
                 const QModelIndex& index) const override;
  void paint(QPainter* p, const QStyleOptionViewItem& o,
             const QModelIndex& index) const override;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_RICHTEXTDELEGATE_H
