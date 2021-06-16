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

#ifndef AVOGADRO_QTPLUGINS_RICHTEXTDELEGATE_H
#define AVOGADRO_QTPLUGINS_RICHTEXTDELEGATE_H

#include <QPainter>
#include <QStyledItemDelegate>
#include <QTextDocument>

namespace Avogadro {
namespace QtPlugins {

class RichTextDelegate : public QStyledItemDelegate
{
  Q_OBJECT

public:
  RichTextDelegate(QObject* parent = nullptr)
    : QStyledItemDelegate(parent){};
  QSize sizeHint(const QStyleOptionViewItem& o,
                 const QModelIndex& index) const override;
  void paint(QPainter* p, const QStyleOptionViewItem& o,
             const QModelIndex& index) const override;
};
}
}

#endif // AVOGADRO_QTPLUGINS_RICHTEXTDELEGATE_H
