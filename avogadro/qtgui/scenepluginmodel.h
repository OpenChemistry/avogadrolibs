/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_SCENEPLUGINMODEL_H
#define AVOGADRO_QTGUI_SCENEPLUGINMODEL_H

#include "avogadroqtguiexport.h"

#include <QtCore/QAbstractItemModel>

namespace Avogadro {
namespace QtGui {

class ScenePlugin;

/**
 * @class ScenePluginModel scenepluginmodel.h
 * <avogadro/qtgui/scenepluginmodel.h>
 * @brief A model containing scene plugins that will build up the scene.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT ScenePluginModel : public QAbstractItemModel
{
  Q_OBJECT

public:
  explicit ScenePluginModel(QObject* parent = nullptr);

  QModelIndex parent(const QModelIndex& child) const override;
  int rowCount(const QModelIndex& parent) const override;
  int columnCount(const QModelIndex& parent) const override;

  Qt::ItemFlags flags(const QModelIndex& index) const override;

  bool setData(const QModelIndex& index, const QVariant& value,
               int role) override;
  QVariant data(const QModelIndex& index, int role) const override;

  QModelIndex index(int row, int column,
                    const QModelIndex& parent = QModelIndex()) const override;

  void clear();

  QList<ScenePlugin*> scenePlugins() const;
  QList<ScenePlugin*> activeScenePlugins() const;

  ScenePlugin* scenePlugin(const QModelIndex& index) const;
  ScenePlugin* scenePlugin(int row) const;

signals:
  void pluginStateChanged(Avogadro::QtGui::ScenePlugin*);
  void pluginConfigChanged();

public slots:
  void addItem(Avogadro::QtGui::ScenePlugin* item);
  void removeItem(Avogadro::QtGui::ScenePlugin* item);
  void itemChanged();

private:
  QList<ScenePlugin*> m_scenePlugins;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_SCENEPLUGINMODEL_H
