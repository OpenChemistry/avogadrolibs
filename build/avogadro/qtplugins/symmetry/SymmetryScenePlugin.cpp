/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/symmetry/symmetryscene.h"


namespace Avogadro::QtPlugins {

class SymmetrySceneFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit SymmetrySceneFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new SymmetryScene(parent_);
    object->setObjectName("SymmetryScene");
    return object;
  }

  QString identifier() const override { return "SymmetryScene"; }

  QString description() const override { return "Render symmetry elements."; }

};

} // namespace Avogadro::QtPlugins

#include "SymmetryScenePlugin.moc"
