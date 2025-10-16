/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/noncovalent/noncovalent.h"


namespace Avogadro::QtPlugins {

class NonCovalentFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit NonCovalentFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new NonCovalent(parent_);
    object->setObjectName("NonCovalent");
    return object;
  }

  QString identifier() const override { return "NonCovalent"; }

  QString description() const override { return "Non-covalent interaction rendering, including hydrogen bonds"; }

};

} // namespace Avogadro::QtPlugins

#include "NonCovalentPlugin.moc"
