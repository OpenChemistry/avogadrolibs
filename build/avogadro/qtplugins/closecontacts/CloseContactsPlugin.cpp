/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/closecontacts/closecontacts.h"


namespace Avogadro::QtPlugins {

class CloseContactsFactory : public QObject, public QtGui::ScenePluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ScenePluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ScenePluginFactory)

public:
  explicit CloseContactsFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ScenePlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new CloseContacts(parent_);
    object->setObjectName("CloseContacts");
    return object;
  }

  QString identifier() const override { return "CloseContacts"; }

  QString description() const override { return "Predictive close-contact rendering"; }

};

} // namespace Avogadro::QtPlugins

#include "CloseContactsPlugin.moc"
