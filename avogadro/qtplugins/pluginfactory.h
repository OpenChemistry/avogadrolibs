/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLUGINFACTORY_H
#define AVOGADRO_QTPLUGINS_PLUGINFACTORY_H

#include <QtCore/QObject>
#include <QtCore/QString>

namespace Avogadro::QtPlugins {

/**
 * @class PluginFactory pluginfactory.h <avogadro/qtplugins/pluginfactory.h>
 * @brief The base class for plugin factories in Avogadro.
 */
template <typename T>
class PluginFactory
{
public:
  virtual ~PluginFactory() {}

  virtual T* createInstance(QObject *parent = nullptr) = 0;
  virtual QString identifier() const = 0;
  virtual QString description() const = 0;
};

} /* namespace Avogadro */

#endif /* AVOGADRO_QTPLUGINS_PLUGINFACTORY_H */
