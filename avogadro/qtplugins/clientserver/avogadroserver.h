/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#ifndef AVOGADROSERVER_H
#define AVOGADROSERVER_H

#include <list>
#include <string>

namespace ProtoCall {
namespace Runtime {
class vtkCommunicatorChannel;
}
}

class vtkServerSocket;

/**
 * @class AvogadroServer avogadroserver.h
 *        <avogadro/qtplugins/clientserver/avogadroserver.h>
 * @brief Simple server implementation based on vtkServerSocket, accepting
 * connections and processing ProtoCall requests.
 */
class AvogadroServer
{
public:
  AvogadroServer();
  virtual ~AvogadroServer();
  void listen(int port);

private:
  vtkServerSocket* m_socket;
  std::list<ProtoCall::Runtime::vtkCommunicatorChannel*> m_clientChannels;

  void processConnectionEvents();
  void accept();
};

#endif /* AVOGADROSERVER_H */
