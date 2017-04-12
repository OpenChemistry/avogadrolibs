/******************************************************************************

 This source file is part of the Avogadro project.

 Copyright 2013 Kitware, Inc.

 This source code is released under the New BSD License, (the "License").

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

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
