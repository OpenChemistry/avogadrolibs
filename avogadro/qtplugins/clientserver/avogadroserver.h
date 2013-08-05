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

#ifndef AVOGADROSERVER_H_
#define AVOGADROSERVER_H_

#include <string>
#include <list>

namespace ProtoCall {
namespace Runtime {
class vtkCommunicatorChannel;
}
}

class vtkServerSocket;

class AvogadroServer
{
public:
  AvogadroServer();
  virtual ~AvogadroServer();
  void listen(int port);

private:
  vtkServerSocket *m_socket;
  std::list<ProtoCall::Runtime::vtkCommunicatorChannel *> m_clientChannels;

  void processConnectionEvents();
  void accept();

};

#endif /* AVOGADROSERVER_H_ */
