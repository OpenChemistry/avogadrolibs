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

#ifndef AVOREMOTEMOLECULESERVICE_H
#define AVOREMOTEMOLECULESERVICE_H

#include "RemoteMoleculeService.pb.h"

/**
 * @class AvoRemoteMoleculeService avoremotemoleculeservice.h
 * <avogadro/qtplugins/clientserver/avoremotemoleculeservice.h>
 * @brief The server side implementation of the RemoteMoleculeService, provides
 * functionality to open a molecule on a remote system.
 */
class AvoRemoteMoleculeService : public RemoteMoleculeService
{
public:
  virtual ~AvoRemoteMoleculeService();

  void open(const OpenRequest* input, OpenResponse* output,
            ::google::protobuf::Closure* done);

  void fileFormats(FileFormats* formats, ::google::protobuf::Closure* done);
};

#endif /* AVOREMOTEMOLECULESERVICE_H */
