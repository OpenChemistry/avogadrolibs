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

#ifndef AVOREMOTEFILESYSTEMSERVICE_H
#define AVOREMOTEFILESYSTEMSERVICE_H

#include "RemoteFileSystemService.pb.h"

class AvoRemoteFileSystemService : public RemoteFileSystemService
{
public:
  virtual ~AvoRemoteFileSystemService();

  void ls(const Path* input, Listing* output,
      ::google::protobuf::Closure* done);

  void cwd(Path* output, ::google::protobuf::Closure* done);

  void separator(Separator* output, ::google::protobuf::Closure* done);

  void specialDirectories(Paths* output, ::google::protobuf::Closure* done) {};
  void absolutePath(const Path* input, Path* output,
      ::google::protobuf::Closure* done);

private:
  void ls(const std::string path, Listing* output);

};

#endif /* AVOREMOTEFILESYSTEMSERVICE_H */
