/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#ifndef AVOREMOTEFILESYSTEMSERVICE_H
#define AVOREMOTEFILESYSTEMSERVICE_H

#include "RemoteFileSystemService.pb.h"

/**
 * @class AvoRemoteFileSystemService avoremotefilesystemservice.h
 * <avogadro/qtplugins/clientserver/avoremotefilesystemservice.h>
 * @brief Server side implementation of RemoteFileSystemService. Provides
 * methods for browsing a remote filesystem.
 */
class AvoRemoteFileSystemService : public RemoteFileSystemService
{
public:
  virtual ~AvoRemoteFileSystemService();

  void ls(const Path* input, Listing* output,
          ::google::protobuf::Closure* done);

  void cwd(Path* output, ::google::protobuf::Closure* done);

  void separator(Separator* output, ::google::protobuf::Closure* done);

  void specialDirectories(Paths* output, ::google::protobuf::Closure* done){};
  void absolutePath(const Path* input, Path* output,
                    ::google::protobuf::Closure* done);

private:
  void ls(const std::string path, Listing* output);
};

#endif /* AVOREMOTEFILESYSTEMSERVICE_H */
