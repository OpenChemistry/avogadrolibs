/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
