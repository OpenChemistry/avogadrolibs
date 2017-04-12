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

#include "avoremotemoleculeservice.h"

#include <avogadro/core/molecule.h>
#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <iostream>

using Avogadro::Core::Molecule;
using std::string;

AvoRemoteMoleculeService::~AvoRemoteMoleculeService()
{
}

void AvoRemoteMoleculeService::open(const OpenRequest* input,
                                    OpenResponse* output,
                                    ::google::protobuf::Closure* done)
{

  string path = input->path();

  Avogadro::Io::FileFormatManager& mgr =
    Avogadro::Io::FileFormatManager::instance();
  Molecule molecule;

  // Try and read the file
  if (!mgr.readFile(molecule, path)) {
    output->setErrorString(mgr.error());
    done->Run();
    return;
  }

  // If we where successful send the result back
  output->mutable_molecule()->set(&molecule);
  done->Run();
}

void AvoRemoteMoleculeService::fileFormats(FileFormats* formats,
                                           ::google::protobuf::Closure* done)
{
  Avogadro::Io::FileFormatManager& mgr =
    Avogadro::Io::FileFormatManager::instance();

  std::vector<const Avogadro::Io::FileFormat*> fileFormats = mgr.fileFormats();
  for (std::vector<const Avogadro::Io::FileFormat*>::iterator iter =
         fileFormats.begin();
       iter != fileFormats.end(); ++iter) {
    FileFormat* format = formats->add_formats();
    format->set_name((*iter)->name());

    std::vector<std::string> extensions = (*iter)->fileExtensions();
    for (std::vector<std::string>::iterator extIter = extensions.begin();
         extIter != extensions.end(); ++extIter) {
      format->add_extension(*extIter);
    }
  }

  done->Run();
}
