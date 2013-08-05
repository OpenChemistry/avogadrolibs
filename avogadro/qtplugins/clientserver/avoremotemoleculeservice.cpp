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


#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/core/molecule.h>

using Avogadro::Core::Molecule;
using std::string;

AvoRemoteMoleculeService::~AvoRemoteMoleculeService()
{
}

void AvoRemoteMoleculeService::open(const OpenRequest* input,
    OpenResponse* output, ::google::protobuf::Closure* done)
{

  string path = input->path();
  string format = input->format();

  Avogadro::Io::FileFormat *reader = NULL;
  if (format == "cml")
    reader = new Avogadro::Io::CmlFormat;
  else if (format == "cjson")
    reader = new Avogadro::Io::CjsonFormat;

  Molecule molecule;

  // Try and read the file
  if (!reader->readFile(path, molecule)) {
    output->setErrorString(reader->error());
    done->Run();
    return;
  }

  // If we where successful send the result back
  output->mutable_molecule()->set(&molecule);
  done->Run();
}
