/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2017 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "archive.h"
#include "archive_entry.h"
#include <QtCore/QList>
#include <string>

namespace Avogadro {

namespace QtPlugins {

class ZipExtracter
{
public:
  ZipExtracter();
  ~ZipExtracter();
  char* convert(const std::string&);
  int copyData(struct archive* ar, struct archive* aw);
  QList<QString> extract(std::string extractdir, std::string absolutepath);
  QList<QString> listFiles(const std::string absolutepath);
};
}
}
