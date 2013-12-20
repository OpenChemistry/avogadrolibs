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

#include "avoremotefilesystemservice.h"
#include "filedialogmodel.h"
#include <vtkNew.h>
#include <vtkDirectory.h>

#if defined(_WIN32)
# define _WIN32_IE 0x0400  // special folder support
# define _WIN32_WINNT 0x0400  // shared folder support
# include <windows.h>   // FindFirstFile, FindNextFile, FindClose, ...
# include <direct.h>    // _getcwd
# include <shlobj.h>    // SHGetFolderPath
# include <sys/stat.h>  // stat
# include <string.h>   // for strcasecmp
# define vtkPVServerFileListingGetCWD _getcwd
#else
# include <sys/types.h> // DIR, struct dirent, struct stat
# include <sys/stat.h>  // stat
# include <dirent.h>    // opendir, readdir, closedir
# include <unistd.h>    // access, getcwd
# include <errno.h>     // errno
# include <string.h>    // strerror
# include <stdlib.h>    // getenv
# define vtkPVServerFileListingGetCWD getcwd
#endif
#if defined (__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <vector>
#endif

#include <vtksys/SystemTools.hxx>
#include <vtksys/RegularExpression.hxx>
#include <set>
#include <string>

#include <sstream>

using std::string;
using std::ostringstream;


AvoRemoteFileSystemService::~AvoRemoteFileSystemService()
{
}

void ls(const std::string path, Listing* output)
{
  vtkNew<vtkDirectory> dir;
  if (!dir->Open(path.c_str())) {
    ostringstream msg;
    msg << "Unable to open directory: " << path;
    output->setErrorString(msg.str());
    return;
  }

  for (vtkIdType i=0; i< dir->GetNumberOfFiles(); i++) {
    const char *filepath = dir->GetFile(i);

    Path *path = output->add_paths();
    path->set_path(filepath);
  }
}

void AvoRemoteFileSystemService::ls(const Path* input, Listing *output,
    ::google::protobuf::Closure* done)
{
  string dirPath;

  if (input->has_path()) {
    dirPath = input->path();
  }
  // List the current working directory
  else {
    dirPath = vtksys::SystemTools::GetCurrentWorkingDirectory().c_str();
  }

  ls(dirPath, output);
  done->Run();
}

inline void vtkPVFileInformationAddTerminatingSlash(std::string& name)
{
  if (name.size()>0)
    {
    char last = *(name.end()-1);
    if (last != '/' && last != '\\')
      {
#if defined(_WIN32)
      name += "\\";
#else
      name += "/";
#endif
      }
    }
}


bool isHidden(const string &name, const string &path)
{
 bool hidden;
#if defined(_WIN32)
  LPCSTR fp = path;
  DWORD flags= GetFileAttributes(fp);
  hidden =( flags & FILE_ATTRIBUTE_HIDDEN) ? true: false;
#else
  hidden =( name[0] == '.' )? true:false;
#endif
  return hidden;
}

void AvoRemoteFileSystemService::ls(string path, Listing *output)
{
  output->mutable_path()->set_path(path);

#if defined(_WIN32)

  vtkErrorMacro("GetDirectoryListing() cannot be called on Windows systems.");
  return;

#else

  std::string prefix = path;
  vtkPVFileInformationAddTerminatingSlash(prefix);

  if (vtksys::SystemTools::FileExists(path.c_str())) {
    output->mutable_path()->set_type((vtksys::SystemTools::FileIsDirectory(
        path.c_str()))? FileDialogModel::DIRECTORY
            : FileDialogModel::SINGLE_FILE);
  }

  // Open the directory and make sure it exists.
  DIR* dir = opendir(path.c_str());
  if (!dir)
    {
    // Could add check of errno here.
    return;
    }

  // Loop through the directory listing.
  while(const dirent* d = readdir(dir)) {
    // Skip the special directory entries.
    if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
      {
      continue;
      }
    Path *entry = output->add_paths();

    string fullPath = prefix + d->d_name;

    entry->set_name(string(d->d_name));
    entry->set_path(fullPath);
    entry->set_hidden(isHidden(entry->name(), entry->path()));

    FileDialogModel::FileType type = FileDialogModel::INVALID;

    if (vtksys::SystemTools::FileExists(fullPath.c_str())) {
      type =
        (vtksys::SystemTools::FileIsDirectory(fullPath.c_str()))?
            FileDialogModel::DIRECTORY : FileDialogModel::SINGLE_FILE;
    }

    entry->set_type(type);
  }

  closedir(dir);
#endif
}

void AvoRemoteFileSystemService::cwd(Path* output,
    ::google::protobuf::Closure* done)
{
    std::string path =
    vtksys::SystemTools::GetCurrentWorkingDirectory().c_str();


  output->set_path(path);

  done->Run();
}


void AvoRemoteFileSystemService::separator(Separator* output,
    ::google::protobuf::Closure* done)
{
#if defined(_WIN32) && !defined(__CYGWIN__)
  output->set_separator("\\");
#else
  output->set_separator("/");
#endif

  done->Run();
}

void AvoRemoteFileSystemService::absolutePath(const Path* input, Path* output,
    ::google::protobuf::Closure* done)
{
  std::string ret = input->name();
#if defined(WIN32)
  if (!IsUncPath(input->name()) && !IsNetworkPath(input->name()))
#endif
  {
  ret = vtksys::SystemTools::CollapseFullPath(input->name().c_str(),
    input->path().c_str());
  }

  output->set_path(ret);
  output->set_name(input->name());

  done->Run();
}
