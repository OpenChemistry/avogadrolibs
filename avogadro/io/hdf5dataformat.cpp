/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "hdf5dataformat.h"

#include "hdf5.h"

#include <cstdio>

namespace {

// Exclude from Doxygen:
/// @cond
// Build up a list of absolute paths to all datasets in the file. To be used
// with H5Ovisit (see Hdf5DataFormat::datasets()).
class ListDatasetsVisitor
{
public:
  std::vector<std::string> datasets;
  static herr_t operation(hid_t /*o_id*/, const char *name,
                          const H5O_info_t *object_info, void *op_data)
  {
    // If this object isn't a dataset, continue
    if (object_info->type != H5O_TYPE_DATASET)
      return 0;

    ListDatasetsVisitor *self = reinterpret_cast<ListDatasetsVisitor*>(op_data);
    self->datasets.push_back(std::string(name));
    return 0;
  }
};
// end doxygen exclude:
/// @endcond
}

namespace Avogadro {
namespace Io {

// Exclude from Doxygen:
/// @cond
// Internal storage. Used to keep HDF5 stuff out of the header.
class Hdf5DataFormat::Private
{
public:
  Private() :
    fileId(H5I_INVALID_HID),
    threshold(1024)
  {
  }

  std::string filename;
  hid_t fileId;

  size_t threshold;
};
// end doxygen exclude:
/// @endcond

Hdf5DataFormat::Hdf5DataFormat()
  : d(new Private())
{
}

Hdf5DataFormat::~Hdf5DataFormat()
{
  if (isOpen())
    closeFile();
  delete d;
}

bool Hdf5DataFormat::isOpen() const
{
  return d->fileId != H5I_INVALID_HID;
}

bool Hdf5DataFormat::openFile(const std::string &filename_,
                              Hdf5DataFormat::OpenMode mode)
{
  // File already open?
  if (isOpen())
    return false;

  switch (mode) {
  case ReadOnly:
    // File must exist -- use open
    d->fileId = H5Fopen(filename_.c_str(), H5F_ACC_RDONLY, H5P_DEFAULT);
    break;
  case ReadWriteTruncate:
    // Create new file:
    d->fileId = H5Fcreate(filename_.c_str(), H5F_ACC_TRUNC, H5P_DEFAULT,
                          H5P_DEFAULT);
    break;
  case ReadWriteAppend:
    // Test if the file exists:
    if (FILE *handle = fopen(filename_.c_str(), "r")) {
      // Exists! Use open
      fclose(handle);
      d->fileId = H5Fopen(filename_.c_str(), H5F_ACC_RDWR, H5P_DEFAULT);
    }
    else {
      // File doesn't exist yet. Create it.
      d->fileId = H5Fcreate(filename_.c_str(), H5F_ACC_EXCL, H5P_DEFAULT,
                            H5P_DEFAULT);
    }
    break;
  }

  // Error opening if file id is negative
  if (d->fileId < 0) {
    d->fileId = H5I_INVALID_HID;
    return false;
  }

  d->filename = filename_;
  return true;
}

std::string Hdf5DataFormat::filename() const
{
  return d->filename;
}

bool Hdf5DataFormat::closeFile()
{
  // Is there a file open?
  if (!isOpen())
    return false;

  herr_t err = H5Fclose(d->fileId);
  if (err < 0)
    return false;

  d->fileId = H5I_INVALID_HID;
  d->filename.clear();
  return true;
}

void Hdf5DataFormat::setThreshold(size_t bytes)
{
  d->threshold = bytes;
}

size_t Hdf5DataFormat::threshold() const
{
  return d->threshold;
}

bool Hdf5DataFormat::exceedsThreshold(const Eigen::MatrixXd &data) const
{
  size_t size = data.rows() * data.cols() * sizeof(double);
  return size > d->threshold;
}

bool Hdf5DataFormat::datasetExists(const std::string &path) const
{
  if (!isOpen())
    return false;

  // "/" cannot be a valid dataset, and this function must take an absolute path
  if (path.size() < 2)
    return false;

  // Verify that all paths leading to the target exist, one by one (grr...)
  size_t slashIndex = 0;
  do {
    slashIndex = path.find('/', slashIndex+1);
    if (slashIndex != std::string::npos) {
      htri_t exists = H5Lexists(d->fileId, path.substr(0, slashIndex).c_str(),
                                H5P_DEFAULT);
      if (exists != 1)
        return false;
    }
  } while (slashIndex != std::string::npos);

  // Verify that the deepest link exists
  if (H5Lexists(d->fileId, path.c_str(), H5P_DEFAULT) != 1)
    return false;

  // Verify that the deepest link resolves to an object
  if (H5Oexists_by_name(d->fileId, path.c_str(), H5P_DEFAULT) != 1)
    return false;

  // See if the object is a dataset
  H5O_info_t info;
  if (H5Oget_info_by_name(d->fileId, path.c_str(), &info, H5P_DEFAULT) < 0)
    return false;

  return info.type == H5O_TYPE_DATASET;
}

bool Hdf5DataFormat::removeDataset(const std::string &path) const
{
  if (!isOpen())
    return false;

  return H5Ldelete(d->fileId, path.c_str(), H5P_DEFAULT) >= 0;
}

bool Hdf5DataFormat::writeDataset(const std::string &path,
                                  const Eigen::MatrixXd &data) const
{
  if (!isOpen())
    return false;

  // Remove old data set if it exists
  if (datasetExists(path)) {
    if (!removeDataset(path))
      return false;
  }

  // Get dimensions of data.
  hsize_t dims[2];
  dims[0] = data.rows();
  dims[1] = data.cols();

  // Create a dataspace description
  hid_t dataspace_id = H5Screate_simple(2, dims, NULL);
  if (dataspace_id < 0)
    return false;

  // Create any intermediate groups if needed:
  hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
  if (lcpl_id == -1 || H5Pset_create_intermediate_group(lcpl_id, 1) < 0) {
    H5Sclose(dataspace_id);
    return false;
  }

  // Create the dataset
  hid_t dataset_id = H5Dcreate(d->fileId, path.c_str(), H5T_NATIVE_DOUBLE,
                               dataspace_id, lcpl_id, H5P_DEFAULT, H5P_DEFAULT);
  if (dataset_id < 0) {
    H5Sclose(dataspace_id);
    return false;
  }

  // Write the actual data. Transpose matrix (Eigen defaults to col-major).
  herr_t err = H5Dwrite(dataset_id, H5T_NATIVE_DOUBLE, H5S_ALL, dataspace_id,
                        H5P_DEFAULT, data.transpose().data());

  // Cleanup
  H5Dclose(dataset_id);
  H5Sclose(dataspace_id);

  if (err < 0)
    return false;

  return true;
}

bool Hdf5DataFormat::readDataset(const std::string &path,
                                 Eigen::MatrixXd &data) const
{
  if (!isOpen())
    return false;

  if (!datasetExists(path))
    return false;

  // Open dataset
  hid_t dataset_id = H5Dopen(d->fileId, path.c_str(), H5P_DEFAULT);
  if (dataset_id < 0)
    return false;

  // Lookup dimensions
  // Get dataspace for dataset
  hid_t dataspace_id = H5Dget_space(dataset_id);
  if (dataset_id < 0) {
    H5Dclose(dataset_id);
    return false;
  }

  // Get number of dimensions. Must = 2
  if (H5Sget_simple_extent_ndims(dataspace_id) != 2) {
    H5Sclose(dataspace_id);
    H5Dclose(dataset_id);
    return false;
  }

  // Get actual dimensions. We know it must be 2D
  hsize_t dims[2];
  if (H5Sget_simple_extent_dims(dataspace_id, dims, NULL) != 2) {
    H5Sclose(dataspace_id);
    H5Dclose(dataset_id);
    return false;
  }

  // Resize and populate matrix. Transpose matrix (Eigen defaults to col-major).
  data.resize(dims[0], dims[1]);
  if (H5Dread(dataset_id, H5T_NATIVE_DOUBLE, H5S_ALL, dataspace_id, H5P_DEFAULT,
              data.transpose().data())) {
    data.resize(0,0);
    H5Sclose(dataspace_id);
    H5Dclose(dataset_id);
    return false;
  }

  // Cleanup
  H5Sclose(dataspace_id);
  H5Dclose(dataset_id);

  return true;
}

std::vector<std::string> Hdf5DataFormat::datasets() const
{
  if (!isOpen())
    return std::vector<std::string>();

  ListDatasetsVisitor visitor;
  herr_t code = H5Ovisit(d->fileId, H5_INDEX_NAME, H5_ITER_INC,
                         &visitor.operation, &visitor);

  if (code < 0)
    return std::vector<std::string>();
  return visitor.datasets;
}

} // namespace Io
} // namespace Avogadro
