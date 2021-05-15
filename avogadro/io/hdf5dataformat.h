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

#ifndef AVOGADRO_HDF5DATAFORMAT_H
#define AVOGADRO_HDF5DATAFORMAT_H

#include "avogadroioexport.h"

#include <avogadro/core/matrix.h> // can't forward declare eigen types

#include <cstddef>
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {
template <typename T>
class Array;
}
namespace Io {

/**
 * @class Hdf5DataFormat hdf5dataformat.h <avogadro/io/hdf5dataformat.h>
 * @brief The Hdf5DataFormat class provides access to data stored in HDF5 files.
 * @author Allison Vacanti
 *
 * This class is intended to supplement an existing format reader/writer by
 * providing the option to write large data to an HDF5 file store. The purpose
 * is to keep text format files at a managable size.
 *
 * To use this class, open or create an HDF5 file with the openFile method,
 * using the appropriate OpenMode for the intended operation. Data can be
 * written to the file using the writeDataset methods and retrieved using the
 * readDataset methods. When finished, call closeFile to release the file
 * resources from the HDF5 library.
 *
 * A complete set of datasets available in an open file can be retrieved with
 * the datasets() method, and the existence of a particular dataset can be
 * tested with datasetExists(). removeDataset() can be used to unlink an
 * existing dataset from the file, though this will not free any space on disk.
 * The space occupied by an unlinked dataset may be reclaimed by new write
 * operations, but only if they occur before the file is closed.
 *
 * A convenient thresholding system is implemented to help the accompanying text
 * format writer determine which data is "large" enough to be stored in HDF5. A
 * size threshold (in bytes) may be set with the setThreshold() function (the
 * default is 1KB). A data object may be passed to the exceedsThreshold method
 * to see if the size of the data in the container exceeds the currently set
 * threshold. If so, it should be written into the HDF5 file by writeDataset.
 * If not, it should be serialized into the text file in a suitable format. The
 * thresholding operations are optional; the threshold size does not affect the
 * behavior of the read/write methods and are only for user convenience.
 */
class AVOGADROIO_EXPORT Hdf5DataFormat
{
public:
  Hdf5DataFormat();

  /** Destructor. Closes any open file before freeing memory. */
  ~Hdf5DataFormat();

  /** Open modes for use with openFile(). */
  enum OpenMode
  {
    /** Open an existing file in read-only mode. The file must exist. */
    ReadOnly = 0,
    /**
     * Create a file in read/write mode, removing any existing file with the
     * same name.
     */
    ReadWriteTruncate,
    /**
     * Open an file in read/write mode. If the file exist, its contents will be
     * preserved. If it does not, a new file will be created.
     */
    ReadWriteAppend
  };

  /** @return true if a file is open. */
  bool isOpen() const;

  /**
   * @brief openFile Open a file for use by this reader/writer.
   * @param filename_ Name of the file to open.
   * @param mode OpenMode for the file. Default is ReadWriteAppend.
   * @note Only a single file may be opened at a time. Attempting to open
   * multiple files without calling closeFile() will fail.
   * @return True if the file is successfully opened/create by the HDF5
   * subsystem, false otherwise.
   */
  bool openFile(const std::string& filename_, OpenMode mode = ReadWriteAppend);

  /**
   * @return The name of the open file, or an empty string if no file is open.
   */
  std::string filename() const;

  /**
   * @brief closeFile Close the file and reset the reader/writer. Another file
   * may be opened after calling this function.
   * @return true if the file is successfully released by the HDF5 subsystem.
   */
  bool closeFile();

  /**
   * @brief setThreshold Set the threshold size in bytes that will be used in
   * the exceedsThreshold functions. The threshold can be used to determine
   * which
   * data is considered "large enough" to be stored in HDF5, rather than an
   * accompanying format.
   * @param bytes The size in bytes for the threshold. Default: 1KB.
   */
  void setThreshold(size_t bytes);

  /** @return The current threshold size in bytes. Default: 1KB. */
  size_t threshold() const;

  /**
   * @brief exceedsThreshold Test if a data set is "large enough" to be stored
   * in HDF5 format. If this function returns true, the number of bytes tested
   * is larger than the threshold and the data should be written into the HDF5
   * file. If false, the data should be written into the accompanying format.
   * @param bytes The size of the dataset in bytes
   * @return true if the size exceeds the threshold set by setThreshold.
   */
  bool exceedsThreshold(size_t bytes) const;

  /**
   * @brief exceedsThreshold Test if a data set is "large enough" to be stored
   * in HDF5 format. If this function returns true, the size of the data in the
   * object is larger than the threshold and should be written into the HDF5
   * file. If false, the data should be written into the accompanying format.
   * @param data Data object to test.
   * @return true if the size of the serializable data in @a data exceeds the
   * threshold set by setThreshold.
   */
  bool exceedsThreshold(const MatrixX& data) const;

  /**
   * @brief exceedsThreshold Test if a data set is "large enough" to be stored
   * in HDF5 format. If this function returns true, the size of the data in the
   * object is larger than the threshold and should be written into the HDF5
   * file. If false, the data should be written into the accompanying format.
   * @param data Data object to test.
   * @return true if the size of the serializable data in @a data exceeds the
   * threshold set by setThreshold.
   */
  bool exceedsThreshold(const std::vector<double>& data) const;

  /**
   * @brief exceedsThreshold Test if a data set is "large enough" to be stored
   * in HDF5 format. If this function returns true, the size of the data in the
   * object is larger than the threshold and should be written into the HDF5
   * file. If false, the data should be written into the accompanying format.
   * @param data Data object to test.
   * @return true if the size of the serializable data in @a data exceeds the
   * threshold set by setThreshold.
   */
  bool exceedsThreshold(const Core::Array<double>& data) const;

  /**
   * @brief datasetExists Test if the currently open file contains a dataset at
   * the HDF5 absolute path @a path.
   * @param path An absolute path into the HDF5 data.
   * @return true if the object at @a path both exists and is a dataset, false
   * otherwise.
   */
  bool datasetExists(const std::string& path) const;

  /**
   * @brief removeDataset Remove a dataset from the currently opened file.
   * @param path An absolute path into the HDF5 data.
   * @return true if the dataset exists and has been successfully removed.
   * \warning Removing datasets can be expensive in terms of filesize, as
   * deleted space cannot be reclaimed by HDF5 once the file is closed, and the
   * file will not decrease in size as datasets are removed. For details, see
   * http://www.hdfgroup.org/HDF5/doc/H5.user/Performance.html#Freespace.
   */
  bool removeDataset(const std::string& path) const;

  /**
   * @brief datasetDimensions Find the dimensions of a dataset.
   * @param path An absolute path into the HDF5 data.
   * @return A vector containing the dimensionality of the data, major dimension
   * first. If an error is encountered, an empty vector is returned.
   */
  std::vector<int> datasetDimensions(const std::string& path) const;

  /**
   * @brief writeDataset Write the data to the currently opened file at the
   * specified absolute HDF5 path.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to serialize to HDF5.
   * @return true if the data is successfully written, false otherwise.
   */
  bool writeDataset(const std::string& path, const MatrixX& data) const;

  /**
   * @brief writeDataset Write the data to the currently opened file at the
   * specified absolute HDF5 path.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to serialize to HDF5.
   * @param ndims The number of dimensions in the data. Default: 1.
   * @param dims The dimensionality of the data, major dimension first. Default:
   * data.size().
   * @note Since std::vector is a flat container, the dimensionality data is
   * only used to set up the dataset metadata in the HDF5 container. Omitting
   * the dimensionality parameters will write a flat array.
   * @return true if the data is successfully written, false otherwise.
   */
  bool writeDataset(const std::string& path, const std::vector<double>& data,
                    int ndims = 1, size_t* dims = nullptr) const;

  /**
   * @brief writeDataset Write the data to the currently opened file at the
   * specified absolute HDF5 path.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to serialize to HDF5.
   * @param ndims The number of dimensions in the data. Default: 1.
   * @param dims The dimensionality of the data, major dimension first. Default:
   * data.size().
   * @note Since this is a flat container, the dimensionality data is
   * only used to set up the dataset metadata in the HDF5 container. Omitting
   * the dimensionality parameters will write a flat array.
   * @return true if the data is successfully written, false otherwise.
   */
  bool writeDataset(const std::string& path, const Core::Array<double>& data,
                    int ndims = 1, size_t* dims = nullptr) const;

  /**
   * @brief readDataset Populate the data container @data with data at from the
   * specified path in the currently opened HDF5 file.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to into which the HDF5 data shall be
   * deserialized. @a data will be resized to fit the data.
   * @return true if the data is successfully read, false otherwise. If the
   * read fails, the @a data object may be left in an unpredictable state.
   */
  bool readDataset(const std::string& path, MatrixX& data) const;

  /**
   * @brief readDataset Populate the data container @data with data at from the
   * specified path in the currently opened HDF5 file.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to into which the HDF5 data shall be
   * deserialized. @a data will be resized to fit the data.
   * @return A vector containing the dimensionality of the dataset, major
   * dimension first. If an error occurs, an empty vector is returned and *data
   * will be set to nullptr.
   */
  std::vector<int> readDataset(const std::string& path,
                               std::vector<double>& data) const;

  /**
   * @brief readDataset Populate the data container @data with data at from the
   * specified path in the currently opened HDF5 file.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to into which the HDF5 data shall be
   * deserialized. @a data will be resized to fit the data.
   * @return A vector containing the dimensionality of the dataset, major
   * dimension first. If an error occurs, an empty vector is returned and *data
   * will be set to nullptr.
   */
  std::vector<int> readDataset(const std::string& path,
                               Core::Array<double>& data) const;

  /**
   * @brief datasets Traverse the currently opened file and return a list of all
   * dataset objects in the file.
   * @return A list of datasets in the current file.
   * \warning The list is not cached internal and is recalculated on each call.
   * This may be expensive on large HDF5 files, so external caching is
   * recommended if this data is frequently needed.
   */
  std::vector<std::string> datasets() const;

  /** Used to abstract details of container resizing. */
  class ResizeContainer;

private:
  /**
   * @brief writeRawDataset Write the data to the currently opened file at the
   * specified absolute HDF5 path.
   * @param path An absolute path into the HDF5 data.
   * @param data The data container to serialize to HDF5.
   * @param ndims The number of dimensions in the data.
   * @param dims The data dimensions, major dimension first.
   * @note Since a double[] is a flat container, the dimensionality data is
   * only used to set up the dataset metadata in the HDF5 container. The result
   * of multiplying all values in @a dims must equal the length of the @a data.
   * @return true if the data is successfully written, false otherwise.
   */
  bool writeRawDataset(const std::string& path, const double data[], int ndims,
                       size_t dims[]) const;

  /**
   * @brief readRawDataset Populate the data container @data with data from the
   * specified path in the currently opened HDF5 file.
   * @param path An absolute path into the HDF5 data.
   * @param container A subclass of ResizeContainer with the container to read
   * data into.
   * @return A vector containing the dimensionality of the dataset, major
   * dimension first. If an error occurs, an empty vector is returned.
   */
  std::vector<int> readRawDataset(const std::string& path,
                                  ResizeContainer& container) const;

  class Private;
  /** Internal storage, used to encapsulate HDF5 data. */
  Private* const d;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_HDF5DATAFORMAT_H
