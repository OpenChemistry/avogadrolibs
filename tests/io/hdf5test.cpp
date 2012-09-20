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

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/io/hdf5dataformat.h>

#include <cstdio>

using Avogadro::Io::Hdf5DataFormat;

namespace {

bool fileExists(const char *filename)
{
  FILE *handle = fopen(filename, "r");
  if (handle != NULL) {
    fclose(handle);
    return true;
  }
  return false;
}

}

TEST(Hdf5Test, openCloseReadOnly)
{
  Hdf5DataFormat hdf5;
  std::string testfile = std::string(AVOGADRO_DATA) + "/data/hdf5file.h5";
  ASSERT_TRUE(fileExists(testfile.c_str()));
  ASSERT_TRUE(hdf5.openFile(testfile.c_str(), Hdf5DataFormat::ReadOnly))
      << "Failed to open " << testfile << " in read-only mode.";

  std::vector<std::string> refDatasets;
  refDatasets.resize(3);
  refDatasets[0] = "Data";
  refDatasets[1] = "Group1/Group2/Data";
  refDatasets[2] = "Test/MoleculeData/Matrix1";

  std::vector<std::string> datasets = hdf5.datasets();

  EXPECT_EQ(refDatasets, datasets) << "Unexpected list of datasets.";

  ASSERT_TRUE(hdf5.closeFile())
      << "Failed to close read-only file " << testfile << ".";
}

TEST(Hdf5Test, openCloseReadWriteAppend)
{
  Hdf5DataFormat hdf5;
  std::string testfile = std::string(AVOGADRO_DATA) + "/data/hdf5file.h5";
  ASSERT_TRUE(fileExists(testfile.c_str()));
  ASSERT_TRUE(hdf5.openFile(testfile.c_str(), Hdf5DataFormat::ReadWriteAppend))
      << "Failed to open " << testfile << " in read-write (append) mode.";

  std::vector<std::string> refDatasets;
  refDatasets.resize(3);
  refDatasets[0] = "Data";
  refDatasets[1] = "Group1/Group2/Data";
  refDatasets[2] = "Test/MoleculeData/Matrix1";

  std::vector<std::string> datasets = hdf5.datasets();

  EXPECT_EQ(refDatasets, datasets) << "Unexpected list of datasets.";

  ASSERT_TRUE(hdf5.closeFile())
      << "Failed to close read-only file " << testfile << ".";
}

TEST(Hdf5Test, readWriteEigenMatrixXd)
{
  char tmpFileName [L_tmpnam];
  tmpnam(tmpFileName);

  Hdf5DataFormat hdf5;
  ASSERT_TRUE(hdf5.openFile(tmpFileName, Hdf5DataFormat::ReadWriteTruncate))
      << "Opening test file '" << tmpFileName << "' failed.";

  Eigen::MatrixXd mat (10, 10);
  for (int row = 0; row < 10; ++row) {
    for (int col = 0; col < 10; ++col) {
      mat(row, col) = row * col * col + row + col;
    }
  }

  EXPECT_TRUE(hdf5.writeDataset("/Group1/Group2/Data", mat))
      << "Writing Eigen::MatrixXd failed.";

  Eigen::MatrixXd matRead;
  EXPECT_TRUE(hdf5.readDataset("/Group1/Group2/Data", matRead))
      << "Reading Eigen::MatrixXd failed.";
  EXPECT_TRUE(mat.isApprox(matRead))
      << "Matrix read does not match matrix written.\nWritten:\n" << mat
      << "\nRead:\n" << matRead;

  ASSERT_TRUE(hdf5.closeFile())
      << "Closing test file '" << tmpFileName << "' failed.";

  remove(tmpFileName);
}

TEST(Hdf5Test, thresholdsEigenMatrixXd)
{
  Hdf5DataFormat hdf5;
  size_t threshold = 12;
  hdf5.setThreshold(threshold);
  EXPECT_EQ(hdf5.threshold(), threshold);

  int numDoubles = threshold/sizeof(double);

  EXPECT_FALSE(hdf5.exceedsThreshold(Eigen::MatrixXd(1, numDoubles - 1)))
      << "Bad threshold check result for small data.";
  EXPECT_FALSE(hdf5.exceedsThreshold(Eigen::MatrixXd(1, numDoubles)))
      << "Bad threshold check result for data at threshold limit.";
  EXPECT_TRUE(hdf5.exceedsThreshold(Eigen::MatrixXd(1, numDoubles + 1)))
      << "Bad threshold check result for large data.";

}

TEST(Hdf5Test, datasetInteraction)
{
  char tmpFileName [L_tmpnam];
  tmpnam(tmpFileName);

  Hdf5DataFormat hdf5;
  ASSERT_TRUE(hdf5.openFile(tmpFileName, Hdf5DataFormat::ReadWriteTruncate))
      << "Opening test file '" << tmpFileName << "' failed.";

  Eigen::MatrixXd mat(1,1);
  mat(0, 0) = 0.0;

  EXPECT_TRUE(hdf5.writeDataset("/TLDData", mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/Group1/DeeperData", mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/Group1/Group2/EvenDeeperData", mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/Group1/DeeperDataSibling", mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/Group1/Group2a/Grandchild", mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/Group1/Group2a/Group3/Group4/Group5/Deeeep",
                                mat))
      << "Writing Eigen::MatrixXd failed.";
  EXPECT_TRUE(hdf5.writeDataset("/TLDataSibling", mat))
      << "Writing Eigen::MatrixXd failed.";


  std::vector<std::string> refDatasets;
  refDatasets.resize(7);
  refDatasets[0] = "Group1/DeeperData";
  refDatasets[1] = "Group1/DeeperDataSibling";
  refDatasets[2] = "Group1/Group2/EvenDeeperData";
  refDatasets[3] = "Group1/Group2a/Grandchild";
  refDatasets[4] = "Group1/Group2a/Group3/Group4/Group5/Deeeep";
  refDatasets[5] = "TLDData";
  refDatasets[6] = "TLDataSibling";
  EXPECT_EQ(refDatasets, hdf5.datasets()) << "List of dataset unexpected.";

  EXPECT_FALSE(hdf5.datasetExists("/IShouldNotExist"))
      << "Non-existing dataset reported as found.";

  for (size_t i = 0; i < refDatasets.size(); ++i) {
    const std::string &str = refDatasets[i];
    EXPECT_TRUE(hdf5.datasetExists(str))
        << "Data set should exist, but isn't found: " << str;
    EXPECT_TRUE(hdf5.removeDataset(str))
        << "Error removing dataset " << str;
    EXPECT_FALSE(hdf5.datasetExists(str))
        << "Removed dataset still exists: " << str;
  }

  ASSERT_TRUE(hdf5.closeFile())
      << "Closing test file '" << tmpFileName << "' failed.";

  remove(tmpFileName);
}
