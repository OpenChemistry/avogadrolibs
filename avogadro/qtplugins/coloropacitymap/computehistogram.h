/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_COMPUTE_HISTOGRAM_H
#define AVOGADRO_COMPUTE_HISTOGRAM_H

#include <vtkDoubleArray.h>
#include <vtkFloatArray.h>
#include <vtkImageData.h>
#include <vtkIntArray.h>
#include <vtkMath.h>
#include <vtkPointData.h>
#include <vtkTable.h>

#include <cmath>

namespace Avogadro {

/** Single component integral type specialization. */
template <typename T,
          typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
void calcHistogram(T* values, const vtkIdType numTuples, const float min,
                   const float inv, int* pops, int&)
{
  for (vtkIdType j = 0; j < numTuples; ++j) {
    ++pops[static_cast<int>((*values++ - min) * inv)];
  }
}

/** Needs to be present, should never be compiled. */
template <typename T>
void calcHistogram(T*, const vtkIdType, int*)
{
  static_assert(!std::is_same<unsigned char, T>::value, "Invalid type");
}

/** Single component unsigned char covering 0 -> 255 range. */
void calcHistogram(unsigned char* values, const vtkIdType numTuples, int* pops)
{
  for (vtkIdType j = 0; j < numTuples; ++j) {
    ++pops[*values++];
  }
}

/** Single component floating point type specialization. */
template <typename T,
          typename std::enable_if<!std::is_integral<T>::value>::type* = nullptr>
void calcHistogram(T* values, const vtkIdType numTuples, const float min,
                   const float inv, int* pops, int& invalid)
{
  for (vtkIdType j = 0; j < numTuples; ++j) {
    T value = *(values++);
    if (std::isfinite(value)) {
      ++pops[static_cast<int>((value - min) * inv)];
    } else {
      ++invalid;
    }
  }
}

/**
 * Computes a histogram from an array of values.
 * \param values The array from which to compute the histogram.
 * \param numTuples Number of tuples in the array.
 * \param numComponents Number of components in each tuple.
 * \param min Minimum value in range
 * \param max Maximum value in range
 * \param inv Inverse of bin size, numBins is the number of bins
 * in the histogram (or length of the pops array), and invalid is a return
 * parameter indicating how many values in the array had a non-finite value.
 */
template <typename T>
void CalculateHistogram(T* values, const vtkIdType numTuples,
                        const vtkIdType numComponents, const float min,
                        const float max, int* pops, const float inv,
                        int& invalid)
{
  // Single component is a simpler/faster path, let's dispatch separately.
  if (numComponents == 1) {
    // Very fast path for unsigned char in 0 -> 255 range, or fast path.
    if (std::is_same<T, unsigned char>::value && min == 0.f && max == 255.f) {
      calcHistogram(values, numTuples, pops);
    } else {
      calcHistogram(values, numTuples, min, inv, pops, invalid);
    }
  } else {
    // Multicomponent magnitude
    for (vtkIdType j = 0; j < numTuples; ++j) {
      // Check that all components are valid.
      bool valid = true;
      double squaredSum = 0.0;
      for (vtkIdType c = 0; c < numComponents; ++c) {
        T value = *(values + c);
        if (!vtkMath::IsFinite(value)) {
          valid = false;
          break;
        }
        squaredSum += (value * value);
      }
      if (valid) {
        int index = static_cast<int>((sqrt(squaredSum) - min) * inv);
        ++pops[index];
      } else {
        ++invalid;
      }
      values += numComponents;
    }
  }
}

void PopulateHistogram(vtkImageData* input, vtkTable* output)
{
  // The output table will have the twice the number of columns, they will be
  // the x and y for input column. This is the bin centers, and the population.
  double minmax[2] = { 0.0, 0.0 };

  // This number of bins in the 2D histogram will also be used as the number of
  // bins in the 2D transfer function for X (scalar value) and Y (gradient mag.)
  const int numberOfBins = 256;

  // Keep the array we are working on around even if the user shallow copies
  // over the input image data by incrementing the reference count here.
  vtkSmartPointer<vtkDataArray> arrayPtr = input->GetPointData()->GetScalars();
  if (!arrayPtr) {
    return;
  }

  // The bin values are the centers, extending +/- half an inc either side
  arrayPtr->GetFiniteRange(minmax, -1);
  if (minmax[0] == minmax[1]) {
    minmax[1] = minmax[0] + 1.0;
  }

  double inc = (minmax[1] - minmax[0]) / (numberOfBins - 1);
  double halfInc = inc / 2.0;
  vtkSmartPointer<vtkFloatArray> extents =
    vtkFloatArray::SafeDownCast(output->GetColumnByName("image_extents"));
  if (!extents) {
    extents = vtkSmartPointer<vtkFloatArray>::New();
    extents->SetName("image_extents");
  }
  extents->SetNumberOfTuples(numberOfBins);
  double min = minmax[0] + halfInc;
  for (int j = 0; j < numberOfBins; ++j) {
    extents->SetValue(j, min + j * inc);
  }
  vtkSmartPointer<vtkIntArray> populations =
    vtkIntArray::SafeDownCast(output->GetColumnByName("image_pops"));
  if (!populations) {
    populations = vtkSmartPointer<vtkIntArray>::New();
    populations->SetName("image_pops");
  }
  populations->SetNumberOfTuples(numberOfBins);
  auto pops = static_cast<int*>(populations->GetVoidPointer(0));
  for (int k = 0; k < numberOfBins; ++k) {
    pops[k] = 0;
  }
  int invalid = 0;

  switch (arrayPtr->GetDataType()) {
    vtkTemplateMacro(CalculateHistogram(
      reinterpret_cast<VTK_TT*>(arrayPtr->GetVoidPointer(0)),
      arrayPtr->GetNumberOfTuples(), arrayPtr->GetNumberOfComponents(),
      minmax[0], minmax[1], pops, 1.0 / inc, invalid));
    default:
      cout << "UpdateFromFile: Unknown data type" << endl;
  }

#ifndef NDEBUG
  vtkIdType total = invalid;
  for (int i = 0; i < numberOfBins; ++i)
    total += pops[i];
  assert(total == arrayPtr->GetNumberOfTuples());
#endif
  if (invalid) {
    cout << "Warning: NaN or infinite value in dataset" << endl;
  }

  output->AddColumn(extents);
  output->AddColumn(populations);
}

} // namespace Avogadro
#endif // AVOGADRO_COMPUTE_HISTOGRAM_H
