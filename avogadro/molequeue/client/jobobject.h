/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_JOBOBJECT_H
#define AVOGADRO_MOLEQUEUE_JOBOBJECT_H

#include "avogadromolequeueexport.h"

#include <QtCore/QJsonObject>

#include <QtCore/QString>
#include <QtCore/QVariant>

namespace Avogadro {
namespace MoleQueue {

/**
 * @class JobObject jobobject.h <molequeue/client/jobobject.h>
 * @brief Simple client-side representation for a MoleQueue job.
 * @author Marcus D. Hanwell
 *
 * The Job class provides a simple interface to the client side representation
 * of a job to be submitted to MoleQueue. Any fields that are not set/present
 * will be omitted entirely, or set to default values by MoleQueue. The internal
 * representation of a job (and the transport used) is JSON.
 *
 * The Job class and data structure is very lightweight, and designed to be
 * easily copied, modified and passed around.
 */

class AVOGADROMOLEQUEUE_EXPORT JobObject
{
public:
  JobObject();
  ~JobObject();

  /** Set the @p value of the specified @p key. */
  void setValue(const QString &key, const QVariant &value);

  /** Get the value of the specified @p key. If the key is not set, return
   * @p defaultValue. */
  QVariant value(const QString &key,
                 const QVariant &defaultValue = QVariant()) const;

  /**
   * Set the job up using the supplied JSON object. This replaces all previous
   * settings that may have been applied.
   */
  void fromJson(const QJsonObject &jsonObject) { m_value = jsonObject; }

  /** Get the JSON object with the current job settings in it. */
  QJsonObject json() const { return m_value; }

  /**
   * Set the queue that the job should be submitted to. This must be a valid
   * queue name discovered using the client API.
   */
  void setQueue(const QString &queueName);

  /**
   * Get the name of the queue that the job will be submitted to. An empty
   * string means that no queue has been set.
   */
  QString queue() const;

  /**
   * Set the program that the job should be submitted to. This must be a valid
   * program in a valid queue as discovered using the client API.
   */
  void setProgram(const QString &programName);

  /**
   * Get the name of the program that the job will be submitted to. An empty
   * string means that no program has been set.
   */
  QString program() const;

  /**
   * Set the description of the job, this is free text.
   */
  void setDescription(const QString &descriptionText);

  /**
   * Get the description of the job.
   */
  QString description() const;

  /**
   * @brief Set the input file for the job.
   * @param fileName The file name as it will appear in the working directory.
   * @param contents The contents of the file specified.
   */
  void setInputFile(const QString &fileName, const QString &contents);

  /**
   * Set the input file for the job, the file will be copied and the file name
   * used in the working directory of the job submission.
   * \param path The full path to the input file.
   */
  void setInputFile(const QString &path);

  /**
   * Set the input file using a JSON object. This must conform to the file
   * specification.
   * @param file A JSON object employing file specification to specify input.
   */
  void setInputFile(const QJsonObject &file);

  /**
   * Get the input file for the job. This is a JSON object using the file spec.
   */
  QJsonObject inputFile() const;

  /**
   * Append an additional input file for the job.
   * @param fileName The file name as it will appear in the working directory.
   * @param contents The contents of the file specified.
   */
  void appendAdditionalInputFile(const QString &fileName,
                                 const QString &contents);

  /**
   * Append an additional input file for the job, the file will be copied and
   * the file name used in the working directory of the job submission.
   * @param path The full path to the input file.
   */
  void appendAdditionalInputFile(const QString &path);

  /**
   * Set the additional input file using a JSON object. This must conform to the
   * file specification.
   * @param files A JSON array employing file specification to specify input.
   */
  void setAdditionalInputFiles(const QJsonArray &files);

  /** Clear additional input files. */
  void clearAdditionalInputFiles();

  /**
   * Get the additional input files for the job. This is a JSON object using the
   * file spec.
   */
  QJsonArray additionalInputFiles() const;

protected:
  QJsonObject m_value;

  /**
   * Generate a filespec JSON object form the supplied file name and contents.
   */
  QJsonObject fileSpec(const QString &fileName, const QString &contents);

  /**
   * Generate a filespec JSON object form the supplied file path (must exist).
   */
  QJsonObject fileSpec(const QString &path);
};

} // End namespace MoleQueue
} // End namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_JOBOBJECT_H
