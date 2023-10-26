#ifndef AVOGADRO_PythonCmdLineInterface_H
#define AVOGADRO_PythonCmdLineInterface_H

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QProcess>
#include <QtWidgets/QMessageBox>
#include <QtCore/QFile>

void activateEnvironment(const QString& envType, const QString& envName);
QStringList detectPythonInterpreters();
void installRequirements(const QString& folderPath, const QString& installMethod);

#endif