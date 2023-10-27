#include "pythoncmdlineinterface.h"

bool isBinaryPresent(const QString& binaryName) {
    QProcess process;
    process.start(binaryName, QStringList() << "--version");
    process.waitForFinished();
    return process.exitCode() == 0;
}

void installRequirements(const QString& folderPath, const QString& installMethod, const QString& pythonInstallation) {
    if (installMethod.isEmpty()) {
        return;
    }

    if (!isBinaryPresent(installMethod)) {
        QMessageBox::critical(nullptr, "Installation Error", installMethod + " is not installed on this system.");
        return;
    }

    // Extract the environment name from pythonInstallation, if present
    QString envName;
    int colonIndex = pythonInstallation.indexOf(":");
    int parenIndex = pythonInstallation.indexOf("(");
    if (parenIndex != -1 && colonIndex != -1) {
        envName = pythonInstallation.mid(parenIndex + 1, colonIndex - parenIndex - 1).trimmed();
    }

    // Prepare environment activation command only if envName is not empty
    QString activateCommand;
    if (!envName.isEmpty()) {
        if (pythonInstallation.contains("Conda")) {
            activateCommand = (QSysInfo::productType() == "windows") ? 
                               QString("activate %1 && ").arg(envName) : 
                               QString("conda activate %1 && ").arg(envName);
        } else if (pythonInstallation.contains("VirtualEnv")) {
            activateCommand = (QSysInfo::productType() == "windows") ? 
                               QString("%1\\Scripts\\activate && ").arg(envName) : 
                               QString("source %1/bin/activate && ").arg(envName);
        }
    }

    QString requirementsTxt = folderPath + "/requirements.txt";
    QString pyprojectToml = folderPath + "/pyproject.toml";
    QString installCommand;

    if (QFile::exists(requirementsTxt)) {
        if (installMethod == "pip") {
            installCommand = activateCommand + "pip install -r " + requirementsTxt;
        } else if (installMethod == "conda") {
            installCommand = activateCommand + "conda install --file " + requirementsTxt;
        }
    } else if (QFile::exists(pyprojectToml)) {
        if (installMethod == "pip") {
            installCommand = activateCommand + "pip install " + folderPath;
        } else if (installMethod == "conda") {
            QMessageBox::information(nullptr, "Installation Info", "Conda cannot install from a pyproject.toml file.");
            return;
        }
    }

    if (!installCommand.isEmpty()) {
        QProcess process;
        process.start(installCommand);
        process.waitForFinished();

        if (process.exitCode() != 0) {
            QMessageBox::critical(nullptr, "Installation Error", process.readAllStandardError());
        }
    } else {
        QMessageBox::information(nullptr, "No Requirements Found", "Neither requirements.txt nor pyproject.toml found.");
    }
}

QString extractPythonPaths(const QString& pythonInterpreterString) {
    int colonIndex = pythonInterpreterString.lastIndexOf(":");
    if (colonIndex != -1) {
        QString path = pythonInterpreterString.mid(colonIndex + 1).trimmed();
        return path;
    }
    return "";
}
 
QString pythonInterpreterVersion(const QString& interpreterPath) {
    QProcess process;
    process.start(interpreterPath + " --version");
    process.waitForFinished();
    if ( process.exitCode() == 0 ) {
        return process.readAllStandardOutput();
    } else {
        return "Python";
    }
}

QStringList detectPythonInterpreters() {
    QStringList interpreters;
    QProcess process;
    QString pythonCmd = (QSysInfo::productType() == "windows") ? "where python" : "which python";
    process.start(pythonCmd);
    process.waitForFinished();
    QString systemPythonPath = process.readAllStandardOutput();
    if (!systemPythonPath.isEmpty()) {
        QString pythonPath = systemPythonPath.trimmed();
        interpreters << QString("%1: %2").arg(pythonInterpreterVersion(pythonPath),pythonPath);
    }
    process.start("conda env list");
    process.waitForFinished();
    QString condaEnvsOutput = process.readAllStandardOutput();
    auto lines = condaEnvsOutput.split('\n');
    for (const QString& line : lines.mid(2)) {
        if (!line.isEmpty()) {
            auto parts = line.split(' ');
            QString envName = parts[0];
            QString envPath = parts.last();
            QString pythonPath = envPath + QDir::separator() + "bin" + QDir::separator() + "python";
            interpreters << QString("%1 (Conda: %2): %3").arg(pythonInterpreterVersion(pythonPath),envName, pythonPath);
        }
    }
    // virtualenv cannot be detected automatically
    return interpreters;
}

void activateEnvironment(const QString& envType, const QString& envName) {
    QProcess process;
    if (envType == "Conda") {
        process.start("conda --version");
        process.waitForFinished();
        if (process.exitCode() != 0) {
            QMessageBox::warning(nullptr, "Activation Failed", "Conda is not installed on this computer.");
            return;
        }
        if (envName == "") {
            process.start("conda deactivate");
        } else {
            process.start(QString("conda activate %1").arg(envName));
        }
    } else if (envType == "VirtualEnv") {
        if (envName == "") {
            process.start("deactivate");
        } else {
            process.start(QString("source %1/bin/activate").arg(envName));
        }
    }
    process.waitForFinished();
    if (process.exitCode() != 0) {
        QMessageBox::warning(nullptr, "Activation Failed", "Failed to activate or deactivate environment");
    }
}

QString extractInstallerCodeFrom(const QString& interpreter) {
    bool hasConda = false;
    bool hasPip = false;

    if (interpreter.contains("Conda")) {
        hasConda = true;
    }
    if (interpreter.contains("VirtualEnv")) {
        hasPip = true;
    }

    if (hasConda) {
        return "conda";
    } else if (hasPip) {
        return "pip";
    } else {
        return "";
    }
}
