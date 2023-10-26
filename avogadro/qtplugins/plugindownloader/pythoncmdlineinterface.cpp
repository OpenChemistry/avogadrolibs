#include "pythoncmdlineinterface.h"

QStringList detectPythonInterpreters() {
    QStringList interpreters;
    QProcess process;
    QString pythonCmd = (QSysInfo::productType() == "windows") ? "where python" : "which python";
    process.start(pythonCmd);
    process.waitForFinished();
    QString systemPythonPath = process.readAllStandardOutput();
    if (!systemPythonPath.isEmpty()) {
        interpreters << QString("Python (base): %1").arg(systemPythonPath.trimmed());
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
            interpreters << QString("Python (Conda: %1): %2").arg(envName, envPath);
        }
    }
    process.start("virtualenv --list");
    process.waitForFinished();
    QString venvsOutput = process.readAllStandardOutput();
    lines = venvsOutput.split('\n');
    for (const QString& line : lines) {
        if (!line.isEmpty()) {
            interpreters << QString("Python (VirtualEnv: %1)").arg(line.trimmed());
        }
    }
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
        if (envName == "base") {
            process.start("conda deactivate");
        } else {
            process.start(QString("conda activate %1").arg(envName));
        }
    } else if (envType == "VirtualEnv") {
        if (envName == "base") {
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