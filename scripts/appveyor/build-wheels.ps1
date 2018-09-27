trap { Write-Error $_; Exit 1 }

set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"
Invoke-WebRequest -Uri "https://github.com/pybind/pybind11/archive/v2.2.4.zip" -OutFile "v2.2.4.zip"
sz x v2.2.4.zip -oC:\projects -aoa -r
Invoke-WebRequest -Uri "http://bitbucket.org/eigen/eigen/get/3.3.5.zip" -OutFile "3.3.5.zip"
sz x  3.3.5.zip -oC:\projects -aoa -r
C:\Python35-x64\python.exe C:\projects\avogadrolibs\scripts\appveyor\windows_build_wheels.py
