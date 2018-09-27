cd ..

git init .

git remote add origin git://github.com/OpenChemistry/openchemistry.git

git pull origin master

git -c submodule.avogadrolibs.update=none submodule update --init

cd ../

mkdir openchemistry-build

cd openchemistry-build

choco install ninja

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64

cmake -G %CMAKE_GENERATOR% ../openchemistry

cmake --build . --target avogadrolibs --config Release
