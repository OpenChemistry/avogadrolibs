TEMPLATE = subdirs

SUBDIRS +=  jkqtplotterlib test_distributionplot

jkqtplotterlib.file = ../../qmake/staticlib/jkqtplotterlib/jkqtplotterlib.pro

test_distributionplot.file=$$PWD/test_distributionplot.pro
test_distributionplot.depends = jkqtplotterlib
