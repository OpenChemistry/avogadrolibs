TEMPLATE = subdirs

SUBDIRS +=  jkqtmathtextlib  jkqtmathtext_test

jkqtmathtextlib.file = ../../qmake/staticlib/jkqtmathtextlib/jkqtmathtextlib.pro

jkqtmathtext_test.file=$$PWD/jkqtmathtext_test.pro
jkqtmathtext_test.depends = jkqtmathtextlib
