# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Generic output file parser and related tools"""

import bz2
import fileinput
import gzip
import inspect
import io
import logging
import numpy
import os
import random
import sys
import zipfile

from . import utils
from .data import ccData

# This seems to avoid a problem with Avogadro.
logging.logMultiprocessing = 0


class myBZ2File(bz2.BZ2File):
    """Return string instead of bytes"""
    def __next__(self):
        line = super(bz2.BZ2File, self).__next__()
        return line.decode("ascii", "replace")

    def next(self):
        line = self.__next__()
        return line


class myGzipFile(gzip.GzipFile):
    """Return string instead of bytes"""
    def __next__(self):
        super_ob = super(gzip.GzipFile, self)
        # seemingly different versions of gzip can have either next or __next__
        if hasattr(super_ob, 'next'):
            line = super_ob.next()
        else:
            line = super_ob.__next__()
        return line.decode("ascii", "replace")

    def next(self):
        line = self.__next__()
        return line


class myFileinputFile(fileinput.FileInput):
    """Implement next() method"""
    def next(self):
        line = next(self)
        return line


class FileWrapper(object):
    """Wrap a file-like object or stream with some custom tweaks"""

    def __init__(self, source, pos=0):

        self.src = source

        # Most file-like objects have seek and tell methods, but streams returned
        # by urllib.urlopen in Python2 do not, which will raise an AttributeError
        # in this code. On the other hand, in Python3 these methods do exist since
        # urllib uses the stream class in the io library, but they raise a different
        # error, namely is.UnsupportedOperation. That is why it is hard to be more
        # specific with except block here.
        try:

            self.src.seek(0, 2)
            self.size = self.src.tell()
            self.src.seek(pos, 0)
            self.pos = pos

        except:

            # Stream returned by urllib should have size information.
            if hasattr(self.src, 'headers') and 'content-length' in self.src.headers:
                self.size = int(self.src.headers['content-length'])

            # Assume the position is what was passed to the constructor.
            self.pos = pos

    def next(self):
        line = next(self.src)
        self.pos += len(line)
        return line

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self

    def close(self):
        self.src.close()

    def seek(self, pos, ref):

        # If we are seeking to end, we can emulate it usually. As explained above,
        # we cannot be too specific with the except clause due to differences
        # between Python2 and 3. Yet another reason to drop Python 2 soon!
        try:
            self.src.seek(pos, ref)
        except:
            if ref == 2:
                self.src.read()
            else:
                raise

        if ref == 0:
            self.pos = pos
        if ref == 1:
            self.pos += pos
        if ref == 2 and hasattr(self, 'size'):
            self.pos = self.size


def openlogfile(filename):
    """Return a file object given a filename.

    Given the filename of a log file or a gzipped, zipped, or bzipped
    log file, this function returns a file-like object.

    Given a list of filenames, this function returns a FileInput object,
    which can be used for seamless iteration without concatenation.
    """

    # If there is a single string argument given.
    if type(filename) in [str, str]:

        extension = os.path.splitext(filename)[1]

        if extension == ".gz":
            fileobject = myGzipFile(filename, "r")

        elif extension == ".zip":
            zip = zipfile.ZipFile(filename, "r")
            assert len(zip.namelist()) == 1, "ERROR: Zip file contains more than 1 file"
            fileobject = io.StringIO(zip.read(zip.namelist()[0]).decode("ascii", "ignore"))

        elif extension in ['.bz', '.bz2']:
            # Module 'bz2' is not always importable.
            assert bz2 is not None, "ERROR: module bz2 cannot be imported"
            fileobject = myBZ2File(filename, "r")

        else:
            fileobject = FileWrapper(io.open(filename, "r", errors='ignore'))

        return fileobject

    elif hasattr(filename, "__iter__"):

        # This is needed, because fileinput will assume stdin when filename is empty.
        if len(filename) == 0:
            return None

        # Compression (gzip and bzip) is supported as of Python 2.5.
        if sys.version_info[0] >= 2 and sys.version_info[1] >= 5:
            fileobject = fileinput.input(filename, openhook=fileinput.hook_compressed)
        else:
            fileobject = myFileinputFile(filename)

        return fileobject


class Logfile(object):
    """Abstract class for logfile objects.

    Subclasses defined by cclib:
        ADF, DALTON, GAMESS, GAMESSUK, Gaussian, Jaguar, Molpro, NWChem, ORCA,
          Psi, QChem
    """

    def __init__(self, source, loglevel=logging.INFO, logname="Log",
                 logstream=sys.stdout, datatype=ccData, **kwds):
        """Initialise the Logfile object.

        This should be called by a subclass in its own __init__ method.

        Inputs:
            source - a logfile, list of logfiles, or stream with at least a read method
            loglevel - integer corresponding to a log level from the logging module
            logname - name of the source logfile passed to this constructor
            logstream - where to output the logging information
            datatype - class to use for gathering data attributes
        """

        # Set the filename to source if it is a string or a list of strings, which are
        # assumed to be filenames. Otherwise, assume the source is a file-like object
        # if it has a read method, and we will try to use it like a stream.
        if isinstance(source, str):
            self.filename = source
            self.isstream = False
        elif isinstance(source, list) and all([isinstance(s, str) for s in source]):
            self.filename = source
            self.isstream = False
        elif hasattr(source, "read"):
            self.filename = "stream %s" % str(type(source))
            self.isstream = True
            self.stream = source
        else:
            raise ValueError

        # Set up the logger.
        # Note that calling logging.getLogger() with one name always returns the same instance.
        # Presently in cclib, all parser instances of the same class use the same logger,
        #   which means that care needs to be taken not to duplicate handlers.
        self.loglevel = loglevel
        self.logname = logname
        self.logger = logging.getLogger('%s %s' % (self.logname, self.filename))
        self.logger.setLevel(self.loglevel)
        if len(self.logger.handlers) == 0:
            handler = logging.StreamHandler(logstream)
            handler.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
            self.logger.addHandler(handler)

        # Periodic table of elements.
        self.table = utils.PeriodicTable()

        # This is the class that will be used in the data object returned by parse(), and should
        # normally be ccData or a subclass of it.
        self.datatype = datatype

        # Change the class used if we want optdone to be a list or if the 'future' option
        # is used, which might have more consequences in the future.
        optdone_as_list = kwds.get("optdone_as_list", False) or kwds.get("future", False)
        optdone_as_list = optdone_as_list if isinstance(optdone_as_list, bool) else False
        if not optdone_as_list:
            from .data import ccData_optdone_bool
            self.datatype = ccData_optdone_bool

    def __setattr__(self, name, value):

        # Send info to logger if the attribute is in the list self._attrlist.
        if name in getattr(self, "_attrlist", {}) and hasattr(self, "logger"):

            # Call logger.info() only if the attribute is new.
            if not hasattr(self, name):
                if type(value) in [numpy.ndarray, list]:
                    self.logger.info("Creating attribute %s[]" % name)
                else:
                    self.logger.info("Creating attribute %s: %s" % (name, str(value)))

        # Set the attribute.
        object.__setattr__(self, name, value)

    def parse(self, progress=None, fupdate=0.05, cupdate=0.002):
        """Parse the logfile, using the assumed extract method of the child."""

        # Check that the sub-class has an extract attribute,
        #  that is callable with the proper number of arguemnts.
        if not hasattr(self, "extract"):
            raise AttributeError("Class %s has no extract() method." % self.__class__.__name__)
        if not callable(self.extract):
            raise AttributeError("Method %s._extract not callable." % self.__class__.__name__)
        if len(inspect.getargspec(self.extract)[0]) != 3:
            raise AttributeError("Method %s._extract takes wrong number of arguments." % self.__class__.__name__)

        # Save the current list of attributes to keep after parsing.
        # The dict of self should be the same after parsing.
        _nodelete = list(set(self.__dict__.keys()))

        # Initiate the FileInput object for the input files.
        # Remember that self.filename can be a list of files.
        if not self.isstream:
            inputfile = openlogfile(self.filename)
        else:
            inputfile = FileWrapper(self.stream)

        # Intialize self.progress
        is_compressed = isinstance(inputfile, myGzipFile) or isinstance(inputfile, myBZ2File)
        if progress and not (is_compressed):
            self.progress = progress
            self.progress.initialize(inputfile.size)
            self.progress.step = 0
        self.fupdate = fupdate
        self.cupdate = cupdate

        # Maybe the sub-class has something to do before parsing.
        self.before_parsing()

        # Loop over lines in the file object and call extract().
        # This is where the actual parsing is done.
        for line in inputfile:

            self.updateprogress(inputfile, "Unsupported information", cupdate)

            # This call should check if the line begins a section of extracted data.
            # If it does, it parses some lines and sets the relevant attributes (to self).
            # Any attributes can be freely set and used across calls, however only those
            #   in data._attrlist will be moved to final data object that is returned.
            self.extract(inputfile, line)

        # Close input file object.
        if not self.isstream:
            inputfile.close()

        # Maybe the sub-class has something to do after parsing.
        self.after_parsing()

        # If atomcoords were not parsed, but some input coordinates were ("inputcoords").
        # This is originally from the Gaussian parser, a regression fix.
        if not hasattr(self, "atomcoords") and hasattr(self, "inputcoords"):
            self.atomcoords = numpy.array(self.inputcoords, 'd')

        # Set nmo if not set already - to nbasis.
        if not hasattr(self, "nmo") and hasattr(self, "nbasis"):
            self.nmo = self.nbasis

        # Creating deafult coreelectrons array.
        if not hasattr(self, "coreelectrons") and hasattr(self, "natom"):
            self.coreelectrons = numpy.zeros(self.natom, "i")

        # Create the data object we want to return. This is normally ccData, but can be changed
        # by passing the datatype argument to the constructor. All supported cclib attributes
        # are copied to this object, but beware that in order to be moved an attribute must be
        # included in the data._attrlist of ccData (or whatever else).
        # There is the possibility of passing assitional argument via self.data_args, but
        # we use this sparingly in cases where we want to limit the API with options, etc.
        data = self.datatype(attributes=self.__dict__)

        # Now make sure that the cclib attributes in the data object are all the correct type,
        # including arrays and lists of arrays.
        data.arrayify()

        # Delete all temporary attributes (including cclib attributes).
        # All attributes should have been moved to a data object, which will be returned.
        for attr in list(self.__dict__.keys()):
            if not attr in _nodelete:
                self.__delattr__(attr)

        # Update self.progress as done.
        if hasattr(self, "progress"):
            self.progress.update(inputfile.size, "Done")

        return data

    def before_parsing(self):
        """Set parser-specific variables and do other initial things here."""
        pass

    def after_parsing(self):
        """Correct data or do parser-specific validation after parsing is finished."""
        pass

    def updateprogress(self, inputfile, msg, xupdate=0.05):
        """Update progress."""

        if hasattr(self, "progress") and random.random() < xupdate:
            newstep = inputfile.pos
            if newstep != self.progress.step:
                self.progress.update(newstep, msg)
                self.progress.step = newstep

    def normalisesym(self, symlabel):
        """Standardise the symmetry labels between parsers.

        This method should be overwritten by individual parsers, and should
        contain appropriate doctests. If is not overwritten, this is detected
        as an error by unit tests.
        """
        return "ERROR: This should be overwritten by this subclass"

    def float(self, number):
        """Convert a string to a float.

        This method should perform certain checks that are specific to cclib,
        including avoiding the problem with Ds instead of Es in scientific notation.
        Another point is converting string signifying numerical problems (*****)
        to something we can manage (Numpy's NaN).

        >>> t = Logfile("dummyfile")
        >>> t.float("123.2323E+02")
        12323.23
        >>> t.float("123.2323D+02")
        12323.23
        >>> t.float("*****")
        nan
        """

        if list(set(number)) == ['*']:
            return numpy.nan

        return float(number.replace("D", "E"))

    def set_attribute(self, name, value, check=True):
        """Set an attribute and perform a check when it already exists.

        Note that this can be used for scalars and lists alike, whenever we want
        to set a value for an attribute. By default we want to check that
        the value does not change if the attribute already exists, and this function
        is a good place to add more tests in the future.
        """
        if check and hasattr(self, name):
            try:
                assert getattr(self, name) == value
            except AssertionError:
                self.logger.warning("Attribute %s changed value (%s -> %s)" % (name, getattr(self, name), value))
        setattr(self, name, value)

    def skip_lines(self, inputfile, sequence):
        """Read trivial line types and check they are what they are supposed to be.

        This function will read len(sequence) lines and do certain checks on them,
        when the elements of sequence have the appropriate values. Currently the
        following elements trigger checks:
            'blank' or 'b'      - the line should be blank
            'dashes' or 'd'     - the line should contain only dashes (or spaces)
            'equals' or 'e'     - the line should contain only equal signs (or spaces)
            'stars' or 's'      - the line should contain only stars (or spaces)
        """

        expected_characters = {
            '-': ['dashes', 'd'],
            '=': ['equals', 'e'],
            '*': ['stars', 's'],
        }

        lines = []
        for expected in sequence:

            # Read the line we want to skip.
            line = next(inputfile)

            # Blank lines are perhaps the most common thing we want to check for.
            if expected in ["blank", "b"]:
                try:
                    assert line.strip() == ""
                except AssertionError:
                    frame, fname, lno, funcname, funcline, index = inspect.getouterframes(inspect.currentframe())[1]
                    parser = fname.split('/')[-1]
                    msg = "In %s, line %i, line not blank as expected: %s" % (parser, lno, line.strip())
                    self.logger.warning(msg)

            # All cases of heterogeneous lines can be dealt with by the same code.
            for character, keys in expected_characters.items():
                if expected in keys:
                    try:
                        assert all([c == character for c in line.strip() if c != ' '])
                    except AssertionError:
                        frame, fname, lno, funcname, funcline, index = inspect.getouterframes(inspect.currentframe())[1]
                        parser = fname.split('/')[-1]
                        msg = "In %s, line %i, line not all %s as expected: %s" % (parser, lno, keys[0], line.strip())
                        self.logger.warning(msg)
                        continue

            # Save the skipped line, and we will return the whole list.
            lines.append(line)

        return lines

    skip_line = lambda self, inputfile, expected: self.skip_lines(inputfile, [expected])


if __name__ == "__main__":
    import doctest
    doctest.testmod()
