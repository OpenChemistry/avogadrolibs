# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Facilities for moving parsed data to other cheminformatic libraries."""

try:
    import openbabel
except ImportError:
    pass
else:
    from .cclib2openbabel import makeopenbabel

try:
    import PyQuante
except ImportError:
    pass
else:
    from .cclib2pyquante import makepyquante

try:
    import Bio
except ImportError:
    pass
else:
    from .cclib2biopython import makebiopython
