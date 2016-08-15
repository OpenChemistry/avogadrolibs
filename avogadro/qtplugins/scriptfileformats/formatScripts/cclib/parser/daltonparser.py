# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006-2015, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for DALTON output files"""

from __future__ import print_function

import numpy

from . import logfileparser
from . import utils


class DALTON(logfileparser.Logfile):
    """A DALTON log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(DALTON, self).__init__(logname="DALTON", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "DALTON log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'DALTON("%s")' % (self.filename)

    def normalisesym(self, label):
        """Normalise the symmetries used by DALTON."""

        # It appears that DALTON is using the correct labels.
        return label

    def before_parsing(self):

        # Used to decide whether to wipe the atomcoords clean.
        self.firststdorient = True

        # Use to track which section/program output we are parsing,
        # since some programs print out the same headers, which we
        # would like to use as triggers.
        self.section = None

        # If there is no symmetry, assume this.
        self.symlabels = ['Ag']

    def parse_geometry(self, lines):
        """Parse DALTON geometry lines into an atomcoords array."""

        coords = []
        for lin in lines:

            # Without symmetry there are simply four columns, and with symmetry
            # an extra label is printed after the atom type.
            cols = lin.split()
            if cols[1][0] == "_":
                xyz = cols[2:]
            else:
                xyz = cols[1:]

            # The assumption is that DALTON always print in atomic units.
            xyz = [utils.convertor(float(x), 'bohr', 'Angstrom') for x in xyz]
            coords.append(xyz)

        return coords

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # This section at the start of geometry optimization jobs gives us information
        # about optimization targets (geotargets) and possibly other things as well.
        # Notice how the number of criteria required to converge is set to 2 here,
        # but this parameter can (probably) be tweaked in the input.
        #
        # Chosen parameters for *OPTIMI :
        # -------------------------------
        #
        # Default 1st order method will be used:   BFGS update.
        # Optimization will be performed in redundant internal coordinates (by default).
        # Model Hessian will be used as initial Hessian.
        # The model Hessian parameters of Roland Lindh will be used.
        #
        #
        # Trust region method will be used to control step (default).
        #
        # Convergence threshold for gradient set to :      1.00D-04
        # Convergence threshold for energy set to   :      1.00D-06
        # Convergence threshold for step set to     :      1.00D-04
        # Number of convergence criteria set to     :   2
        #
        if line.strip()[:25] == "Convergence threshold for":

            if not hasattr(self, 'geotargets'):
                self.geotargets = []
                self.geotargets_names = []

            target = self.float(line.split()[-1])
            name = line.strip()[25:].split()[0]

            self.geotargets.append(target)
            self.geotargets_names.append(name)

        # This is probably the first place where atomic symmetry labels are printed,
        # somewhere afer the SYMGRP point group information section. We need to know
        # which atom is in which symmetry, since this influences how some things are
        # print later on. We can also get some generic attributes along the way.
        #
        #                                 Isotopic Masses
        #                                 ---------------
        #
        #                           C   _1     12.000000
        #                           C   _2     12.000000
        #                           C   _1     12.000000
        #                           C   _2     12.000000
        #                           ...
        #
        # Note that when there is no symmetry there are only two columns here.
        #
        # It is also a good idea to keep in mind that DALTON, with symmetry on, operates
        # in a specific point group, so symmetry atoms have no internal representation.
        # Therefore only atoms marked as "_1" or "#1" in other places are actually
        # represented in the model. The symmetry atoms (higher symmetry indices) are
        # generated on the fly when writing the output. We will save the symmetry indices
        # here for later use.
        #
        # Additional note: the symmetry labels are printed only for atoms that have
        # symmetry images... so assume "_1" if a label is missing. For example, there will
        # be no label for atoms on an axes, such as the oxygen in water in C2v:
        #
        #                           O          15.994915
        #                           H   _1      1.007825
        #                           H   _2      1.007825
        #
        if line.strip() == "Isotopic Masses":

            self.skip_lines(inputfile, ['d', 'b'])

            # Since some symmetry labels may be missing, read in all lines first.
            lines = []
            line = next(inputfile)
            while line.strip():
                lines.append(line)
                line = next(inputfile)

            # Split lines into columsn and dd any missing symmetry labels, if needed.
            lines = [l.split() for l in lines]
            if any([len(l) == 3 for l in lines]):
                for il, l in enumerate(lines):
                    if len(l) == 2:
                        lines[il] = [l[0], "_1", l[1]]

            atomnos = []
            symmetry_atoms = []
            atommasses = []
            for cols in lines:
                atomnos.append(self.table.number[cols[0]])
                if len(cols) == 3:
                    symmetry_atoms.append(int(cols[1][1]))
                    atommasses.append(float(cols[2]))
                else:
                    atommasses.append(float(cols[1]))

            self.set_attribute('atomnos', atomnos)
            self.set_attribute('atommasses', atommasses)

            self.set_attribute('natom', len(atomnos))
            self.set_attribute('natom', len(atommasses))

            # Save this for later if there were any labels.
            self.symmetry_atoms = symmetry_atoms or None

        # This section is close to the beginning of the file, and can be used
        # to parse natom, nbasis and atomnos. We also construct atombasis here,
        # although that is symmetry-dependent (see inline comments). Note that
        # DALTON operates on the idea of atom type, which are not necessarily
        # unique element-wise.
        #
        #  Atoms and basis sets
        #  --------------------
        #
        #  Number of atom types :    6
        #  Total number of atoms:   20
        #
        #  Basis set used is "STO-3G" from the basis set library.
        #
        #  label    atoms   charge   prim   cont     basis
        #  ----------------------------------------------------------------------
        #  C           6    6.0000    15     5      [6s3p|2s1p]
        #  H           4    1.0000     3     1      [3s|1s]
        #  C           2    6.0000    15     5      [6s3p|2s1p]
        #  H           2    1.0000     3     1      [3s|1s]
        #  C           2    6.0000    15     5      [6s3p|2s1p]
        #  H           4    1.0000     3     1      [3s|1s]
        #  ----------------------------------------------------------------------
        #  total:     20   70.0000   180    60
        #  ----------------------------------------------------------------------
        #
        #  Threshold for neglecting AO integrals:  1.00D-12
        #
        if line.strip() == "Atoms and basis sets":

            self.skip_lines(inputfile, ['d', 'b'])

            line = next(inputfile)
            assert "Number of atom types" in line
            self.ntypes = int(line.split()[-1])

            line = next(inputfile)
            assert "Total number of atoms:" in line
            self.set_attribute("natom", int(line.split()[-1]))

            self.skip_lines(inputfile, ['b', 'basisname', 'b'])

            line = next(inputfile)
            cols = line.split()

            # Detecting which columns things are in will be somewhat more robust
            # to formatting changes in the future.
            iatoms = cols.index('atoms')
            icharge = cols.index('charge')
            icont = cols.index('cont')

            self.skip_line(inputfile, 'dashes')

            atomnos = []
            atombasis = []
            nbasis = 0
            for itype in range(self.ntypes):

                line = next(inputfile)
                cols = line.split()

                atoms = int(cols[iatoms])
                charge = float(cols[icharge])
                assert int(charge) == charge
                charge = int(charge)
                cont = int(cols[icont])

                for at in range(atoms):

                    atomnos.append(charge)

                    # If symmetry atoms are present, these will have basis functions
                    # printed immediately after the one unique atom, so for all
                    # practical purposes cclib can assume the ordering in atombasis
                    # follows this out-of order scheme to match the output.
                    if self.symmetry_atoms:

                        # So we extend atombasis only for the unique atoms (with a
                        # symmetry index of 1), interleaving the basis functions
                        # for this atoms with basis functions for all symmetry atoms.
                        if self.symmetry_atoms[at] == 1:
                            nsyms = 1
                            while (at + nsyms < self.natom) and self.symmetry_atoms[at + nsyms] == nsyms + 1:
                                nsyms += 1
                            for isym in range(nsyms):
                                istart = nbasis + isym
                                iend = nbasis + cont*nsyms + isym
                                atombasis.append(list(range(istart, iend, nsyms)))
                            nbasis += cont*nsyms

                    else:
                        atombasis.append(list(range(nbasis, nbasis + cont)))
                        nbasis += cont

            self.set_attribute('atomnos', atomnos)
            self.set_attribute('atombasis', atombasis)
            self.set_attribute('nbasis', nbasis)

            self.skip_line(inputfile, 'dashes')

            line = next(inputfile)
            self.set_attribute('natom', int(line.split()[iatoms]))
            self.set_attribute('nbasis', int(line.split()[icont]))

            self.skip_line(inputfile, 'dashes')

        # The Gaussian exponents and contraction coefficients are printed for each primitive
        # and then the contraction information is printed separately (see below) Both segmented
        # and general contractions are used, but we can parse them the same way since zeros are
        # inserted for primitives that are not used. However, no atom index is printed here
        # so we don't really know when a new atom is started without using information
        # from other section (we should already have atombasis parsed at this point).
        #
        #  Orbital exponents and contraction coefficients
        #  ----------------------------------------------
        #
        #
        #  C   #1 1s      1       71.616837      0.1543    0.0000
        #   seg. cont.    2       13.045096      0.5353    0.0000
        #                 3        3.530512      0.4446    0.0000
        #                 4        2.941249      0.0000   -0.1000
        # ...
        #
        # Here is a corresponding fragment for general contractions:
        #
        #  C      1s      1    33980.000000      0.0001   -0.0000    0.0000    0.0000    0.0000
        #                                        0.0000    0.0000    0.0000    0.0000
        #   gen. cont.    2     5089.000000      0.0007   -0.0002    0.0000    0.0000    0.0000
        #                                        0.0000    0.0000    0.0000    0.0000
        #                 3     1157.000000      0.0037   -0.0008    0.0000    0.0000    0.0000
        #                                        0.0000    0.0000    0.0000    0.0000
        #                 4      326.600000      0.0154   -0.0033    0.0000    0.0000    0.0000
        # ...
        #
        if line.strip() == "Orbital exponents and contraction coefficients":

            self.skip_lines(inputfile, ['d', 'b', 'b'])

            # Here we simply want to save the numbers defining each primitive for later use,
            # where the first number is the exponent, and the rest are coefficients which
            # should be zero if the primitive is not used in a contraction. This list is
            # symmetry agnostic, although primitives/contractions are not generally.
            self.primitives = []

            prims = []
            line = next(inputfile)
            while line.strip():

                # Each contraction/section is separated by a blank line, and at the very
                # end there is an extra blank line.
                while line.strip():

                    # For generalized contraction it is typical to see the coefficients wrapped
                    # to new lines, so we must collect them until we are sure a primitive starts.
                    if line[:30].strip():
                        if prims:
                            self.primitives.append(prims)
                        prims = []

                    prims += [float(x) for x in line[20:].split()]

                    line = next(inputfile)

                line = next(inputfile)

            # At the end we have the final primitive to save.
            self.primitives.append(prims)

        # This is the corresponding section to the primitive definitions parsed above, so we
        # assume those numbers are available in the variable 'primitives'. Here we read in the
        # indicies of primitives, which we use to construct gbasis.
        # 
        #  Contracted Orbitals
        #  -------------------
        #
        #    1  C       1s      1    2    3    4    5    6    7    8    9   10   11   12
        #    2  C       1s      1    2    3    4    5    6    7    8    9   10   11   12
        #    3  C       1s     10
        #    4  C       1s     11
        # ...
        #
        # Here is an fragment with symmetry labels:
        #
        # ...
        #    1  C   #1  1s      1    2    3
        #    2  C   #2  1s      7    8    9
        #    3  C   #1  1s      4    5    6
        # ...
        #
        if line.strip() == "Contracted Orbitals":

            self.skip_lines(inputfile, ['d', 'b'])

            # This is the reverse of atombasis, so that we can easily map from a basis functions
            # to the corresponding atom for use in the loop below.
            basisatoms = [None for i in range(self.nbasis)]
            for iatom in range(self.natom):
                for ibasis in self.atombasis[iatom]:
                    basisatoms[ibasis] = iatom

            # Since contractions are not generally given in order (when there is symmetry),
            # start with an empty list for gbasis.
            gbasis = [[] for i in range(self.natom)]

            # This will hold the number of contractions already printed for each orbital,
            # counting symmetry orbitals separately.
            orbitalcount = {}

            for ibasis in range(self.nbasis):

                line = next(inputfile)
                cols = line.split()

                # The first columns is always the basis function index, which we can assert.
                assert int(cols[0]) == ibasis + 1

                # The number of columns is differnet when symmetry is used. If there are further
                # complications, it may be necessary to use exact slicing, since the formatting
                # of this section seems to be fixed (although columns can be missing). Notice how
                # We subtract one from the primitive indices here already to match cclib's
                # way of counting from zero in atombasis.
                if '#' in line:
                    sym = cols[2]
                    orbital = cols[3]
                    prims = [int(i) - 1 for i in cols[4:]]
                else:
                    sym = None
                    orbital = cols[2]
                    prims = [int(i) - 1 for i in cols[3:]]

                shell = orbital[0]
                subshell = orbital[1].upper()

                iatom = basisatoms[ibasis]

                # We want to count the number of contractiong already parsed for each orbital,
                # but need to make sure to differentiate between atoms and symmetry atoms.
                orblabel = str(iatom) + '.' + orbital + (sym or "")
                orbitalcount[orblabel] = orbitalcount.get(orblabel, 0) + 1

                # Here construct the actual primitives for gbasis, which should be a list
                # of 2-tuples containing an exponent an coefficient. Note how we are indexing
                # self.primitives from zero although the printed numbering starts from one.
                primitives = []
                for ip in prims:
                    p = self.primitives[ip]
                    exponent = p[0]
                    coefficient = p[orbitalcount[orblabel]]
                    primitives.append((exponent, coefficient))

                contraction = (subshell, primitives)
                if contraction not in gbasis[iatom]:
                    gbasis[iatom].append(contraction)

            self.skip_line(inputfile, 'blank')

            self.set_attribute('gbasis', gbasis)

        # Since DALTON sometimes uses symmetry labels (Ag, Au, etc.) and sometimes
        # just the symmetry group index, we need to parse and keep a mapping between
        # these two for later use.
        #
        #  Symmetry Orbitals
        #  -----------------
        #
        #  Number of orbitals in each symmetry:          25    5   25    5
        #
        #
        #  Symmetry  Ag ( 1)
        #
        #    1     C        1s         1 +    2
        #    2     C        1s         3 +    4
        # ...
        #
        if line.strip() == "Symmetry Orbitals":

            self.skip_lines(inputfile, ['d', 'b'])

            line = inputfile.next()
            self.symcounts = [int(c) for c in line.split(':')[1].split()]

            self.symlabels = []
            for sc in self.symcounts:

                self.skip_lines(inputfile, ['b', 'b'])

                # If the number of orbitals for a symmetry is zero, the printout
                # is different (see MP2 unittest logfile for an example).
                line = inputfile.next()

                if sc == 0:
                    assert "No orbitals in symmetry" in line
                else:
                    assert line.split()[0] == "Symmetry"
                    self.symlabels.append(line.split()[1])
                    self.skip_line(inputfile, 'blank')
                    for i in range(sc):
                        orbital = inputfile.next()

        #      Wave function specification
        #      ============================
        # @    Wave function type        >>> KS-DFT <<<
        # @    Number of closed shell electrons          70
        # @    Number of electrons in active shells       0
        # @    Total charge of the molecule               0
        #
        # @    Spin multiplicity and 2 M_S                1         0
        # @    Total number of symmetries                 4 (point group: C2h)
        # @    Reference state symmetry                   1 (irrep name : Ag )
        #
        #     This is a DFT calculation of type: B3LYP
        # ...
        #
        if "@    Number of electrons in active shells" in line:
            self.unpaired_electrons = int(line.split()[-1])
        if "@    Total charge of the molecule" in line:
            self.set_attribute("charge", int(line.split()[-1]))
        if "@    Spin multiplicity and 2 M_S" in line:
            self.set_attribute("mult", int(line.split()[-2]))

        #     Orbital specifications
        #     ======================
        #     Abelian symmetry species          All |    1    2    3    4
        #                                           |  Ag   Au   Bu   Bg
        #                                       --- |  ---  ---  ---  ---
        #     Total number of orbitals           60 |   25    5   25    5
        #     Number of basis functions          60 |   25    5   25    5
        #
        #      ** Automatic occupation of RKS orbitals **
        #
        #      -- Initial occupation of symmetries is determined from extended Huckel guess.
        #      -- Initial occupation of symmetries is :
        # @    Occupied SCF orbitals              35 |   15    2   15    3
        #
        #     Maximum number of Fock   iterations      0
        #     Maximum number of DIIS   iterations     60
        #     Maximum number of QC-SCF iterations     60
        #     Threshold for SCF convergence     1.00D-05
        #     This is a DFT calculation of type: B3LYP
        # ...
        #
        if "Total number of orbitals" in line:
            # DALTON 2015 adds a @ in front of number of orbitals
            chomp = line.split()
            index = 4
            if "@" in chomp:
                index = 5
            self.set_attribute("nbasis", int(chomp[index]))
            self.nmo_per_symmetry = list(map(int, chomp[index+2:]))
            assert self.nbasis == sum(self.nmo_per_symmetry)
        if "@    Occupied SCF orbitals" in line and not hasattr(self, 'homos'):
            temp = line.split()
            homos = int(temp[4])
            self.set_attribute('homos', [homos - 1 + self.unpaired_electrons])
        if "Threshold for SCF convergence" in line:
            if not hasattr(self, "scftargets"):
                self.scftargets = []
            scftarget = self.float(line.split()[-1])
            self.scftargets.append([scftarget])

        #                   .--------------------------------------------.
        #                   | Starting in Wave Function Section (SIRIUS) |
        #                   `--------------------------------------------'
        #
        if "Starting in Wave Function Section (SIRIUS)" in line:
            self.section = "SIRIUS"

        #  *********************************************
        #  ***** DIIS optimization of Hartree-Fock *****
        #  *********************************************
        #
        #  C1-DIIS algorithm; max error vectors =    8
        #
        #  Automatic occupation of symmetries with  70 electrons.
        #
        #  Iter     Total energy    Error norm  Delta(E)    SCF occupation
        #  -----------------------------------------------------------------------------
        #       K-S energy, electrons, error :    -46.547567739269  69.9999799123   -2.01D-05
        # @  1  -381.645762476       4.00D+00  -3.82D+02    15   2  15   3
        #       Virial theorem: -V/T =      2.008993
        # @      MULPOP C   _1  0.15; C   _2  0.15; C   _1  0.12; C   _2  0.12; C   _1  0.11; C   _2  0.11; H   _1 -0.15; H   _2 -0.15; H   _1 -0.14; H   _2 -0.14;
        # @             C   _1  0.23; C   _2  0.23; H   _1 -0.15; H   _2 -0.15; C   _1  0.08; C   _2  0.08; H   _1 -0.12; H   _2 -0.12; H   _1 -0.13; H   _2 -0.13;
        #  -----------------------------------------------------------------------------
        #       K-S energy, electrons, error :    -46.647668038900  69.9999810430   -1.90D-05
        # @  2  -381.949410128       1.05D+00  -3.04D-01    15   2  15   3
        #       Virial theorem: -V/T =      2.013393
        # ...
        #
        # With and without symmetry, the "Total energy" line is shifted a little.
        if self.section == "SIRIUS" and "Iter" in line and "Total energy" in line:

            iteration = 0
            converged = False
            values = []
            if not hasattr(self, "scfvalues"):
                self.scfvalues = []

            while not converged:

                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF!')
                    break

                # each iteration is bracketed by "-------------"
                if "-------------------" in line:
                    iteration += 1
                    continue

                # the first hit of @ n where n is the current iteration
                strcompare = "@{0:>3d}".format(iteration)
                if strcompare in line:
                    temp = line.split()
                    error_norm = self.float(temp[3])
                    values.append([error_norm])

                if line[0] == "@" and "converged in" in line:
                    converged = True

            # It seems DALTON does change the SCF convergence criteria during a
            # geometry optimization, but also does not print them. So, assume they
            # are unchanged and copy the initial values after the first step. However,
            # it would be good to check up on this - perhaps it is possible to print.
            self.scfvalues.append(values)
            if len(self.scfvalues) > 1:
                self.scftargets.append(self.scftargets[-1])

        # DALTON organizes the energies by symmetry, so we need to parse first,
        # and then sort the energies (and labels) before we store them.
        #
        # The formatting varies depending on RHF/DFT and/or version. Here is
        # an example from a DFT job:
        #
        #  *** SCF orbital energy analysis ***
        #
        #  Only the five lowest virtual orbital energies printed in each symmetry.
        #
        #  Number of electrons :   70
        #  Orbital occupations :   15    2   15    3
        #
        #  Sym       Kohn-Sham orbital energies
        #
        # 1 Ag    -10.01616533   -10.00394288   -10.00288640   -10.00209612    -9.98818062
        #          -0.80583154    -0.71422407    -0.58487249    -0.55551093    -0.50630125
        # ...
        #
        # Here is an example from an RHF job that only has symmetry group indices:
        #
        #  *** SCF orbital energy analysis ***
        #
        #  Only the five lowest virtual orbital energies printed in each symmetry.
        #
        #  Number of electrons :   70
        #  Orbital occupations :   15    2   15    3
        #
        #  Sym       Hartree-Fock orbital energies
        #
        #   1    -11.04052518   -11.03158921   -11.02882211   -11.02858563   -11.01747921
        #         -1.09029777    -0.97492511    -0.79988247    -0.76282547    -0.69677619
        # ...
        #
        if self.section == "SIRIUS" and "*** SCF orbital energy analysis ***" in line:

            # to get ALL orbital energies, the .PRINTLEVELS keyword needs
            # to be at least 0,10 (up from 0,5). I know, obvious, right?
            # this, however, will conflict with the scfvalues output that
            # changes into some weird form of DIIS debug output.

            mosyms = []
            moenergies = []

            self.skip_line(inputfile, 'blank')
            line = next(inputfile)

            # There is some extra text between the section header and
            # the number of electrons for open-shell calculations.
            while "Number of electrons" not in line:
                line = next(inputfile)
            nelectrons = int(line.split()[-1])

            line = next(inputfile)
            occupations = [int(o) for o in line.split()[3:]]
            nsym = len(occupations)

            self.skip_lines(inputfile, ['b', 'header', 'b'])

            # now parse nsym symmetries
            for isym in range(nsym):

                # For unoccupied symmetries, nothing is printed here.
                if occupations[isym] == 0:
                    continue

                # When there are exactly five energies printed (on just one line), it seems
                # an extra blank line is printed after a block.
                line = next(inputfile)
                if not line.strip():
                    line = next(inputfile)
                cols = line.split()

                # The first line has the orbital symmetry information, but sometimes
                # it's the label and sometimes it's the index. There are always five
                # energies per line, though, so we can deduce if we have the labels or
                # not just the index. In the latter case, we depend on the labels
                # being read earlier into the list `symlabels`. Finally, if no symlabels
                # were read that implies there is only one symmetry, namely Ag.
                if 'A' in cols[1] or 'B' in cols[1]:
                    sym = self.normalisesym(cols[1])
                    energies = [float(t) for t in cols[2:]]
                else:
                    if hasattr(self, 'symlabels'):
                        sym = self.normalisesym(self.symlabels[int(cols[0]) - 1])
                    else:
                        assert cols[0] == '1'
                        sym = "Ag"
                    energies = [float(t) for t in cols[1:]]

                while len(energies) > 0:
                    moenergies.extend(energies)
                    mosyms.extend(len(energies)*[sym])
                    line = next(inputfile)
                    energies = [float(col) for col in line.split()]

            # now sort the data about energies and symmetries. see the following post for the magic
            # http://stackoverflow.com/questions/19339/a-transpose-unzip-function-in-python-inverse-of-zip
            sdata = sorted(zip(moenergies, mosyms), key=lambda x: x[0])
            moenergies, mosyms = zip(*sdata)

            self.moenergies = [[]]
            self.moenergies[0] = [utils.convertor(moenergy, 'hartree', 'eV') for moenergy in moenergies]
            self.mosyms = [[]]
            self.mosyms[0] = mosyms

            if not hasattr(self, "nmo"):
                self.nmo = self.nbasis
                if len(self.moenergies[0]) != self.nmo:
                    self.set_attribute('nmo', len(self.moenergies[0]))

        #                       .-----------------------------------.
        #                       | >>> Final results from SIRIUS <<< |
        #                       `-----------------------------------'
        #
        #
        # @    Spin multiplicity:           1
        # @    Spatial symmetry:            1 ( irrep  Ag  in C2h )
        # @    Total charge of molecule:    0
        #
        # @    Final DFT energy:           -382.050716652387
        # @    Nuclear repulsion:           445.936979976608
        # @    Electronic energy:          -827.987696628995
        #
        # @    Final gradient norm:           0.000003746706
        # ...
        #
        if "Final DFT energy" in line or "Final HF energy" in line:
            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            temp = line.split()
            self.scfenergies.append(utils.convertor(float(temp[-1]), "hartree", "eV"))

        if "@   = MP2 second order energy" in line:
            energ = utils.convertor(float(line.split()[-1]), 'hartree', 'eV')
            if not hasattr(self, "mpenergies"):
                self.mpenergies = []
            self.mpenergies.append([])
            self.mpenergies[-1].append(energ)

        if "Total energy CCSD(T)" in line:
            energ = utils.convertor(float(line.split()[-1]), 'hartree', 'eV')
            if not hasattr(self, "ccenergies"):
                self.ccenergies = []
            self.ccenergies.append(energ)

        # The molecular geometry requires the use of .RUN PROPERTIES in the input.
        # Note that the second column is not the nuclear charge, but the atom type
        # index used internally by DALTON.
        #
        #                             Molecular geometry (au)
        #                             -----------------------
        #
        # C   _1     1.3498778652            2.3494125195            0.0000000000
        # C   _2    -1.3498778652           -2.3494125195            0.0000000000
        # C   _1     2.6543517307            0.0000000000            0.0000000000
        # ...
        #
        if "Molecular geometry (au)" in line:

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []

            if self.firststdorient:
                self.firststdorient = False

            self.skip_lines(inputfile, ['d', 'b'])

            lines = [next(inputfile) for i in range(self.natom)]
            atomcoords = self.parse_geometry(lines)
            self.atomcoords.append(atomcoords)

        if "Optimization Control Center" in line:
            self.section = "OPT"
            assert set(next(inputfile).strip()) == set(":")

        # During geometry optimizations the geometry is printed in the section
        # that is titles "Optimization Control Center". Note that after an optimizations
        # finishes, DALTON normally runs another "static property section (ABACUS)",
        # so the final geometry will be repeated in atomcoords.
        #
        #                                Next geometry (au)
        #                                ------------------
        #
        # C   _1     1.3203201560            2.3174808341            0.0000000000
        # C   _2    -1.3203201560           -2.3174808341            0.0000000000
        # ...
        if self.section == "OPT" and line.strip() == "Next geometry (au)":

            self.skip_lines(inputfile, ['d', 'b'])

            lines = [next(inputfile) for i in range(self.natom)]
            coords = self.parse_geometry(lines)
            self.atomcoords.append(coords)

        # This section contains data for optdone and geovalues, although we could use
        # it to double check some atttributes that were parsed before.
        #
        #                             Optimization information
        #                             ------------------------
        #
        # Iteration number               :       4
        # End of optimization            :       T
        # Energy at this geometry is     :    -379.777956
        # Energy change from last geom.  :      -0.000000
        # Predicted change               :      -0.000000
        # Ratio, actual/predicted change :       0.952994
        # Norm of gradient               :       0.000058
        # Norm of step                   :       0.000643
        # Updated trust radius           :       0.714097
        # Total Hessian index            :       0
        #
        if self.section == "OPT" and line.strip() == "Optimization information":

            self.skip_lines(inputfile, ['d', 'b'])

            line = next(inputfile)
            assert 'Iteration number' in line
            iteration = int(line.split()[-1])
            line = next(inputfile)
            assert 'End of optimization' in line
            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(line.split()[-1] == 'T')

            # We need a way to map between lines here and the targets stated at the
            # beginning of the file in 'Chosen parameters for *OPTIMI (see above),
            # and this dictionary facilitates that. The keys are target names parsed
            # in that initial section after input processing, and the values are
            # substrings that should appear in the lines in this section. Make an
            # exception for the energy at iteration zero where there is no gradient,
            # and take the total energy for geovalues.
            targets_labels = {
                'gradient': 'Norm of gradient',
                'energy': 'Energy change from last',
                'step': 'Norm of step',
            }
            values = [numpy.nan] * len(self.geotargets)
            while line.strip():
                if iteration == 0 and "Energy at this geometry" in line:
                    index = self.geotargets_names.index('energy')
                    values[index] = self.float(line.split()[-1])
                for tgt, lbl in targets_labels.items():
                    if lbl in line and tgt in self.geotargets_names:
                        index = self.geotargets_names.index(tgt)
                        values[index] = self.float(line.split()[-1])
                line = next(inputfile)

            # If we're missing something above, throw away the partial geovalues since
            # we don't want artificial NaNs getting into cclib. Instead, fix the dictionary
            # to make things work.
            if not numpy.nan in values:
                if not hasattr(self, 'geovalues'):
                    self.geovalues = []
                self.geovalues.append(values)

        # -------------------------------------------------
        # extract the center of mass line
        if "Center-of-mass coordinates (a.u.):" in line:
            temp = line.split()
            reference = [utils.convertor(float(temp[i]), "bohr", "Angstrom") for i in [3, 4, 5]]
            if not hasattr(self, 'moments'):
                self.moments = [reference]

        # -------------------------------------------------
        # Extract the dipole moment
        if "Dipole moment components" in line:
            dipole = numpy.zeros(3)
            line = next(inputfile)
            line = next(inputfile)
            line = next(inputfile)
            if not "zero by symmetry" in line:
                line = next(inputfile)

                line = next(inputfile)
                temp = line.split()
                for i in range(3):
                    dipole[i] = float(temp[2])  # store the Debye value
            if hasattr(self, 'moments'):
                self.moments.append(dipole)

        ## 'vibfreqs', 'vibirs', and 'vibsyms' appear in ABACUS.
        # Vibrational Frequencies and IR Intensities
        # ------------------------------------------
        #
        # mode   irrep        frequency             IR intensity
        # ============================================================
        #                 cm-1       hartrees     km/mol   (D/A)**2/amu
        # ------------------------------------------------------------
        #  1      A      3546.72    0.016160      0.000   0.0000
        #  2      A      3546.67    0.016160      0.024   0.0006
        # ...
        if "Vibrational Frequencies and IR Intensities" in line:

            self.skip_lines(inputfile, ['dashes', 'blank'])
            line = next(inputfile)
            assert line.strip() == "mode   irrep        frequency             IR intensity"
            self.skip_line(inputfile, 'equals')
            line = next(inputfile)
            assert line.strip() == "cm-1       hartrees     km/mol   (D/A)**2/amu"
            self.skip_line(inputfile, 'dashes')
            line = next(inputfile)

            # The normal modes are in order of decreasing IR
            # frequency, so they can't be added directly to
            # attributes; they must be grouped together first, sorted
            # in order of increasing frequency, then added to their
            # respective attributes.

            vibdata = []

            while line.strip():
                sline = line.split()
                vibsym = sline[1]
                vibfreq = float(sline[2])
                vibir = float(sline[4])
                vibdata.append((vibfreq, vibir, vibsym))
                line = next(inputfile)

            vibdata.sort(key=lambda normalmode: normalmode[0])

            self.vibfreqs = [normalmode[0] for normalmode in vibdata]
            self.vibirs = [normalmode[1] for normalmode in vibdata]
            self.vibsyms = [normalmode[2] for normalmode in vibdata]

            # Now extract the normal mode displacements.
            self.skip_lines(inputfile, ['b', 'b'])
            line = next(inputfile)
            assert line.strip() == "Normal Coordinates (bohrs*amu**(1/2)):"

            # Normal Coordinates (bohrs*amu**(1/2)):
            # --------------------------------------
            #
            #
            #               1  3547     2  3547     3  3474     4  3471     5  3451 
            # ----------------------------------------------------------------------
            #
            #   C      x   -0.000319   -0.000314    0.002038    0.000003   -0.001599
            #   C      y   -0.000158   -0.000150   -0.001446    0.003719   -0.002576
            #   C      z    0.000000   -0.000000   -0.000000    0.000000   -0.000000
            #
            #   C      x    0.000319   -0.000315   -0.002038    0.000003    0.001600
            #   C      y    0.000157   -0.000150    0.001448    0.003717    0.002577
            # ...
            self.skip_line(inputfile, 'd')
            line = next(inputfile)

            vibdisps = numpy.empty(shape=(len(self.vibirs), self.natom, 3))

            ndisps = 0
            while ndisps < len(self.vibirs):
                # Skip two blank lines.
                line = next(inputfile)
                line = next(inputfile)
                # Use the header with the normal mode indices and
                # frequencies to update where we are.
                ndisps_block = (len(line.split()) // 2)
                mode_min, mode_max = ndisps, ndisps + ndisps_block
                # Skip a line of dashes and a blank line.
                line = next(inputfile)
                line = next(inputfile)
                for w in range(self.natom):
                    for coord in range(3):
                        line = next(inputfile)
                        vibdisps[mode_min:mode_max, w, coord] = [float(i) for i in  line.split()[2:]]
                    # Skip a blank line.
                    line = next(inputfile)
                ndisps += ndisps_block

            # The vibrational displacements are in the wrong order;
            # reverse them.
            self.vibdisps = vibdisps[::-1, :, :]

        ## 'vibramans'
        #     Raman related properties for freq.  0.000000 au  = Infinity nm
        #     ---------------------------------------------------------------
        #
        # Mode    Freq.     Alpha**2   Beta(a)**2   Pol.Int.   Depol.Int.  Dep. Ratio 
        #
        #    1   3546.72    0.379364   16.900089   84.671721   50.700268    0.598786
        #    2   3546.67    0.000000    0.000000    0.000000    0.000000    0.599550
        if "Raman related properties for freq." in line:

            self.skip_lines(inputfile, ['d', 'b'])
            line = next(inputfile)
            assert line[1:76] == "Mode    Freq.     Alpha**2   Beta(a)**2   Pol.Int.   Depol.Int.  Dep. Ratio"
            self.skip_line(inputfile, 'b')
            line = next(inputfile)

            vibramans = []

            # The Raman intensities appear under the "Pol.Int."
            # (polarization intensity) column.
            for m in range(len(self.vibfreqs)):
                vibramans.append(float(line.split()[4]))
                line = next(inputfile)

            # All vibrational properties in DALTON appear in reverse
            # order.
            self.vibramans = vibramans[::-1]

        # Electronic excitations: single residues of the linear
        # response equations.
        if "Linear Response single residue calculation" in line:

            etsyms = []
            etenergies = []
            # etoscs = []
            etsecs = []

            symmap = {"T": "Triplet", "F": "Singlet"}

            while "End of Dynamic Property Section (RESPONS)" not in line:

                line = next(inputfile)

                if "Operator symmetry" in line:
                    do_triplet = line[-2]

                if "@ Excited state no:" in line:
                    etsym = line.split()[9] # -2
                    etsyms.append(symmap[do_triplet] + "-" + etsym)
                    self.skip_lines(inputfile, ['d', 'b', 'Excitation energy in a.u.'])
                    line = next(inputfile)
                    etenergy = float(line.split()[1])
                    etenergies.append(etenergy)

                    while "The dominant contributions" not in line:
                        line = next(inputfile)

                    self.skip_line(inputfile, 'b')
                    line = next(inputfile)
                    # [0] is the starting (occupied) MO
                    # [1] is the ending (unoccupied) MO
                    # [2] and [3] are the excitation/deexcitation coefficients
                    # [4] is the orbital overlap
                    # [5] is the ...
                    # [6] is the ...
                    # [7] is the ...
                    assert "I    A    K_IA      K_AI   <|I|*|A|> <I^2*A^2>    Weight   Contrib" in line
                    self.skip_line(inputfile, 'b')
                    line = next(inputfile)
                    sec = []

                    while line.strip():
                        chomp = line.split()
                        startidx = int(chomp[0]) - 1
                        endidx = int(chomp[1]) - 1
                        contrib = float(chomp[2])
                        # Since DALTON is restricted open-shell only,
                        # there is not distinction between alpha and
                        # beta spin.
                        sec.append([(startidx, 0), (endidx, 0), contrib])
                        line = next(inputfile)

                    etsecs.append(sec)

            self.set_attribute('etsyms', etsyms)
            self.set_attribute('etenergies', etenergies)
            # self.set_attribute('etoscs', etoscs)
            self.set_attribute('etsecs', etsecs)

        # TODO:
        # aonames
        # aooverlaps
        # atomcharges
        # atomspins
        # coreelectrons
        # enthalpy
        # entropy
        # etoscs
        # etrotats
        # freeenergy
        # grads
        # hessian
        # mocoeffs
        # nocoeffs
        # nooccnos
        # scancoords
        # scanenergies
        # scannames
        # scanparm
        # temperature
        # vibanharms

        # N/A:
        # fonames
        # fooverlaps
        # fragnames
        # frags



if __name__ == "__main__":
    import doctest, daltonparser, sys
    if len(sys.argv) == 1:
        doctest.testmod(daltonparser, verbose=False)

    if len(sys.argv) >= 2:
        parser = daltonparser.DALTON(sys.argv[1])
        data = parser.parse()

    if len(sys.argv) > 2:
        for i in range(len(sys.argv[2:])):
            if hasattr(data, sys.argv[2 + i]):
                print(getattr(data, sys.argv[2 + i]))
