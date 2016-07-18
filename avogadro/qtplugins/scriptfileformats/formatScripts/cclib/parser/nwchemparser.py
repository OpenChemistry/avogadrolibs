# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2008-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for NWChem output files"""

import itertools
import numpy
import re

from . import logfileparser
from . import utils


class NWChem(logfileparser.Logfile):
    """An NWChem log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(NWChem, self).__init__(logname="NWChem", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "NWChem log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'NWChem("%s")' % (self.filename)

    def normalisesym(self, label):
        """Use standard symmetry labels instead of NWChem labels.

        To normalise:
        (1) If label is one of [SG, PI, PHI, DLTA], replace by [sigma, pi, phi, delta]
        (2) replace any G or U by their lowercase equivalent

        >>> sym = NWChem("dummyfile").normalisesym
        >>> labels = ['A1', 'AG', 'A1G', "SG", "PI", "PHI", "DLTA", 'DLTU', 'SGG']
        >>> map(sym, labels)
        ['A1', 'Ag', 'A1g', 'sigma', 'pi', 'phi', 'delta', 'delta.u', 'sigma.g']
        """
        # FIXME if necessary
        return label

    name2element = lambda self, lbl: "".join(itertools.takewhile(str.isalpha, str(lbl)))

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # This is printed in the input module, so should always be the first coordinates,
        # and contains some basic information we want to parse as well. However, this is not
        # the only place where the coordinates are printed during geometry optimization,
        # since the gradients module has a separate coordinate printout, which happens
        # alongside the coordinate gradients. This geometry printout happens at the
        # beginning of each optimization step only.
        if line.strip() == 'Geometry "geometry" -> ""' or line.strip() == 'Geometry "geometry" -> "geometry"':

            self.skip_lines(inputfile, ['dashes', 'blank', 'units', 'blank', 'header', 'dashes'])

            if not hasattr(self, 'atomcoords'):
                self.atomcoords = []

            line = next(inputfile)
            coords = []
            atomnos = []
            while line.strip():
                # The column labeled 'tag' is usually empty, but I'm not sure whether it can have spaces,
                # so for now assume that it can and that there will be seven columns in that case.
                if len(line.split()) == 6:
                    index, atomname, nuclear, x, y, z = line.split()
                else:
                    index, atomname, tag, nuclear, x, y, z = line.split()
                coords.append(list(map(float, [x, y, z])))
                atomnos.append(int(float(nuclear)))
                line = next(inputfile)

            self.atomcoords.append(coords)

            self.set_attribute('atomnos', atomnos)

        # If the geometry is printed in XYZ format, it will have the number of atoms.
        if line[12:31] == "XYZ format geometry":

            self.skip_line(inputfile, 'dashes')
            natom = int(next(inputfile).strip())
            self.set_attribute('natom', natom)

        if line.strip() == "NWChem Geometry Optimization":
            self.skip_lines(inputfile, ['d', 'b', 'b', 'b', 'b', 'title', 'b', 'b'])
            line = next(inputfile)
            while line.strip():
                if "maximum gradient threshold" in line:
                    gmax = float(line.split()[-1])
                if "rms gradient threshold" in line:
                    grms = float(line.split()[-1])
                if "maximum cartesian step threshold" in line:
                    xmax = float(line.split()[-1])
                if "rms cartesian step threshold" in line:
                    xrms = float(line.split()[-1])
                line = next(inputfile)

            self.set_attribute('geotargets', [gmax, grms, xmax, xrms])

        # NWChem does not normally print the basis set for each atom, but rather
        # chooses the concise option of printing Gaussian coefficients for each
        # atom type/element only once. Therefore, we need to first parse those
        # coefficients and afterwards build the appropriate gbasis attribute based
        # on that and atom types/elements already parsed (atomnos). However, if atom
        # are given different names (number after element, like H1 and H2), then NWChem
        # generally prints the gaussian parameters for all unique names, like this:
        #
        #                      Basis "ao basis" -> "ao basis" (cartesian)
        #                      -----
        #  O (Oxygen)
        #  ----------
        #            Exponent  Coefficients
        #       -------------- ---------------------------------------------------------
        #  1 S  1.30709320E+02  0.154329
        #  1 S  2.38088610E+01  0.535328
        # (...)
        #
        #  H1 (Hydrogen)
        #  -------------
        #            Exponent  Coefficients
        #       -------------- ---------------------------------------------------------
        #  1 S  3.42525091E+00  0.154329
        # (...)
        #
        #  H2 (Hydrogen)
        #  -------------
        #            Exponent  Coefficients
        #       -------------- ---------------------------------------------------------
        #  1 S  3.42525091E+00  0.154329
        # (...)
        #
        # This current parsing code below assumes all atoms of the same element
        # use the same basis set, but that might not be true, and this will probably
        # need to be considered in the future when such a logfile appears.
        if line.strip() == """Basis "ao basis" -> "ao basis" (cartesian)""":
            self.skip_line(inputfile, 'dashes')
            gbasis_dict = {}
            line = next(inputfile)
            while line.strip():
                atomname = line.split()[0]
                atomelement = self.name2element(atomname)
                gbasis_dict[atomelement] = []
                self.skip_lines(inputfile, ['d', 'labels', 'd'])
                shells = []
                line = next(inputfile)
                while line.strip() and line.split()[0].isdigit():
                    shell = None
                    while line.strip():
                        nshell, type, exp, coeff = line.split()
                        nshell = int(nshell)
                        assert len(shells) == nshell - 1
                        if not shell:
                            shell = (type, [])
                        else:
                            assert shell[0] == type
                        exp = float(exp)
                        coeff = float(coeff)
                        shell[1].append((exp, coeff))
                        line = next(inputfile)
                    shells.append(shell)
                    line = next(inputfile)
                gbasis_dict[atomelement].extend(shells)

            gbasis = []
            for i in range(self.natom):
                atomtype = self.table.element[self.atomnos[i]]
                gbasis.append(gbasis_dict[atomtype])

            self.set_attribute('gbasis', gbasis)

        # Normally the indexes of AOs assigned to specific atoms are also not printed,
        # so we need to infer that. We could do that from the previous section,
        # it might be worthwhile to take numbers from two different places, hence
        # the code below, which builds atombasis based on the number of functions
        # listed in this summary of the AO basis. Similar to previous section, here
        # we assume all atoms of the same element have the same basis sets, but
        # this will probably need to be revised later.

        # The section we can glean info about aonmaes looks like:
        #
        # Summary of "ao basis" -> "ao basis" (cartesian)
        # ------------------------------------------------------------------------------
        #       Tag                 Description            Shells   Functions and Types
        # ---------------- ------------------------------  ------  ---------------------
        # C                           sto-3g                  3        5   2s1p
        # H                           sto-3g                  1        1   1s
        #
        # However, we need to make sure not to match the following entry lines:
        #
        # *  Summary of "ao basis" -> "" (cartesian)
        # *  Summary of allocated global arrays
        #
        # Unfortantely, "ao basis" isn't unique because it can be renamed to anything for
        # later reference: http://www.nwchem-sw.org/index.php/Basis
        # It also appears that we have to handle cartesian vs. spherical

        if line[1:11] == "Summary of":
            match = re.match(' Summary of "([^\"]*)" -> "([^\"]*)" \((.+)\)', line)

            if match and match.group(1) == match.group(2):

                self.skip_lines(inputfile, ['d', 'title', 'd'])

                self.shells = {}
                self.shells["type"] = match.group(3)

                atombasis_dict = {}

                line = next(inputfile)
                while line.strip():
                    atomname, desc, shells, funcs, types = line.split()
                    atomelement = self.name2element(atomname)

                    self.shells[atomname] = types
                    atombasis_dict[atomelement] = int(funcs)
                    line = next(inputfile)

                last = 0
                atombasis = []
                for atom in self.atomnos:
                    atomelement = self.table.element[atom]
                    nfuncs = atombasis_dict[atomelement]
                    atombasis.append(list(range(last, last+nfuncs)))
                    last = atombasis[-1][-1] + 1

                self.set_attribute('atombasis', atombasis)

        # This section contains general parameters for Hartree-Fock calculations,
        # which do not contain the 'General Information' section like most jobs.
        if line.strip() == "NWChem SCF Module":
            # If the calculation doesn't have a title specified, there
            # aren't as many lines to skip here.
            self.skip_lines(inputfile, ['d', 'b', 'b'])
            line = next(inputfile)
            if line.strip():
                self.skip_lines(inputfile, ['b', 'b', 'b'])
            line = next(inputfile)
            while line.strip():
                if line[2:8] == "charge":
                    charge = int(float(line.split()[-1]))
                    self.set_attribute('charge', charge)
                if line[2:13] == "open shells":
                    unpaired = int(line.split()[-1])
                    self.set_attribute('mult', 2*unpaired + 1)
                if line[2:7] == "atoms":
                    natom = int(line.split()[-1])
                    self.set_attribute('natom', natom)
                if line[2:11] == "functions":
                    nfuncs = int(line.split()[-1])
                    self.set_attribute("nbasis", nfuncs)
                line = next(inputfile)

        # This section contains general parameters for DFT calculations, as well as
        # for the many-electron theory module.
        if line.strip() == "General Information":

            if hasattr(self, 'linesearch') and self.linesearch:
                return

            while line.strip():

                if "No. of atoms" in line:
                    self.set_attribute('natom', int(line.split()[-1]))
                if "Charge" in line:
                    self.set_attribute('charge', int(line.split()[-1]))
                if "Spin multiplicity" in line:
                    mult = line.split()[-1]
                    if mult == "singlet":
                        mult = 1
                    self.set_attribute('mult', int(mult))
                if "AO basis - number of function" in line:
                    nfuncs = int(line.split()[-1])
                    self.set_attribute('nbasis', nfuncs)

                # These will be present only in the DFT module.
                if "Convergence on energy requested" in line:
                    target_energy = float(line.split()[-1].replace('D', 'E'))
                if "Convergence on density requested" in line:
                    target_density = float(line.split()[-1].replace('D', 'E'))
                if "Convergence on gradient requested" in line:
                    target_gradient = float(line.split()[-1].replace('D', 'E'))

                line = next(inputfile)

            # Pretty nasty temporary hack to set scftargets only in the SCF module.
            if "target_energy" in dir() and "target_density" in dir() and "target_gradient" in dir():
                if not hasattr(self, 'scftargets'):
                    self.scftargets = []
                self.scftargets.append([target_energy, target_density, target_gradient])

        # If the full overlap matrix is printed, it looks like this:
        #
        # global array: Temp Over[1:60,1:60],  handle: -996
        #
        #            1           2           3           4           5           6
        #       ----------- ----------- ----------- ----------- ----------- -----------
        #   1       1.00000     0.24836    -0.00000    -0.00000     0.00000     0.00000
        #   2       0.24836     1.00000     0.00000    -0.00000     0.00000     0.00030
        #   3      -0.00000     0.00000     1.00000     0.00000     0.00000    -0.00014
        # ...
        if "global array: Temp Over[" in line:

            self.set_attribute('nbasis', int(line.split('[')[1].split(',')[0].split(':')[1]))
            self.set_attribute('nmo', int(line.split(']')[0].split(',')[1].split(':')[1]))

            aooverlaps = []
            while len(aooverlaps) < self.nbasis:

                self.skip_line(inputfile, 'blank')

                indices = [int(i) for i in inputfile.next().split()]
                assert indices[0] == len(aooverlaps) + 1

                self.skip_line(inputfile, "dashes")
                data = [inputfile.next().split() for i in range(self.nbasis)]
                indices = [int(d[0]) for d in data]
                assert indices == list(range(1, self.nbasis+1))

                for i in range(1, len(data[0])):
                    vector = [float(d[i]) for d in data]
                    aooverlaps.append(vector)

            self.set_attribute('aooverlaps', aooverlaps)

        if line.strip() in ("The SCF is already converged", "The DFT is already converged"):
            if self.linesearch:
                return
            self.scftargets.append(self.scftargets[-1])
            self.scfvalues.append(self.scfvalues[-1])

        # The default (only?) SCF algorithm for Hartree-Fock is a preconditioned conjugate
        # gradient method that apparently "always" converges, so this header should reliably
        # signal a start of the SCF cycle. The convergence targets are also printed here.
        if line.strip() == "Quadratically convergent ROHF":

            if hasattr(self, 'linesearch') and self.linesearch:
                return

            while not "Final" in line:

                # Only the norm of the orbital gradient is used to test convergence.
                if line[:22] == " Convergence threshold":
                    target = float(line.split()[-1])
                    if not hasattr(self, "scftargets"):
                        self.scftargets = []
                    self.scftargets.append([target])

                    # This is critical for the stop condition of the section,
                    # because the 'Final Fock-matrix accuracy' is along the way.
                    # It would be prudent to find a more robust stop condition.
                    while list(set(line.strip())) != ["-"]:
                        line = next(inputfile)

                if line.split() == ['iter', 'energy', 'gnorm', 'gmax', 'time']:
                    values = []
                    self.skip_line(inputfile, 'dashes')
                    line = next(inputfile)
                    while line.strip():
                        it, energy, gnorm, gmax, time = line.split()
                        gnorm = float(gnorm.replace('D', 'E'))
                        values.append([gnorm])
                        try:
                            line = next(inputfile)
                        # Is this the end of the file for some reason?
                        except StopIteration:
                            self.logger.warning('File terminated before end of last SCF! Last gradient norm: {}'.format(gnorm))
                            break
                    if not hasattr(self, 'scfvalues'):
                        self.scfvalues = []
                    self.scfvalues.append(values)

                # this is totally and utterly broken right now
                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('blech')
                    break

        # The SCF for DFT does not use the same algorithm as Hartree-Fock, but always
        # seems to use the following format to report SCF convergence:
        #   convergence    iter        energy       DeltaE   RMS-Dens  Diis-err    time
        # ---------------- ----- ----------------- --------- --------- ---------  ------
        # d= 0,ls=0.0,diis     1   -382.2544324446 -8.28D+02  1.42D-02  3.78D-01    23.2
        # d= 0,ls=0.0,diis     2   -382.3017298534 -4.73D-02  6.99D-03  3.82D-02    39.3
        # d= 0,ls=0.0,diis     3   -382.2954343173  6.30D-03  4.21D-03  7.95D-02    55.3
        # ...
        if line.split() == ['convergence', 'iter', 'energy', 'DeltaE', 'RMS-Dens', 'Diis-err', 'time']:

            if hasattr(self, 'linesearch') and self.linesearch:
                return

            self.skip_line(inputfile, 'dashes')
            line = next(inputfile)
            values = []
            while line.strip():

                # Sometimes there are things in between iterations with fewer columns,
                # and we want to skip those lines, most probably. An exception might
                # unrestricted calcualtions, which show extra RMS density and DIIS
                # errors, although it is not clear yet whether these are for the
                # beta orbitals or somethine else. The iterations look like this in that case:
                #   convergence    iter        energy       DeltaE   RMS-Dens  Diis-err    time
                # ---------------- ----- ----------------- --------- --------- ---------  ------
                # d= 0,ls=0.0,diis     1   -382.0243202601 -8.28D+02  7.77D-03  1.04D-01    30.0
                #                                                     7.68D-03  1.02D-01
                # d= 0,ls=0.0,diis     2   -382.0647539758 -4.04D-02  4.64D-03  1.95D-02    59.2
                #                                                     5.39D-03  2.36D-02
                # ...
                if len(line[17:].split()) == 6:
                    iter, energy, deltaE, dens, diis, time = line[17:].split()
                    val_energy = float(deltaE.replace('D', 'E'))
                    val_density = float(dens.replace('D', 'E'))
                    val_gradient = float(diis.replace('D', 'E'))
                    values.append([val_energy, val_density, val_gradient])

                try:
                    line = next(inputfile)
                # Is this the end of the file for some reason?
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF! Last error: {}'.format(diis))
                    break

            if not hasattr(self, 'scfvalues'):
                self.scfvalues = []

            self.scfvalues.append(values)

        # These triggers are supposed to catch the current step in a geometry optimization search
        # and determine whether we are currently in the main (initial) SCF cycle of that step
        # or in the subsequent line search. The step is printed between dashes like this:
        #
        #          --------
        #          Step   0
        #          --------
        #
        # and the summary lines that describe the main SCF cycle for the frsit step look like this:
        #
        #@ Step       Energy      Delta E   Gmax     Grms     Xrms     Xmax   Walltime
        #@ ---- ---------------- -------- -------- -------- -------- -------- --------
        #@    0    -379.76896249  0.0D+00  0.04567  0.01110  0.00000  0.00000      4.2
        #                                                       ok       ok
        #
        # However, for subsequent step the format is a bit different:
        #
        #  Step       Energy      Delta E   Gmax     Grms     Xrms     Xmax   Walltime
        #  ---- ---------------- -------- -------- -------- -------- -------- --------
        #@    2    -379.77794602 -7.4D-05  0.00118  0.00023  0.00440  0.01818     14.8
        #                                              ok
        #
        # There is also a summary of the line search (which we don't use now), like this:
        #
        # Line search:
        #     step= 1.00 grad=-1.8D-05 hess= 8.9D-06 energy=   -379.777955 mode=accept
        # new step= 1.00                   predicted energy=   -379.777955
        #
        if line[10:14] == "Step":
            self.geostep = int(line.split()[-1])
            self.skip_line(inputfile, 'dashes')
            self.linesearch = False
        if line[0] == "@" and line.split()[1] == "Step":
            at_and_dashes = next(inputfile)
            line = next(inputfile)
            assert int(line.split()[1]) == self.geostep == 0
            gmax = float(line.split()[4])
            grms = float(line.split()[5])
            xrms = float(line.split()[6])
            xmax = float(line.split()[7])
            if not hasattr(self, 'geovalues'):
                self.geovalues = []
            self.geovalues.append([gmax, grms, xmax, xrms])
            self.linesearch = True
        if line[2:6] == "Step":
            self.skip_line(inputfile, 'dashes')
            line = next(inputfile)
            assert int(line.split()[1]) == self.geostep
            if self.linesearch:
                #print(line)
                return
            gmax = float(line.split()[4])
            grms = float(line.split()[5])
            xrms = float(line.split()[6])
            xmax = float(line.split()[7])
            if not hasattr(self, 'geovalues'):
                self.geovalues = []
            self.geovalues.append([gmax, grms, xmax, xrms])
            self.linesearch = True

        # There is a clear message when the geometry optimization has converged:
        #
        #      ----------------------
        #      Optimization converged
        #      ----------------------
        #
        if line.strip() == "Optimization converged":
            self.skip_line(inputfile, 'dashes')
            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.geovalues) - 1)

        if "Failed to converge" in line and hasattr(self, 'geovalues'):
            if not hasattr(self, 'optdone'):
                self.optdone = []

        # The line containing the final SCF energy seems to be always identifiable like this.
        if "Total SCF energy" in line or "Total DFT energy" in line:

            # NWChem often does a line search during geometry optimization steps, reporting
            # the SCF information but not the coordinates (which are not necessarily 'intermediate'
            # since the step size can become smaller). We want to skip these SCF cycles,
            # unless the coordinates can also be extracted (possibly from the gradients?).
            if hasattr(self, 'linesearch') and self.linesearch:
                return

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            energy = float(line.split()[-1])
            energy = utils.convertor(energy, "hartree", "eV")
            self.scfenergies.append(energy)

        # The final MO orbitals are printed in a simple list, but apparently not for
        # DFT calcs, and often this list does not contain all MOs, so make sure to
        # parse them from the MO analysis below if possible. This section will be like this:
        #
        #       Symmetry analysis of molecular orbitals - final
        #       -----------------------------------------------
        #
        #  Numbering of irreducible representations:
        #
        #     1 ag          2 au          3 bg          4 bu
        #
        #  Orbital symmetries:
        #
        #     1 bu          2 ag          3 bu          4 ag          5 bu
        #     6 ag          7 bu          8 ag          9 bu         10 ag
        # ...
        if line.strip() == "Symmetry analysis of molecular orbitals - final":

            self.skip_lines(inputfile, ['d', 'b', 'numbering', 'b', 'reps', 'b', 'syms', 'b'])

            if not hasattr(self, 'mosyms'):
                self.mosyms = [[None]*self.nbasis]
            line = next(inputfile)
            while line.strip():
                ncols = len(line.split())
                assert ncols % 2 == 0
                for i in range(ncols//2):
                    index = int(line.split()[i*2]) - 1
                    sym = line.split()[i*2+1]
                    sym = sym[0].upper() + sym[1:]
                    if self.mosyms[0][index]:
                        if self.mosyms[0][index] != sym:
                            self.logger.warning("Symmetry of MO %i has changed" % (index+1))
                    self.mosyms[0][index] = sym
                line = next(inputfile)

        # The same format is used for HF and DFT molecular orbital analysis. We want to parse
        # the MO energies from this section, although it is printed already before this with
        # less precision (might be useful to parse that if this is not available). Also, this
        # section contains coefficients for the leading AO contributions, so it might also
        # be useful to parse and use those values if the full vectors are not printed.
        #
        # The block looks something like this (two separate alpha/beta blocks in the unrestricted case):
        #
        #                       ROHF Final Molecular Orbital Analysis
        #                       -------------------------------------
        #
        # Vector    1  Occ=2.000000D+00  E=-1.104059D+01  Symmetry=bu
        #              MO Center=  1.4D-17,  0.0D+00, -6.5D-37, r^2= 2.1D+00
        #   Bfn.  Coefficient  Atom+Function         Bfn.  Coefficient  Atom+Function
        #  ----- ------------  ---------------      ----- ------------  ---------------
        #     1      0.701483   1 C  s                 6     -0.701483   2 C  s
        #
        # Vector    2  Occ=2.000000D+00  E=-1.104052D+01  Symmetry=ag
        # ...
        # Vector   12  Occ=2.000000D+00  E=-1.020253D+00  Symmetry=bu
        #              MO Center= -1.4D-17, -5.6D-17,  2.9D-34, r^2= 7.9D+00
        #   Bfn.  Coefficient  Atom+Function         Bfn.  Coefficient  Atom+Function
        #  ----- ------------  ---------------      ----- ------------  ---------------
        #    36     -0.298699  11 C  s                41      0.298699  12 C  s
        #     2      0.270804   1 C  s                 7     -0.270804   2 C  s
        #    48     -0.213655  15 C  s                53      0.213655  16 C  s
        # ...
        #
        if "Final" in line and "Molecular Orbital Analysis" in line:

            # Unrestricted jobs have two such blocks, for alpha and beta orbitals, and
            # we need to keep track of which one we're parsing (always alpha in restricted case).
            unrestricted = ("Alpha" in line) or ("Beta" in line)
            alphabeta = int("Beta" in line)

            self.skip_lines(inputfile, ['dashes', 'blank'])

            energies = []
            symmetries = [None]*self.nbasis
            line = next(inputfile)
            homo = 0
            while line[:7] == " Vector":

                # Note: the vector count starts from 1 in NWChem.
                nvector = int(line[7:12])

                # A nonzero occupancy for SCF jobs means the orbital is occupied.
                if ("Occ=2.0" in line) or ("Occ=1.0" in line):
                    homo = nvector-1

                # If the printout does not start from the first MO, assume None for all previous orbitals.
                if len(energies) == 0 and nvector > 1:
                    for i in range(1, nvector):
                        energies.append(None)

                energy = float(line[34:47].replace('D', 'E'))
                energy = utils.convertor(energy, "hartree", "eV")
                energies.append(energy)

                # When symmetry is not used, this part of the line is missing.
                if line[47:58].strip() == "Symmetry=":
                    sym = line[58:].strip()
                    sym = sym[0].upper() + sym[1:]
                    symmetries[nvector-1] = sym

                line = next(inputfile)
                if "MO Center" in line:
                    line = next(inputfile)
                if "Bfn." in line:
                    line = next(inputfile)
                if "-----" in line:
                    line = next(inputfile)
                while line.strip():
                    line = next(inputfile)
                line = next(inputfile)

            self.set_attribute('nmo', nvector)

            if not hasattr(self, 'moenergies') or (len(self.moenergies) > alphabeta):
                self.moenergies = []
            self.moenergies.append(energies)

            if not hasattr(self, 'mosyms') or (len(self.mosyms) > alphabeta):
                self.mosyms = []
            self.mosyms.append(symmetries)

            if not hasattr(self, 'homos') or (len(self.homos) > alphabeta):
                self.homos = []
            self.homos.append(homo)

        # This is where the full MO vectors are printed, but a special directive is needed for it:
        #
        #                                 Final MO vectors
        #                                 ----------------
        #
        #
        # global array: alpha evecs[1:60,1:60],  handle: -995
        #
        #            1           2           3           4           5           6
        #       ----------- ----------- ----------- ----------- ----------- -----------
        #   1      -0.69930    -0.69930    -0.02746    -0.02769    -0.00313    -0.02871
        #   2      -0.03156    -0.03135     0.00410     0.00406     0.00078     0.00816
        #   3       0.00002    -0.00003     0.00067     0.00065    -0.00526    -0.00120
        # ...
        #
        if line.strip() == "Final MO vectors":

            if not hasattr(self, 'mocoeffs'):
                self.mocoeffs = []

            self.skip_lines(inputfile, ['d', 'b', 'b'])

            # The columns are MOs, rows AOs, but that's and educated guess since no
            # atom information is printed alongside the indices. This next line gives
            # the dimensions, which we can check. if set before this. Also, this line
            # specifies whether we are dealing with alpha or beta vectors.
            array_info = next(inputfile)
            while ("global array" in array_info):
                alphabeta = int(line.split()[2] == "beta")
                size = array_info.split('[')[1].split(']')[0]
                nbasis = int(size.split(',')[0].split(':')[1])
                nmo = int(size.split(',')[1].split(':')[1])
                self.set_attribute('nbasis', nbasis)
                self.set_attribute('nmo', nmo)

                self.skip_line(inputfile, 'blank')
                mocoeffs = []
                while len(mocoeffs) < self.nmo:
                    nmos = list(map(int, next(inputfile).split()))
                    assert len(mocoeffs) == nmos[0] - 1
                    for n in nmos:
                        mocoeffs.append([])
                    self.skip_line(inputfile, 'dashes')
                    for nb in range(nbasis):
                        line = next(inputfile)
                        index = int(line.split()[0])
                        assert index == nb+1
                        coefficients = list(map(float, line.split()[1:]))
                        assert len(coefficients) == len(nmos)
                        for i, c in enumerate(coefficients):
                            mocoeffs[nmos[i]-1].append(c)
                    self.skip_line(inputfile, 'blank')
                self.mocoeffs.append(mocoeffs)

                array_info = next(inputfile)

        # For Hartree-Fock, the atomic Mulliken charges are typically printed like this:
        #
        #  Mulliken analysis of the total density
        #  --------------------------------------
        #
        #    Atom       Charge   Shell Charges
        # -----------   ------   -------------------------------------------------------
        #    1 C    6     6.00   1.99  1.14  2.87
        #    2 C    6     6.00   1.99  1.14  2.87
        # ...
        if line.strip() == "Mulliken analysis of the total density":

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}

            self.skip_lines(inputfile, ['d', 'b', 'header', 'd'])

            charges = []
            line = next(inputfile)
            while line.strip():
                index, atomname, nuclear, atom = line.split()[:4]
                shells = line.split()[4:]
                charges.append(float(atom)-float(nuclear))
                line = next(inputfile)
            self.atomcharges['mulliken'] = charges

        # Not the the 'overlap population' as printed in the Mulliken population analysis,
        # is not the same thing as the 'overlap matrix'. In fact, it is the overlap matrix
        # multiplied elementwise times the density matrix.
        #
        #          ----------------------------
        #          Mulliken population analysis
        #          ----------------------------
        #
        #          ----- Total      overlap population -----
        #
        #                               1              2              3              4              5              6              7
        #
        #    1   1 C  s            2.0694818227  -0.0535883400  -0.0000000000  -0.0000000000  -0.0000000000  -0.0000000000   0.0000039991
        #    2   1 C  s           -0.0535883400   0.8281341291   0.0000000000  -0.0000000000   0.0000000000   0.0000039991  -0.0009906747
        # ...
        #
        # DFT does not seem to print the separate listing of Mulliken charges
        # by default, but they are printed by this modules later on. They are also print
        # for Hartree-Fock runs, though, so in that case make sure they are consistent.
        if line.strip() == "Mulliken population analysis":

            self.skip_lines(inputfile, ['d', 'b', 'total_overlap_population', 'b'])

            overlaps = []
            line = next(inputfile)
            while all([c.isdigit() for c in line.split()]):

                # There is always a line with the MO indices printed in thie block.
                indices = [int(i)-1 for i in line.split()]
                for i in indices:
                    overlaps.append([])

                # There is usually a blank line after the MO indices, but
                # there are exceptions, so check if line is blank first.
                line = next(inputfile)
                if not line.strip():
                    line = next(inputfile)

                # Now we can iterate or atomic orbitals.
                for nao in range(self.nbasis):
                    data = list(map(float, line.split()[4:]))
                    for i, d in enumerate(data):
                        overlaps[indices[i]].append(d)
                    line = next(inputfile)

                line = next(inputfile)

            # This header should be printed later, before the charges are print, which of course
            # are just sums of the overlaps and could be calculated. But we just go ahead and
            # parse them, make sure they're consistent with previously parsed values and
            # use these since they are more precise (previous precision could have been just 0.01).
            while "Total      gross population on atoms" not in line:
                line = next(inputfile)
            self.skip_line(inputfile, 'blank')
            charges = []
            for i in range(self.natom):
                line = next(inputfile)
                iatom, element, ncharge, epop = line.split()
                iatom = int(iatom)
                ncharge = float(ncharge)
                epop = float(epop)
                assert iatom == (i+1)
                charges.append(epop-ncharge)

            if not hasattr(self, 'atomcharges'):
                self.atomcharges = {}
            if not "mulliken" in self.atomcharges:
                self.atomcharges['mulliken'] = charges
            else:
                assert max(self.atomcharges['mulliken'] - numpy.array(charges)) < 0.01
                self.atomcharges['mulliken'] = charges

        # NWChem prints the dipole moment in atomic units first, and we could just fast forward
        # to the values in Debye, which are also printed. But we can also just convert them
        # right away and so parse a little bit less. Note how the reference point is print
        # here within the block nicely, as it is for all moment later.
        #
        #          -------------
        #          Dipole Moment
        #          -------------
        #
        # Center of charge (in au) is the expansion point
        #         X =       0.0000000 Y =       0.0000000 Z =       0.0000000
        #
        #   Dipole moment        0.0000000000 Debye(s)
        #             DMX        0.0000000000 DMXEFC        0.0000000000
        #             DMY        0.0000000000 DMYEFC        0.0000000000
        #             DMZ       -0.0000000000 DMZEFC        0.0000000000
        #
        # ...
        #
        if line.strip() == "Dipole Moment":

            self.skip_lines(inputfile, ['d', 'b'])

            reference_comment = next(inputfile)
            assert "(in au)" in reference_comment
            reference = next(inputfile).split()
            self.reference = [reference[-7], reference[-4], reference[-1]]
            self.reference = numpy.array([float(x) for x in self.reference])
            self.reference = utils.convertor(self.reference, 'bohr', 'Angstrom')

            self.skip_line(inputfile, 'blank')

            magnitude = next(inputfile)
            assert magnitude.split()[-1] == "A.U."

            dipole = []
            for i in range(3):
                line = next(inputfile)
                dipole.append(float(line.split()[1]))

            dipole = utils.convertor(numpy.array(dipole), "ebohr", "Debye")

            if not hasattr(self, 'moments'):
                self.moments = [self.reference, dipole]
            else:
                self.moments[1] == dipole

        # The quadrupole moment is pretty straightforward to parse. There are several
        # blocks printed, and the first one called 'second moments' contains the raw
        # moments, and later traceless values are printed. The moments, however, are
        # not in lexicographical order, so we need to sort them. Also, the first block
        # is in atomic units, so remember to convert to Buckinghams along the way.
        #
        #          -----------------
        #          Quadrupole Moment
        #          -----------------
        #
        # Center of charge (in au) is the expansion point
        #         X =       0.0000000 Y =       0.0000000 Z =       0.0000000
        #
        # < R**2 > = ********** a.u.  ( 1 a.u. = 0.280023 10**(-16) cm**2 )
        # ( also called diamagnetic susceptibility )
        #
        #   Second moments in atomic units
        #
        #   Component  Electronic+nuclear     Point charges             Total
        #  --------------------------------------------------------------------------
        #      XX          -38.3608511210          0.0000000000        -38.3608511210
        #      YY          -39.0055467347          0.0000000000        -39.0055467347
        # ...
        #
        if line.strip() == "Quadrupole Moment":

            self.skip_lines(inputfile, ['d', 'b'])

            reference_comment = next(inputfile)
            assert "(in au)" in reference_comment
            reference = next(inputfile).split()
            self.reference = [reference[-7], reference[-4], reference[-1]]
            self.reference = numpy.array([float(x) for x in self.reference])
            self.reference = utils.convertor(self.reference, 'bohr', 'Angstrom')

            self.skip_lines(inputfile, ['b', 'units', 'susc', 'b'])

            line = next(inputfile)
            assert line.strip() == "Second moments in atomic units"

            self.skip_lines(inputfile, ['b', 'header', 'd'])

            # Parse into a dictionary and then sort by the component key.
            quadrupole = {}
            for i in range(6):
                line = next(inputfile)
                quadrupole[line.split()[0]] = float(line.split()[-1])
            lex = sorted(quadrupole.keys())
            quadrupole = [quadrupole[key] for key in lex]

            quadrupole = utils.convertor(numpy.array(quadrupole), "ebohr2", "Buckingham")

            # The checking of potential previous values if a bit more involved here,
            # because it turns out NWChem has separate keywords for dipole, quadrupole
            # and octupole output. So, it is perfectly possible to print the quadrupole
            # and not the dipole... if that is the case set the former to None and
            # issue a warning. Also, a regression has been added to cover this case.
            if not hasattr(self, 'moments') or len(self.moments) < 2:
                self.logger.warning("Found quadrupole moments but no previous dipole")
                self.moments = [self.reference, None, quadrupole]
            else:
                if len(self.moments) == 2:
                    self.moments.append(quadrupole)
                else:
                    assert self.moments[2] == quadrupole

        # The octupole moment is analogous to the quadrupole, but there are more components
        # and the checking of previously parsed dipole and quadrupole moments is more involved,
        # with a corresponding test also added to regressions.
        #
        #          ---------------
        #          Octupole Moment
        #          ---------------
        #
        # Center of charge (in au) is the expansion point
        #         X =       0.0000000 Y =       0.0000000 Z =       0.0000000
        #
        #   Third moments in atomic units
        #
        #   Component  Electronic+nuclear     Point charges             Total
        #  --------------------------------------------------------------------------
        #      XXX          -0.0000000000          0.0000000000         -0.0000000000
        #      YYY          -0.0000000000          0.0000000000         -0.0000000000
        # ...
        #
        if line.strip() == "Octupole Moment":

            self.skip_lines(inputfile, ['d', 'b'])

            reference_comment = next(inputfile)
            assert "(in au)" in reference_comment
            reference = next(inputfile).split()
            self.reference = [reference[-7], reference[-4], reference[-1]]
            self.reference = numpy.array([float(x) for x in self.reference])
            self.reference = utils.convertor(self.reference, 'bohr', 'Angstrom')

            self.skip_line(inputfile, 'blank')

            line = next(inputfile)
            assert line.strip() == "Third moments in atomic units"

            self.skip_lines(inputfile, ['b', 'header', 'd'])

            octupole = {}
            for i in range(10):
                line = next(inputfile)
                octupole[line.split()[0]] = float(line.split()[-1])
            lex = sorted(octupole.keys())
            octupole = [octupole[key] for key in lex]

            octupole = utils.convertor(numpy.array(octupole), "ebohr3", "Debye.ang2")

            if not hasattr(self, 'moments') or len(self.moments) < 2:
                self.logger.warning("Found octupole moments but no previous dipole or quadrupole moments")
                self.moments = [self.reference, None, None, octupole]
            elif len(self.moments) == 2:
                self.logger.warning("Found octupole moments but no previous quadrupole moments")
                self.moments.append(None)
                self.moments.append(octupole)
            else:
                if len(self.moments) == 3:
                    self.moments.append(octupole)
                else:
                    assert self.moments[3] == octupole

        if "Total MP2 energy" in line:
            mpenerg = float(line.split()[-1])
            if not hasattr(self, "mpenergies"):
                self.mpenergies = []
            self.mpenergies.append([])
            self.mpenergies[-1].append(utils.convertor(mpenerg, "hartree", "eV"))

        if "CCSD(T) total energy / hartree" in line:
            ccenerg = float(line.split()[-1])
            if not hasattr(self, "ccenergies"):
                self.ccenergies = []
            self.ccenergies.append([])
            self.ccenergies[-1].append(utils.convertor(ccenerg, "hartree", "eV"))

    def after_parsing(self):
        """NWChem-specific routines for after parsing file.

        Currently, expands self.shells() into self.aonames.
        """

        # setup a few necessary things, including a regular expression
        # for matching the shells
        table = utils.PeriodicTable()
        elements = [table.element[x] for x in self.atomnos]
        pattern = re.compile("(\ds)+(\dp)*(\dd)*(\df)*(\dg)*")

        labels = {}
        labels['s'] = ["%iS"]
        labels['p'] = ["%iPX", "%iPY", "%iPZ"]
        if self.shells['type'] == 'spherical':
            labels['d'] = ['%iD-2', '%iD-1', '%iD0', '%iD1', '%iD2']
            labels['f'] = ['%iF-3', '%iF-2', '%iF-1', '%iF0',
                           '%iF1', '%iF2', '%iF3']
            labels['g'] = ['%iG-4', '%iG-3', '%iG-2', '%iG-1', '%iG0',
                           '%iG1', '%iG2', '%iG3', '%iG4']
        elif self.shells['type'] == 'cartesian':
            labels['d'] = ['%iDXX', '%iDXY', '%iDXZ',
                           '%iDYY', '%iDYZ',
                           '%iDZZ']
            labels['f'] = ['%iFXXX', '%iFXXY', '%iFXXZ',
                           '%iFXYY', '%iFXYZ', '%iFXZZ',
                           '%iFYYY', '%iFYYZ', '%iFYZZ',
                           '%iFZZZ']
            labels['g'] = ['%iGXXXX', '%iGXXXY', '%iGXXXZ',
                           '%iGXXYY', '%iGXXYZ', '%iGXXZZ',
                           '%iGXYYY', '%iGXYYZ', '%iGXYZZ',
                           '%iGXZZZ', '%iGYYYY', '%iGYYYZ',
                           '%iGYYZZ', '%iGYZZZ', '%iGZZZZ']
        else:
            self.logger.warning("Found a non-standard aoname representation type.")
            return

        # now actually build aonames
        # involves expanding 2s1p into appropriate types

        self.aonames = []
        for i, element in enumerate(elements):
            try:
                shell_text = self.shells[element]
            except KeyError:
                del self.aonames
                msg = "Cannot determine aonames for at least one atom."
                self.logger.warning(msg)
                break

            prefix = "%s%i_" % (element, i + 1)  # (e.g. C1_)

            matches = pattern.match(shell_text)
            for j, group in enumerate(matches.groups()):
                if group is None:
                    continue

                count = int(group[:-1])
                label = group[-1]

                for k in range(count):
                    temp = [x % (j + k + 1) for x in labels[label]]
                    self.aonames.extend([prefix + x for x in temp])


if __name__ == "__main__":
    import doctest, nwchemparser
    doctest.testmod(nwchemparser, verbose=False)
