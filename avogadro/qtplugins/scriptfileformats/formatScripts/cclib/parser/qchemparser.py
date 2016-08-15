# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2014-2016, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for Q-Chem output files"""

from __future__ import division
from __future__ import print_function

import itertools
import numpy
import re

from . import logfileparser
from . import utils


class QChem(logfileparser.Logfile):
    """A Q-Chem 4 log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(QChem, self).__init__(logname="QChem", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "QChem log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'QChem("%s")' % (self.filename)

    def normalisesym(self, label):
        """Q-Chem does not require normalizing symmetry labels."""

    def before_parsing(self):

        # Keep track of whether or not we're performing an
        # (un)restricted calculation.
        self.unrestricted = False
        self.is_rohf = False

        # Keep track of whether or not this is a fragment calculation,
        # so that only the supersystem is parsed.
        self.is_fragment_section = False
        # These headers identify when a fragment section is
        # entered/exited.
        self.fragment_section_headers = (
            'Guess MOs from converged MOs on fragments',
            'CP correction for fragment',
        )
        self.supersystem_section_headers = (
            'Done with SCF on isolated fragments',
            'Done with counterpoise correction on fragments',
        )


        # Compile the dashes-and-or-spaces-only regex.
        self.re_dashes_and_spaces = re.compile('^[\s-]+$')

        # Compile the regex for extracting the atomic index from an
        # aoname.
        self.re_atomindex = re.compile('(\d+)_')

        # A maximum of 6 columns per block when printing matrices.
        self.ncolsblock = 6

        # By default, when asked to print orbitals via
        # `scf_print`/`scf_final_print` and/or `print_orbitals`,
        # Q-Chem will print all occupieds and the first 5 virtuals.
        #
        # When the number is set for `print_orbitals`, that section of
        # the output will display (NOcc + that many virtual) MOs, but
        # any other sections present due to
        # `scf_print`/`scf_final_print` will still only display (NOcc
        # + 5) MOs.
        #
        # Note that the density matrix is always (NBasis * NBasis)!
        self.norbdisp_alpha = self.norbdisp_beta = 5
        self.norbdisp_alpha_aonames = self.norbdisp_beta_aonames = 5
        self.norbdisp_set = False

        self.alpha_mo_coefficient_headers = (
            'RESTRICTED (RHF) MOLECULAR ORBITAL COEFFICIENTS',
            'ALPHA MOLECULAR ORBITAL COEFFICIENTS'
        )

    def after_parsing(self):

        # If parsing a fragment job, each of the geometries appended to
        # `atomcoords` may be of different lengths, which will prevent
        # conversion from a list to NumPy array.
        # Take the length of the first geometry as correct, and remove
        # all others with different lengths.
        if len(self.atomcoords) > 1:
            correctlen = len(self.atomcoords[0])
            self.atomcoords[:] = [coords for coords in self.atomcoords
                                  if len(coords) == correctlen]
        # At the moment, there is no similar correction for other properties!

        # QChem does not print all MO coefficients by default, but rather
        # up to HOMO+5. So, fill up the missing values with NaNs. If there are
        # other cases where coefficient are missing, but different ones, this
        # general afterthought might not be appropriate and the fix will
        # need to be done while parsing.
        if hasattr(self, 'mocoeffs'):
            for im in range(len(self.mocoeffs)):
                _nmo, _nbasis = self.mocoeffs[im].shape
                if (_nmo, _nbasis) != (self.nmo, self.nbasis):
                    coeffs = numpy.empty((self.nmo, self.nbasis))
                    coeffs[:] = numpy.nan
                    coeffs[0:_nmo, 0:_nbasis] = self.mocoeffs[im]
                    self.mocoeffs[im] = coeffs

        # When parsing the 'MOLECULAR ORBITAL COEFFICIENTS' block for
        # `aonames`, Q-Chem doesn't print the principal quantum number
        # for each shell; this needs to be added.
        if hasattr(self, 'aonames') and hasattr(self, 'atombasis'):
            angmom = ('', 'S', 'P', 'D', 'F', 'G', 'H', 'I')
            for atom in self.atombasis:
                bfcounts = dict()
                for bfindex in atom:
                    atomname, bfname = self.aonames[bfindex].split('_')
                    # Keep track of how many times each shell type has
                    # appeared.
                    if bfname in bfcounts:
                        bfcounts[bfname] += 1
                    else:
                        # Make sure the starting number for type of
                        # angular momentum begins at the appropriate
                        # principal quantum number (1S, 2P, 3D, 4F,
                        # ...).
                        bfcounts[bfname] = angmom.index(bfname[0])
                    newbfname = '{}{}'.format(bfcounts[bfname], bfname)
                    self.aonames[bfindex] = '_'.join([atomname, newbfname])

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # Disable/enable parsing for fragment sections.
        if any(message in line for message in self.fragment_section_headers):
            self.is_fragment_section = True
        if any(message in line for message in self.supersystem_section_headers):
            self.is_fragment_section = False

        if not self.is_fragment_section:
            # If the input section is repeated back, parse the $rem and
            # $molecule sections.
            if line[0:11] == 'User input:':
                self.skip_line(inputfile, 'd')
                while list(set(line.strip())) != ['-']:

                    if '$rem' in line:
                        while '$end' not in line:
                            line = next(inputfile)
                            if 'print_orbitals' in line.lower():
                                # Stay with the default value if a number isn't
                                # specified.
                                if line.split()[-1].lower() in ('true', 'false'):
                                    continue
                                else:
                                    norbdisp_aonames = int(line.split()[-1])
                                    self.norbdisp_alpha_aonames = norbdisp_aonames
                                    self.norbdisp_beta_aonames = norbdisp_aonames
                                    self.norbdisp_set = True

                    line = next(inputfile)

            # Parse the general basis for `gbasis`, in the style used by
            # Gaussian.
            if 'Basis set in general basis input format:' in line:
                self.skip_lines(inputfile, ['d', '$basis'])
                line = next(inputfile)
                if not hasattr(self, 'gbasis'):
                    self.gbasis = []
                # The end of the general basis block.
                while '$end' not in line:
                    atom = []
                    # 1. Contains element symbol and atomic index of
                    # basis functions; if 0, applies to all atoms of
                    # same element.
                    assert len(line.split()) == 2
                    line = next(inputfile)
                    # The end of each atomic block.
                    while '****' not in line:
                        # 2. Contains the type of basis function {S, SP,
                        # P, D, F, G, H, ...}, the number of primitives,
                        # and the weight of the final contracted function.
                        bfsplitline = line.split()
                        assert len(bfsplitline) == 3
                        bftype = bfsplitline[0]
                        nprim = int(bfsplitline[1])
                        line = next(inputfile)
                        # 3. The primitive basis functions that compose
                        # the contracted basis function; there are `nprim`
                        # of them. The first value is the exponent, and
                        # the second value is the contraction
                        # coefficient. If `bftype == 'SP'`, the primitives
                        # are for both S- and P-type basis functions but
                        # with separate contraction coefficients,
                        # resulting in three columns.
                        if bftype == 'SP':
                            primitives_S = []
                            primitives_P = []
                        else:
                            primitives = []
                        # For each primitive in the contracted basis
                        # function...
                        for iprim in range(nprim):
                            primsplitline = line.split()
                            exponent = float(primsplitline[0])
                            if bftype == 'SP':
                                assert len(primsplitline) == 3
                                coefficient_S = float(primsplitline[1])
                                coefficient_P = float(primsplitline[2])
                                primitives_S.append((exponent, coefficient_S))
                                primitives_P.append((exponent, coefficient_P))
                            else:
                                assert len(primsplitline) == 2
                                coefficient = float(primsplitline[1])
                                primitives.append((exponent, coefficient))
                            line = next(inputfile)
                        if bftype == 'SP':
                            bf_S = ('S', primitives_S)
                            bf_P = ('P', primitives_P)
                            atom.append(bf_S)
                            atom.append(bf_P)
                        else:
                            bf = (bftype, primitives)
                            atom.append(bf)
                        # Move to the next contracted basis function
                        # as long as we don't hit the '****' atom
                        # delimiter.
                    self.gbasis.append(atom)
                    line = next(inputfile)

            # Extract the atomic numbers and coordinates of the atoms.
            if 'Standard Nuclear Orientation (Angstroms)' in line:
                if not hasattr(self, 'atomcoords'):
                    self.atomcoords = []
                self.skip_lines(inputfile, ['cols', 'dashes'])
                atomelements = []
                atomcoords = []
                line = next(inputfile)
                while list(set(line.strip())) != ['-']:
                    entry = line.split()
                    atomelements.append(entry[1])
                    atomcoords.append(list(map(float, entry[2:])))
                    line = next(inputfile)

                self.atomcoords.append(atomcoords)

                # We calculate and handle atomnos no matter what, since in
                # the case of fragment calculations the atoms may change,
                # along with the charge and spin multiplicity.
                self.atomnos = []
                self.atomelements = []
                for atomelement in atomelements:
                    self.atomelements.append(atomelement)
                    if atomelement == 'GH':
                        self.atomnos.append(0)
                    else:
                        self.atomnos.append(self.table.number[atomelement])
                self.natom = len(self.atomnos)
                self.atommap = self.generate_atom_map()
                self.formula_histogram = self.generate_formula_histogram()

            # Number of electrons.
            # Useful for determining the number of occupied/virtual orbitals.
            if 'Nuclear Repulsion Energy' in line:
                line = next(inputfile)
                nelec_re_string = 'There are(\s+[0-9]+) alpha and(\s+[0-9]+) beta electrons'
                match = re.findall(nelec_re_string, line.strip())
                self.set_attribute('nalpha', int(match[0][0].strip()))
                self.set_attribute('nbeta', int(match[0][1].strip()))
                self.norbdisp_alpha += self.nalpha
                self.norbdisp_alpha_aonames += self.nalpha
                self.norbdisp_beta += self.nbeta
                self.norbdisp_beta_aonames += self.nbeta
                # Calculate the spin multiplicity (2S + 1), where S is the
                # total spin of the system.
                S = (self.nalpha - self.nbeta) / 2
                mult = int(2 * S + 1)
                self.set_attribute('mult', mult)
                # Calculate the molecular charge as the difference between
                # the atomic numbers and the number of electrons.
                if hasattr(self, 'atomnos'):
                    charge = sum(self.atomnos) - (self.nalpha + self.nbeta)
                    self.set_attribute('charge', charge)

            # Number of basis functions.
            # Because Q-Chem's integral recursion scheme is defined using
            # Cartesian basis functions, there is often a distinction between the
            # two in the output. We only parse for *pure* functions.
            # Examples:
            #  Only one type:
            #   There are 30 shells and 60 basis functions
            #  Both Cartesian and pure:
            #   ...
            if 'basis functions' in line:
                if not hasattr(self, 'nbasis'):
                    self.set_attribute('nbasis', int(line.split()[-3]))

            # Check for whether or not we're peforming an
            # (un)restricted calculation.
            if 'calculation will be' in line:
                if ' restricted' in line:
                    self.unrestricted = False
                if 'unrestricted' in line:
                    self.unrestricted = True
                if hasattr(self, 'nalpha') and hasattr(self, 'nbeta'):
                    if self.nalpha != self.nbeta:
                        self.unrestricted = True
                        self.is_rohf = True

            # Section with SCF iterations goes like this:
            #
            # SCF converges when DIIS error is below 1.0E-05
            # ---------------------------------------
            #  Cycle       Energy         DIIS Error
            # ---------------------------------------
            #    1    -381.9238072190      1.39E-01
            #    2    -382.2937212775      3.10E-03
            #    3    -382.2939780242      3.37E-03
            # ...
            #
            scf_success_messages = (
                'Convergence criterion met',
                'corrected energy'
            )
            scf_failure_messages = (
                'SCF failed to converge',
                'Convergence failure'
            )
            if 'SCF converges when ' in line:
                if not hasattr(self, 'scftargets'):
                    self.scftargets = []
                target = float(line.split()[-1])
                self.scftargets.append([target])

                # We should have the header between dashes now,
                # but sometimes there are lines before the first dashes.
                while not 'Cycle       Energy' in line:
                    line = next(inputfile)
                self.skip_line(inputfile, 'd')

                values = []
                iter_counter = 1
                line = next(inputfile)
                while not any(message in line for message in scf_success_messages):

                    # Some trickery to avoid a lot of printing that can occur
                    # between each SCF iteration.
                    entry = line.split()
                    if len(entry) > 0:
                        if entry[0] == str(iter_counter):
                            # Q-Chem only outputs one error metric.
                            error = float(entry[2])
                            values.append([error])
                            iter_counter += 1

                    try:
                        line = next(inputfile)
                    # Is this the end of the file for some reason?
                    except StopIteration:
                        self.logger.warning('File terminated before end of last SCF! Last error: {}'.format(error))
                        break

                    # We've converged, but still need the last iteration.
                    if any(message in line for message in scf_success_messages):
                        entry = line.split()
                        error = float(entry[2])
                        values.append([error])
                        iter_counter += 1

                    # This is printed in regression QChem4.2/dvb_sp_unconverged.out
                    # so use it to bail out when convergence fails.
                    if any(message in line for message in scf_failure_messages):
                        break

                if not hasattr(self, 'scfvalues'):
                    self.scfvalues = []
                self.scfvalues.append(numpy.array(values))

            # Molecular orbital coefficients.

            # Try parsing them from this block (which comes from
            # `scf_final_print = 2``) rather than the combined
            # aonames/mocoeffs/moenergies block (which comes from
            # `print_orbitals = true`).
            if 'Final Alpha MO Coefficients' in line:
                if not hasattr(self, 'mocoeffs'):
                    self.mocoeffs = []
                mocoeffs = numpy.empty(shape=(self.nbasis, self.norbdisp_alpha))
                self.parse_matrix(inputfile, mocoeffs)
                self.mocoeffs.append(mocoeffs.transpose())

            if 'Final Beta MO Coefficients' in line:
                mocoeffs = numpy.empty(shape=(self.nbasis, self.norbdisp_beta))
                self.parse_matrix(inputfile, mocoeffs)
                self.mocoeffs.append(mocoeffs.transpose())

            if 'Total energy in the final basis set' in line:
                if not hasattr(self, 'scfenergies'):
                    self.scfenergies = []
                scfenergy = float(line.split()[-1])
                self.scfenergies.append(utils.convertor(scfenergy, 'hartree', 'eV'))

            # Geometry optimization.

            if 'Maximum     Tolerance    Cnvgd?' in line:
                line_g = next(inputfile).split()[1:3]
                line_d = next(inputfile).split()[1:3]
                line_e = next(inputfile).split()[2:4]

                if not hasattr(self, 'geotargets'):
                    self.geotargets = [line_g[1], line_d[1], self.float(line_e[1])]
                if not hasattr(self, 'geovalues'):
                    self.geovalues = []
                maxg = self.float(line_g[0])
                maxd = self.float(line_d[0])
                ediff = self.float(line_e[0])
                geovalues = [maxg, maxd, ediff]
                self.geovalues.append(geovalues)

            if '**  OPTIMIZATION CONVERGED  **' in line:
                if not hasattr(self, 'optdone'):
                    self.optdone = []
                self.optdone.append(len(self.atomcoords))

            if '**  MAXIMUM OPTIMIZATION CYCLES REACHED  **' in line:
                if not hasattr(self, 'optdone'):
                    self.optdone = []

            # Moller-Plesset corrections.

            # There are multiple modules in Q-Chem for calculating MPn energies:
            # cdman, ccman, and ccman2, all with different output.
            #
            # MP2, RI-MP2, and local MP2 all default to cdman, which has a simple
            # block of output after the regular SCF iterations.
            #
            # MP3 is handled by ccman2.
            #
            # MP4 and variants are handled by ccman.

            # This is the MP2/cdman case.
            if 'MP2         total energy' in line:
                if not hasattr(self, 'mpenergies'):
                    self.mpenergies = []
                mp2energy = float(line.split()[4])
                mp2energy = utils.convertor(mp2energy, 'hartree', 'eV')
                self.mpenergies.append([mp2energy])

            # This is the MP3/ccman2 case.
            if line[1:11] == 'MP2 energy' and line[12:19] != 'read as':
                if not hasattr(self, 'mpenergies'):
                    self.mpenergies = []
                mpenergies = []
                mp2energy = float(line.split()[3])
                mpenergies.append(mp2energy)
                line = next(inputfile)
                line = next(inputfile)
                # Just a safe check.
                if 'MP3 energy' in line:
                    mp3energy = float(line.split()[3])
                    mpenergies.append(mp3energy)
                mpenergies = [utils.convertor(mpe, 'hartree', 'eV')
                              for mpe in mpenergies]
                self.mpenergies.append(mpenergies)

            # This is the MP4/ccman case.
            if 'EHF' in line:
                if not hasattr(self, 'mpenergies'):
                    self.mpenergies = []
                mpenergies = []

                while list(set(line.strip())) != ['-']:

                    if 'EMP2' in line:
                        mp2energy = float(line.split()[2])
                        mpenergies.append(mp2energy)
                    if 'EMP3' in line:
                        mp3energy = float(line.split()[2])
                        mpenergies.append(mp3energy)
                    if 'EMP4SDQ' in line:
                        mp4sdqenergy = float(line.split()[2])
                        mpenergies.append(mp4sdqenergy)
                    # This is really MP4SD(T)Q.
                    if 'EMP4 ' in line:
                        mp4sdtqenergy = float(line.split()[2])
                        mpenergies.append(mp4sdtqenergy)

                    line = next(inputfile)

                mpenergies = [utils.convertor(mpe, 'hartree', 'eV')
                              for mpe in mpenergies]
                self.mpenergies.append(mpenergies)

            # Coupled cluster corrections.
            # Hopefully we only have to deal with ccman2 here.

            if 'CCD total energy' in line:
                if not hasattr(self, 'ccenergies'):
                    self.ccenergies = []
                ccdenergy = float(line.split()[-1])
                ccdenergy = utils.convertor(ccdenergy, 'hartree', 'eV')
                self.ccenergies.append(ccdenergy)
            if 'CCSD total energy' in line:
                has_triples = False
                if not hasattr(self, 'ccenergies'):
                    self.ccenergies = []
                ccsdenergy = float(line.split()[-1])
                # Make sure we aren't actually doing CCSD(T).
                line = next(inputfile)
                line = next(inputfile)
                if 'CCSD(T) total energy' in line:
                    has_triples = True
                    ccsdtenergy = float(line.split()[-1])
                    ccsdtenergy = utils.convertor(ccsdtenergy, 'hartree', 'eV')
                    self.ccenergies.append(ccsdtenergy)
                if not has_triples:
                    ccsdenergy = utils.convertor(ccsdenergy, 'hartree', 'eV')
                    self.ccenergies.append(ccsdenergy)

            # Electronic transitions. Works for both CIS and TDDFT.
            if 'Excitation Energies' in line:

                # Restricted:
                # ---------------------------------------------------
                #         TDDFT/TDA Excitation Energies
                # ---------------------------------------------------
                #
                # Excited state   1: excitation energy (eV) =    3.6052
                #    Total energy for state   1:   -382.167872200685
                #    Multiplicity: Triplet
                #    Trans. Mom.:  0.0000 X   0.0000 Y   0.0000 Z
                #    Strength   :  0.0000
                #    D( 33) --> V(  3) amplitude =  0.2618
                #    D( 34) --> V(  2) amplitude =  0.2125
                #    D( 35) --> V(  1) amplitude =  0.9266
                #
                # Unrestricted:
                # Excited state   2: excitation energy (eV) =    2.3156
                #    Total energy for state   2:   -381.980177630969
                #    <S**2>     :  0.7674
                #    Trans. Mom.: -2.7680 X  -0.1089 Y   0.0000 Z
                #    Strength   :  0.4353
                #    S(  1) --> V(  1) amplitude = -0.3105 alpha
                #    D( 34) --> S(  1) amplitude =  0.9322 beta

                self.skip_lines(inputfile, ['dashes', 'blank'])
                line = next(inputfile)

                etenergies = []
                etsyms = []
                etoscs = []
                etsecs = []
                spinmap = {'alpha': 0, 'beta': 1}

                while list(set(line.strip())) != ['-']:

                    # Take the total energy for the state and subtract from the
                    # ground state energy, rather than just the EE;
                    # this will be more accurate.
                    if 'Total energy for state' in line:
                        energy = utils.convertor(float(line.split()[-1]), 'hartree', 'cm-1')
                        etenergy = energy - utils.convertor(self.scfenergies[-1], 'eV', 'cm-1')
                        etenergies.append(etenergy)
                    # if 'excitation energy' in line:
                    #     etenergy = utils.convertor(float(line.split()[-1]), 'eV', 'cm-1')
                    #     etenergies.append(etenergy)
                    if 'Multiplicity' in line:
                        etsym = line.split()[1]
                        etsyms.append(etsym)
                    if 'Strength' in line:
                        strength = float(line.split()[-1])
                        etoscs.append(strength)

                    # This is the list of transitions.
                    if 'amplitude' in line:
                        sec = []
                        while line.strip() != '':
                            if self.unrestricted:
                                spin = spinmap[line[42:47].strip()]
                            else:
                                spin = 0

                            # There is a subtle difference between TDA and RPA calcs,
                            # because in the latter case each transition line is
                            # preceeded by the type of vector: X or Y, name excitation
                            # or deexcitation (see #154 for details). For deexcitations,
                            # we will need to reverse the MO indices. Note also that Q-Chem
                            # starts reindexing virtual orbitals at 1.
                            if line[5] == '(':
                                ttype = 'X'
                                startidx = int(line[6:9]) - 1
                                endidx = int(line[17:20]) - 1 + self.nalpha
                                contrib = float(line[34:41].strip())
                            else:
                                assert line[5] == ":"
                                ttype = line[4]
                                startidx = int(line[9:12]) - 1
                                endidx = int(line[20:23]) - 1 + self.nalpha
                                contrib = float(line[37:44].strip())

                            start = (startidx, spin)
                            end = (endidx, spin)
                            if ttype == 'X':
                                sec.append([start, end, contrib])
                            elif ttype == 'Y':
                                sec.append([end, start, contrib])
                            else:
                                raise ValueError('Unknown transition type: %s' % ttype)
                            line = next(inputfile)
                        etsecs.append(sec)

                    line = next(inputfile)

                self.set_attribute('etenergies', etenergies)
                self.set_attribute('etsyms', etsyms)
                self.set_attribute('etoscs', etoscs)
                self.set_attribute('etsecs', etsecs)

            # Molecular orbital energies and symmetries.
            if 'Orbital Energies (a.u.) and Symmetries' in line:

                #  --------------------------------------------------------------
                #              Orbital Energies (a.u.) and Symmetries
                #  --------------------------------------------------------------
                #
                #  Alpha MOs, Restricted
                #  -- Occupied --
                # -10.018 -10.018 -10.008 -10.008 -10.007 -10.007 -10.006 -10.005
                #   1 Bu    1 Ag    2 Bu    2 Ag    3 Bu    3 Ag    4 Bu    4 Ag
                #  -9.992  -9.992  -0.818  -0.755  -0.721  -0.704  -0.670  -0.585
                #   5 Ag    5 Bu    6 Ag    6 Bu    7 Ag    7 Bu    8 Bu    8 Ag
                #  -0.561  -0.532  -0.512  -0.462  -0.439  -0.410  -0.400  -0.397
                #   9 Ag    9 Bu   10 Ag   11 Ag   10 Bu   11 Bu   12 Bu   12 Ag
                #  -0.376  -0.358  -0.349  -0.330  -0.305  -0.295  -0.281  -0.263
                #  13 Bu   14 Bu   13 Ag    1 Au   15 Bu   14 Ag   15 Ag    1 Bg
                #  -0.216  -0.198  -0.160
                #   2 Au    2 Bg    3 Bg
                #  -- Virtual --
                #   0.050   0.091   0.116   0.181   0.280   0.319   0.330   0.365
                #   3 Au    4 Au    4 Bg    5 Au    5 Bg   16 Ag   16 Bu   17 Bu
                #   0.370   0.413   0.416   0.422   0.446   0.469   0.496   0.539
                #  17 Ag   18 Bu   18 Ag   19 Bu   19 Ag   20 Bu   20 Ag   21 Ag
                #   0.571   0.587   0.610   0.627   0.646   0.693   0.743   0.806
                #  21 Bu   22 Ag   22 Bu   23 Bu   23 Ag   24 Ag   24 Bu   25 Ag
                #   0.816
                #  25 Bu
                #
                #  Beta MOs, Restricted
                #  -- Occupied --
                # -10.018 -10.018 -10.008 -10.008 -10.007 -10.007 -10.006 -10.005
                #   1 Bu    1 Ag    2 Bu    2 Ag    3 Bu    3 Ag    4 Bu    4 Ag
                #  -9.992  -9.992  -0.818  -0.755  -0.721  -0.704  -0.670  -0.585
                #   5 Ag    5 Bu    6 Ag    6 Bu    7 Ag    7 Bu    8 Bu    8 Ag
                #  -0.561  -0.532  -0.512  -0.462  -0.439  -0.410  -0.400  -0.397
                #   9 Ag    9 Bu   10 Ag   11 Ag   10 Bu   11 Bu   12 Bu   12 Ag
                #  -0.376  -0.358  -0.349  -0.330  -0.305  -0.295  -0.281  -0.263
                #  13 Bu   14 Bu   13 Ag    1 Au   15 Bu   14 Ag   15 Ag    1 Bg
                #  -0.216  -0.198  -0.160
                #   2 Au    2 Bg    3 Bg
                #  -- Virtual --
                #   0.050   0.091   0.116   0.181   0.280   0.319   0.330   0.365
                #   3 Au    4 Au    4 Bg    5 Au    5 Bg   16 Ag   16 Bu   17 Bu
                #   0.370   0.413   0.416   0.422   0.446   0.469   0.496   0.539
                #  17 Ag   18 Bu   18 Ag   19 Bu   19 Ag   20 Bu   20 Ag   21 Ag
                #   0.571   0.587   0.610   0.627   0.646   0.693   0.743   0.806
                #  21 Bu   22 Ag   22 Bu   23 Bu   23 Ag   24 Ag   24 Bu   25 Ag
                #   0.816
                #  25 Bu
                #  --------------------------------------------------------------

                self.skip_line(inputfile, 'dashes')
                line = next(inputfile)
                # Sometimes Q-Chem gets a little confused...
                while 'Warning : Irrep of orbital' in line:
                    line = next(inputfile)
                line = next(inputfile)
                energies_alpha = []
                symbols_alpha = []
                if self.unrestricted:
                    energies_beta = []
                    symbols_beta = []
                line = next(inputfile)

                # The end of the block is either a blank line or only dashes.
                while not self.re_dashes_and_spaces.search(line):
                    if 'Occupied' in line or 'Virtual' in line:
                        # A nice trick to find where the HOMO is.
                        if 'Virtual' in line:
                            self.homos = [len(energies_alpha)-1]
                        line = next(inputfile)
                    # Parse the energies and symmetries in pairs of lines.
                    # energies = [utils.convertor(energy, 'hartree', 'eV')
                    #             for energy in map(float, line.split())]
                    # This convoluted bit handles '*******' when present.
                    energies = []
                    energy_line = line.split()
                    for e in energy_line:
                        try:
                            energy = utils.convertor(self.float(e), 'hartree', 'eV')
                        except ValueError:
                            energy = numpy.nan
                        energies.append(energy)
                    energies_alpha.extend(energies)
                    line = next(inputfile)
                    symbols = line.split()[1::2]
                    symbols_alpha.extend(symbols)
                    line = next(inputfile)

                line = next(inputfile)
                # Only look at the second block if doing an unrestricted calculation.
                # This might be a problem for ROHF/ROKS.
                if self.unrestricted:
                    assert 'Beta MOs' in line
                    self.skip_line(inputfile, '-- Occupied --')
                    line = next(inputfile)
                    while not self.re_dashes_and_spaces.search(line):
                        if 'Occupied' in line or 'Virtual' in line:
                            # This will definitely exist, thanks to the above block.
                            if 'Virtual' in line:
                                if len(self.homos) == 1:
                                    self.homos.append(len(energies_beta)-1)
                            line = next(inputfile)
                        energies = []
                        energy_line = line.split()
                        for e in energy_line:
                            try:
                                energy = utils.convertor(self.float(e), 'hartree', 'eV')
                            except ValueError:
                                energy = numpy.nan
                            energies.append(energy)
                        energies_beta.extend(energies)
                        line = next(inputfile)
                        symbols = line.split()[1::2]
                        symbols_beta.extend(symbols)
                        line = next(inputfile)

                # For now, only keep the last set of MO energies, even though it is
                # printed at every step of geometry optimizations and fragment jobs.
                self.moenergies = [[]]
                self.mosyms = [[]]
                self.moenergies[0] = numpy.array(energies_alpha)
                self.mosyms[0] = symbols_alpha
                if self.unrestricted:
                    self.moenergies.append([])
                    self.mosyms.append([])
                    self.moenergies[1] = numpy.array(energies_beta)
                    self.mosyms[1] = symbols_beta

                self.set_attribute('nmo', len(self.moenergies[0]))

            # Molecular orbital energies, no symmetries.

            if line.strip() == 'Orbital Energies (a.u.)':

                # In the case of no orbital symmetries, the beta spin block is not
                # present for restricted calculations.

                #  --------------------------------------------------------------
                #                     Orbital Energies (a.u.)
                #  --------------------------------------------------------------
                #
                #  Alpha MOs
                #  -- Occupied --
                # ******* -38.595 -34.580 -34.579 -34.578 -19.372 -19.372 -19.364
                # -19.363 -19.362 -19.362  -4.738  -3.252  -3.250  -3.250  -1.379
                #  -1.371  -1.369  -1.365  -1.364  -1.362  -0.859  -0.855  -0.849
                #  -0.846  -0.840  -0.836  -0.810  -0.759  -0.732  -0.729  -0.704
                #  -0.701  -0.621  -0.610  -0.595  -0.587  -0.584  -0.578  -0.411
                #  -0.403  -0.355  -0.354  -0.352
                #  -- Virtual --
                #  -0.201  -0.117  -0.099  -0.086   0.020   0.031   0.055   0.067
                #   0.075   0.082   0.086   0.092   0.096   0.105   0.114   0.148
                #
                #  Beta MOs
                #  -- Occupied --
                # ******* -38.561 -34.550 -34.549 -34.549 -19.375 -19.375 -19.367
                # -19.367 -19.365 -19.365  -4.605  -3.105  -3.103  -3.102  -1.385
                #  -1.376  -1.376  -1.371  -1.370  -1.368  -0.863  -0.858  -0.853
                #  -0.849  -0.843  -0.839  -0.818  -0.765  -0.738  -0.737  -0.706
                #  -0.702  -0.624  -0.613  -0.600  -0.591  -0.588  -0.585  -0.291
                #  -0.291  -0.288  -0.275
                #  -- Virtual --
                #  -0.139  -0.122  -0.103   0.003   0.014   0.049   0.049   0.059
                #   0.061   0.070   0.076   0.081   0.086   0.090   0.098   0.106
                #   0.138
                #  --------------------------------------------------------------

                self.skip_lines(inputfile, ['dashes', 'blank'])
                line = next(inputfile)
                energies_alpha = []
                if self.unrestricted:
                    energies_beta = []
                line = next(inputfile)

                # The end of the block is either a blank line or only dashes.
                while not self.re_dashes_and_spaces.search(line):
                    if 'Occupied' in line or 'Virtual' in line:
                        # A nice trick to find where the HOMO is.
                        if 'Virtual' in line:
                            self.homos = [len(energies_alpha)-1]
                        line = next(inputfile)
                    energies = []
                    energy_line = line.split()
                    for e in energy_line:
                        try:
                            energy = utils.convertor(self.float(e), 'hartree', 'eV')
                        except ValueError:
                            energy = numpy.nan
                        energies.append(energy)
                    energies_alpha.extend(energies)
                    line = next(inputfile)

                line = next(inputfile)
                # Only look at the second block if doing an unrestricted calculation.
                # This might be a problem for ROHF/ROKS.
                if self.unrestricted:
                    assert 'Beta MOs' in line
                    self.skip_line(inputfile, '-- Occupied --')
                    line = next(inputfile)
                    while not self.re_dashes_and_spaces.search(line):
                        if 'Occupied' in line or 'Virtual' in line:
                            # This will definitely exist, thanks to the above block.
                            if 'Virtual' in line:
                                if len(self.homos) == 1:
                                    self.homos.append(len(energies_beta)-1)
                            line = next(inputfile)
                        energies = []
                        energy_line = line.split()
                        for e in energy_line:
                            try:
                                energy = utils.convertor(self.float(e), 'hartree', 'eV')
                            except ValueError:
                                energy = numpy.nan
                            energies.append(energy)
                        energies_beta.extend(energies)
                        line = next(inputfile)

                # For now, only keep the last set of MO energies, even though it is
                # printed at every step of geometry optimizations and fragment jobs.
                self.moenergies = [[]]
                self.moenergies[0] = numpy.array(energies_alpha)
                if self.unrestricted:
                    self.moenergies.append([])
                    self.moenergies[1] = numpy.array(energies_beta)
                self.set_attribute('nmo', len(self.moenergies[0]))

            # If we've asked to display more virtual orbitals than there
            # are MOs present in the molecule, fix that now.
            if hasattr(self, 'nmo') and hasattr(self, 'nalpha') and hasattr(self, 'nbeta'):
                if self.norbdisp_alpha_aonames > self.nmo:
                    self.norbdisp_alpha_aonames = self.nmo
                if self.norbdisp_beta_aonames > self.nmo:
                    self.norbdisp_beta_aonames = self.nmo

            # Molecular orbital coefficients.

            # This block comes from `print_orbitals = true/{int}`. Less
            # precision than `scf_final_print >= 2` for `mocoeffs`, but
            # important for `aonames` and `atombasis`.

            if any(header in line
                   for header in self.alpha_mo_coefficient_headers):

                if not hasattr(self, 'mocoeffs'):
                    self.mocoeffs = []
                if not hasattr(self, 'atombasis'):
                    self.atombasis = []
                    for n in range(self.natom):
                        self.atombasis.append([])
                if not hasattr(self, 'aonames'):
                    self.aonames = []
                # We could also attempt to parse `moenergies` here, but
                # nothing is gained by it.

                mocoeffs = numpy.empty(shape=(self.nbasis, self.norbdisp_alpha_aonames))
                self.parse_matrix_aonames(inputfile, mocoeffs)
                # Only use these MO coefficients if we don't have them
                # from `scf_final_print`.
                if len(self.mocoeffs) == 0:
                    self.mocoeffs.append(mocoeffs.transpose())

                # Go back through `aonames` to create `atombasis`.
                assert len(self.aonames) == self.nbasis
                for aoindex, aoname in enumerate(self.aonames):
                    atomindex = int(self.re_atomindex.search(aoname).groups()[0]) - 1
                    self.atombasis[atomindex].append(aoindex)
                assert len(self.atombasis) == len(self.atomnos)

            if 'BETA  MOLECULAR ORBITAL COEFFICIENTS' in line:

                mocoeffs = numpy.empty(shape=(self.nbasis, self.norbdisp_beta_aonames))
                self.parse_matrix_aonames(inputfile, mocoeffs)
                if len(self.mocoeffs) == 1:
                    self.mocoeffs.append(mocoeffs.transpose())

            # Population analysis.

            if 'Ground-State Mulliken Net Atomic Charges' in line:
                self.parse_charge_section(inputfile, 'mulliken')
            if 'Hirshfeld Atomic Charges' in line:
                self.parse_charge_section(inputfile, 'hirshfeld')
            if 'Ground-State ChElPG Net Atomic Charges' in line:
                self.parse_charge_section(inputfile, 'chelpg')

            # Multipole moments are not printed in lexicographical order,
            # so we need to parse and sort them. The units seem OK, but there
            # is some uncertainty about the reference point and whether it
            # can be changed.
            #
            # Notice how the letter/coordinate labels change to coordinate ranks
            # after hexadecapole moments, and need to be translated. Additionally,
            # after 9-th order moments the ranks are not necessarily single digits
            # and so there are spaces between them.
            #
            # -----------------------------------------------------------------
            #                    Cartesian Multipole Moments
            #                  LMN = < X^L Y^M Z^N >
            # -----------------------------------------------------------------
            #    Charge (ESU x 10^10)
            #                 0.0000
            #    Dipole Moment (Debye)
            #         X       0.0000      Y       0.0000      Z       0.0000
            #       Tot       0.0000
            #    Quadrupole Moments (Debye-Ang)
            #        XX     -50.9647     XY      -0.1100     YY     -50.1441
            #        XZ       0.0000     YZ       0.0000     ZZ     -58.5742
            # ...
            #    5th-Order Moments (Debye-Ang^4)
            #       500       0.0159    410      -0.0010    320       0.0005
            #       230       0.0000    140       0.0005    050       0.0012
            # ...
            # -----------------------------------------------------------------
            #
            if "Cartesian Multipole Moments" in line:

                # This line appears not by default, but only when
                # `multipole_order` > 4:
                line = inputfile.next()
                if 'LMN = < X^L Y^M Z^N >' in line:
                    line = inputfile.next()

                # The reference point is always the origin, although normally the molecule
                # is moved so that the center of charge is at the origin.
                self.reference = [0.0, 0.0, 0.0]
                self.moments = [self.reference]

                # Watch out! This charge is in statcoulombs without the exponent!
                # We should expect very good agreement, however Q-Chem prints
                # the charge only with 5 digits, so expect 1e-4 accuracy.
                charge_header = inputfile.next()
                assert charge_header.split()[0] == "Charge"
                charge = float(inputfile.next().strip())
                charge = utils.convertor(charge, 'statcoulomb', 'e') * 1e-10
                # Allow this to change until fragment jobs are properly implemented.
                # assert abs(charge - self.charge) < 1e-4

                # This will make sure Debyes are used (not sure if it can be changed).
                line = inputfile.next()
                assert line.strip() == "Dipole Moment (Debye)"

                while "-----" not in line:

                    # The current multipole element will be gathered here.
                    multipole = []

                    line = inputfile.next()
                    while ("-----" not in line) and ("Moment" not in line):

                        cols = line.split()

                        # The total (norm) is printed for dipole but not other multipoles.
                        if cols[0] == 'Tot':
                            line = inputfile.next()
                            continue

                        # Find and replace any 'stars' with NaN before moving on.
                        for i in range(len(cols)):
                            if '***' in cols[i]:
                                cols[i] = numpy.nan

                        # The moments come in pairs (label followed by value) up to the 9-th order,
                        # although above hexadecapoles the labels are digits representing the rank
                        # in each coordinate. Above the 9-th order, ranks are not always single digits,
                        # so there are spaces between them, which means moments come in quartets.
                        if len(self.moments) < 5:
                            for i in range(len(cols)//2):
                                lbl = cols[2*i]
                                m = cols[2*i + 1]
                                multipole.append([lbl, m])
                        elif len(self.moments) < 10:
                            for i in range(len(cols)//2):
                                lbl = cols[2*i]
                                lbl = 'X'*int(lbl[0]) + 'Y'*int(lbl[1]) + 'Z'*int(lbl[2])
                                m = cols[2*i + 1]
                                multipole.append([lbl, m])
                        else:
                            for i in range(len(cols)//4):
                                lbl = 'X'*int(cols[4*i]) + 'Y'*int(cols[4*i + 1]) + 'Z'*int(cols[4*i + 2])
                                m = cols[4*i + 3]
                                multipole.append([lbl, m])

                        line = inputfile.next()

                    # Sort should use the first element when sorting lists,
                    # so this should simply work, and afterwards we just need
                    # to extract the second element in each list (the actual moment).
                    multipole.sort()
                    multipole = [m[1] for m in multipole]
                    self.moments.append(multipole)

            # For `method = force` or geometry optimizations,
            # the gradient is printed.
            if 'Gradient of SCF Energy' in line:
                if not hasattr(self, 'grads'):
                    self.grads = []
                grad = numpy.empty(shape=(3, self.natom))
                self.parse_matrix(inputfile, grad)
                self.grads.append(grad.T)

            # For IR-related jobs, the Hessian is printed (dim: 3*natom, 3*natom).
            # Note that this is *not* the mass-weighted Hessian.
            if 'Hessian of the SCF Energy' in line:
                if not hasattr(self, 'hessian'):
                    dim = 3*self.natom
                    self.hessian = numpy.empty(shape=(dim, dim))
                    self.parse_matrix(inputfile, self.hessian)

            # Start of the IR/Raman frequency section.
            if 'VIBRATIONAL ANALYSIS' in line:

                while 'STANDARD THERMODYNAMIC QUANTITIES' not in line:
                    ## IR, optional Raman:
                    #
                    # **********************************************************************
                    # **                                                                  **
                    # **                       VIBRATIONAL ANALYSIS                       **
                    # **                       --------------------                       **
                    # **                                                                  **
                    # **        VIBRATIONAL FREQUENCIES (CM**-1) AND NORMAL MODES         **
                    # **     FORCE CONSTANTS (mDYN/ANGSTROM) AND REDUCED MASSES (AMU)     **
                    # **                  INFRARED INTENSITIES (KM/MOL)                   **
                    ##** RAMAN SCATTERING ACTIVITIES (A**4/AMU) AND DEPOLARIZATION RATIOS **
                    # **                                                                  **
                    # **********************************************************************
                    #
                    #
                    # Mode:                 1                      2                      3
                    # Frequency:      -106.88                -102.91                 161.77
                    # Force Cnst:      0.0185                 0.0178                 0.0380
                    # Red. Mass:       2.7502                 2.8542                 2.4660
                    # IR Active:          NO                     YES                    YES
                    # IR Intens:        0.000                  0.000                  0.419
                    # Raman Active:       YES                    NO                     NO
                    ##Raman Intens:     2.048                  0.000                  0.000
                    ##Depolar:          0.750                  0.000                  0.000
                    #               X      Y      Z        X      Y      Z        X      Y      Z
                    # C          0.000  0.000 -0.100   -0.000  0.000 -0.070   -0.000 -0.000 -0.027
                    # C          0.000  0.000  0.045   -0.000  0.000 -0.074    0.000 -0.000 -0.109
                    # C          0.000  0.000  0.148   -0.000 -0.000 -0.074    0.000  0.000 -0.121
                    # C          0.000  0.000  0.100   -0.000 -0.000 -0.070    0.000  0.000 -0.027
                    # C          0.000  0.000 -0.045    0.000 -0.000 -0.074   -0.000 -0.000 -0.109
                    # C          0.000  0.000 -0.148    0.000  0.000 -0.074   -0.000 -0.000 -0.121
                    # H         -0.000  0.000  0.086   -0.000  0.000 -0.082    0.000 -0.000 -0.102
                    # H          0.000  0.000  0.269   -0.000 -0.000 -0.091    0.000  0.000 -0.118
                    # H          0.000  0.000 -0.086    0.000 -0.000 -0.082   -0.000  0.000 -0.102
                    # H         -0.000  0.000 -0.269    0.000  0.000 -0.091   -0.000 -0.000 -0.118
                    # C          0.000 -0.000  0.141   -0.000 -0.000 -0.062   -0.000  0.000  0.193
                    # C         -0.000 -0.000 -0.160    0.000  0.000  0.254   -0.000  0.000  0.043
                    # H          0.000 -0.000  0.378   -0.000  0.000 -0.289    0.000  0.000  0.519
                    # H         -0.000 -0.000 -0.140    0.000  0.000  0.261   -0.000 -0.000  0.241
                    # H         -0.000 -0.000 -0.422    0.000  0.000  0.499   -0.000  0.000 -0.285
                    # C          0.000 -0.000 -0.141    0.000  0.000 -0.062   -0.000 -0.000  0.193
                    # C         -0.000 -0.000  0.160   -0.000 -0.000  0.254    0.000  0.000  0.043
                    # H          0.000 -0.000 -0.378    0.000 -0.000 -0.289   -0.000  0.000  0.519
                    # H         -0.000 -0.000  0.140   -0.000 -0.000  0.261    0.000  0.000  0.241
                    # H         -0.000 -0.000  0.422   -0.000 -0.000  0.499    0.000  0.000 -0.285
                    # TransDip   0.000 -0.000 -0.000    0.000 -0.000 -0.000   -0.000  0.000  0.021
                    #
                    # Mode:                 4                      5                      6
                    # ...
                    #
                    # There isn't any symmetry information for normal modes present
                    # in Q-Chem.
                    # if not hasattr(self, 'vibsyms'):
                    #     self.vibsyms = []
                    if 'Frequency:' in line:
                        if not hasattr(self, 'vibfreqs'):
                            self.vibfreqs = []
                        vibfreqs = map(float, line.split()[1:])
                        self.vibfreqs.extend(vibfreqs)

                    if 'IR Intens:' in line:
                        if not hasattr(self, 'vibirs'):
                            self.vibirs = []
                        vibirs = map(float, line.split()[2:])
                        self.vibirs.extend(vibirs)

                    if 'Raman Intens:' in line:
                        if not hasattr(self, 'vibramans'):
                            self.vibramans = []
                        vibramans = map(float, line.split()[2:])
                        self.vibramans.extend(vibramans)

                    # This is the start of the displacement block.
                    if line.split()[0:3] == ['X', 'Y', 'Z']:
                        if not hasattr(self, 'vibdisps'):
                            self.vibdisps = []
                        disps = []
                        for k in range(self.natom):
                            line = next(inputfile)
                            numbers = list(map(float, line.split()[1:]))
                            N = len(numbers) // 3
                            if not disps:
                                for n in range(N):
                                    disps.append([])
                            for n in range(N):
                                disps[n].append(numbers[3*n:(3*n)+3])
                        self.vibdisps.extend(disps)

                    line = next(inputfile)

                    # Anharmonic vibrational analysis.
                    # Q-Chem includes 3 theories: VPT2, TOSH, and VCI.
                    # For now, just take the VPT2 results.

                    # if 'VIBRATIONAL ANHARMONIC ANALYSIS' in line:

                    #     while list(set(line.strip())) != ['=']:
                    #         if 'VPT2' in line:
                    #             if not hasattr(self, 'vibanharms'):
                    #                 self.vibanharms = []
                    #             self.vibanharms.append(float(line.split()[-1]))
                    #         line = next(inputfile)

            if 'STANDARD THERMODYNAMIC QUANTITIES AT' in line:

                if not hasattr(self, 'temperature'):
                    self.temperature = float(line.split()[4])
                # Not supported yet.
                if not hasattr(self, 'pressure'):
                    self.pressure = float(line.split()[7])
                self.skip_lines(inputfile, ['blank', 'Imaginary'])
                line = next(inputfile)
                # Not supported yet.
                if 'Zero point vibrational energy' in line:
                    if not hasattr(self, 'zpe'):
                        # Convert from kcal/mol to Hartree/particle.
                        self.zpe = utils.convertor(float(line.split()[4]),
                                                   'kcal', 'hartree')

                atommasses = []

                while 'Archival summary' not in line:

                    if 'Has Mass' in line:
                        atommass = float(line.split()[6])
                        atommasses.append(atommass)

                    if 'Total Enthalpy' in line:
                        if not hasattr(self, 'enthalpy'):
                            enthalpy = float(line.split()[2])
                            self.enthalpy = utils.convertor(enthalpy,
                                                            'kcal', 'hartree')
                    if 'Total Entropy' in line:
                        if not hasattr(self, 'entropy'):
                            entropy = float(line.split()[2]) * self.temperature / 1000
                            # This is the *temperature dependent* entropy.
                            self.entropy = utils.convertor(entropy,
                                                           'kcal', 'hartree')
                        if not hasattr(self, 'freeenergy'):
                            self.freeenergy = self.enthalpy - self.entropy

                    line = next(inputfile)

                if not hasattr(self, 'atommasses'):
                    self.atommasses = numpy.array(atommasses)

        # TODO:
        # 'enthalpy' (incorrect)
        # 'entropy' (incorrect)
        # 'freeenergy' (incorrect)
        # 'nocoeffs'
        # 'nooccnos'
        # 'vibanharms'

    def parse_charge_section(self, inputfile, chargetype):
        """Parse the population analysis charge block."""
        self.skip_line(inputfile, 'blank')
        line = next(inputfile)
        has_spins = False
        if 'Spin' in line:
            if not hasattr(self, 'atomspins'):
                self.atomspins = dict()
            has_spins = True
            spins = []
        self.skip_line(inputfile, 'dashes')
        if not hasattr(self, 'atomcharges'):
            self.atomcharges = dict()
        charges = []
        line = next(inputfile)

        while list(set(line.strip())) != ['-']:
            elements = line.split()
            charge = self.float(elements[2])
            charges.append(charge)
            if has_spins:
                spin = self.float(elements[3])
                spins.append(spin)
            line = next(inputfile)

        self.atomcharges[chargetype] = numpy.array(charges)
        if has_spins:
            self.atomspins[chargetype] = numpy.array(spins)

    def parse_matrix(self, inputfile, nparray):
        """Q-Chem prints most matrices in a standard format; parse the matrix
        into a preallocated NumPy array of the appropriate shape.
        """
        nrows, ncols = nparray.shape
        line = next(inputfile)
        assert len(line.split()) == min(self.ncolsblock, ncols)
        colcounter = 0
        while colcounter < ncols:
            # If the line is just the column header (indices)...
            if line[:5].strip() == '':
                line = next(inputfile)
            rowcounter = 0
            while rowcounter < nrows:
                row = list(map(float, line.split()[1:]))
                assert len(row) == min(self.ncolsblock, (ncols - colcounter))
                nparray[rowcounter][colcounter:colcounter + self.ncolsblock] = row
                line = next(inputfile)
                rowcounter += 1
            colcounter += self.ncolsblock

    def parse_matrix_aonames(self, inputfile, nparray):
        """Q-Chem prints most matrices in a standard format; parse the matrix
        into a preallocated NumPy array of the appropriate shape.

        Rather than have one routine for parsing all general matrices
        and the 'MOLECULAR ORBITAL COEFFICIENTS' block, use a second
        which handles `aonames`.
        """
        bigmom = ('d', 'f', 'g', 'h')
        nrows, ncols = nparray.shape
        line = next(inputfile)
        assert len(line.split()) == min(self.ncolsblock, ncols)
        colcounter = 0
        while colcounter < ncols:
            # If the line is just the column header (indices)...
            if line[:5].strip() == '':
                line = next(inputfile)
            # Do nothing for now.
            if 'eigenvalues' in line:
                line = next(inputfile)
            rowcounter = 0
            while rowcounter < nrows:
                row = line.split()
                # Only take the AO names on the first time through.
                if colcounter == 0:
                    if len(self.aonames) != self.nbasis:
                        # Apply the offset for rows where there is
                        # more than one atom of any element in the
                        # molecule.
                        offset = int(self.formula_histogram[row[1]] != 1)
                        if offset:
                            name = self.atommap.get(row[1] + str(row[2]))
                        else:
                            name = self.atommap.get(row[1] + '1')
                        # For l > 1, there is a space between l and
                        # m_l when using spherical functions.
                        shell = row[2 + offset]
                        if shell in bigmom:
                            shell = ''.join([shell, row[3 + offset]])
                        aoname = ''.join([name, '_', shell.upper()])
                        self.aonames.append(aoname)
                row = list(map(float, row[-min(self.ncolsblock, (ncols - colcounter)):]))
                nparray[rowcounter][colcounter:colcounter + self.ncolsblock] = row
                line = next(inputfile)
                rowcounter += 1
            colcounter += self.ncolsblock

    def generate_atom_map(self):
        """Generate the map to go from Q-Chem atom numbering:
        'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'H1', 'H2', 'H3', 'H4', 'C7', ...
        to cclib atom numbering:
        'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'H7', 'H8', 'H9', 'H10', 'C11', ...
        for later use.
        """

        # Generate the desired order.
        order_proper = [element + str(num)
                        for element, num in zip(self.atomelements,
                                                itertools.count(start=1))]
        # We need separate counters for each element.
        element_counters = {element: itertools.count(start=1)
                            for element in set(self.atomelements)}
        # Generate the Q-Chem printed order.
        order_qchem = [element + str(next(element_counters[element]))
                       for element in self.atomelements]
        # Combine the orders into a mapping.
        atommap = {k: v for k, v, in zip(order_qchem, order_proper)}
        return atommap

    def generate_formula_histogram(self):
        """From the atomnos, generate a histogram that represents the
        molecular formula.
        """

        histogram = dict()
        for element in self.atomelements:
            if element in histogram.keys():
                histogram[element] += 1
            else:
                histogram[element] = 1
        return histogram


if __name__ == '__main__':
    import sys
    import doctest, qchemparser

    if len(sys.argv) == 1:
        doctest.testmod(qchemparser, verbose=False)

    if len(sys.argv) == 2:
        parser = qchemparser.QChem(sys.argv[1])
        data = parser.parse()

    if len(sys.argv) > 2:
        for i in range(len(sys.argv[2:])):
            if hasattr(data, sys.argv[2 + i]):
                print(getattr(data, sys.argv[2 + i]))
