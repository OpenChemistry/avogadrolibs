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

"""Parser for Gaussian output files"""

from __future__ import print_function

import numpy
import re

from . import data
from . import logfileparser
from . import utils


class Gaussian(logfileparser.Logfile):
    """A Gaussian 98/03 log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(Gaussian, self).__init__(logname="Gaussian", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "Gaussian log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'Gaussian("%s")' % (self.filename)

    def normalisesym(self, label):
        """Use standard symmetry labels instead of Gaussian labels.

        To normalise:
        (1) If label is one of [SG, PI, PHI, DLTA], replace by [sigma, pi, phi, delta]
        (2) replace any G or U by their lowercase equivalent

        >>> sym = Gaussian("dummyfile").normalisesym
        >>> labels = ['A1', 'AG', 'A1G', "SG", "PI", "PHI", "DLTA", 'DLTU', 'SGG']
        >>> map(sym, labels)
        ['A1', 'Ag', 'A1g', 'sigma', 'pi', 'phi', 'delta', 'delta.u', 'sigma.g']
        """
        # note: DLT must come after DLTA
        greek = [('SG', 'sigma'), ('PI', 'pi'), ('PHI', 'phi'),
                 ('DLTA', 'delta'), ('DLT', 'delta')]
        for k, v in greek:
            if label.startswith(k):
                tmp = label[len(k):]
                label = v
                if tmp:
                    label = v + "." + tmp

        ans = label.replace("U", "u").replace("G", "g")
        return ans

    def before_parsing(self):

        # Used to index self.scftargets[].
        SCFRMS, SCFMAX, SCFENERGY = list(range(3))

        # Flag for identifying Coupled Cluster runs.
        self.coupledcluster = False

        # Fragment number for counterpoise or fragment guess calculations
        # (normally zero).
        self.counterpoise = 0

        # Flag for identifying ONIOM calculations.
        self.oniom = False

    def after_parsing(self):

        # Correct the percent values in the etsecs in the case of
        # a restricted calculation. The following has the
        # effect of including each transition twice.
        if hasattr(self, "etsecs") and len(self.homos) == 1:
            new_etsecs = [[(x[0], x[1], x[2] * numpy.sqrt(2)) for x in etsec]
                          for etsec in self.etsecs]
            self.etsecs = new_etsecs

        if hasattr(self, "scanenergies"):
            self.scancoords = []
            self.scancoords = self.atomcoords

        if (hasattr(self, 'enthalpy') and hasattr(self, 'temperature')
                and hasattr(self, 'freeenergy')):
            self.set_attribute('entropy', (self.enthalpy - self.freeenergy) / self.temperature)

        # This bit is needed in order to trim coordinates that are printed a second time
        # at the end of geometry optimizations. Note that we need to do this for both atomcoords
        # and inputcoords. The reason is that normally a standard orientation is printed and that
        # is what we parse into atomcoords, but inputcoords stores the input (unmodified) coordinates
        # and that is copied over to atomcoords if no standard oritentation was printed, which happens
        # for example for jobs with no symmetry. This last step, however, is now generic for all parsers.
        # Perhaps then this part should also be generic code...
        # Regression that tests this: Gaussian03/cyclopropenyl.rhf.g03.cut.log
        if hasattr(self, 'optdone') and len(self.optdone) > 0:
            last_point = self.optdone[-1]
            if hasattr(self, 'atomcoords'):
                self.atomcoords = self.atomcoords[:last_point + 1]
            if hasattr(self, 'inputcoords'):
                self.inputcoords = self.inputcoords[:last_point + 1]

        # If we parsed high-precision vibrational displacements, overwrite
        # lower-precision displacements in self.vibdisps
        if hasattr(self, 'vibdispshp'):
            self.vibdisps = self.vibdispshp
            del self.vibdispshp

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # This block contains some general information as well as coordinates,
        # which could be parsed in the future:
        #
        # Symbolic Z-matrix:
        # Charge =  0 Multiplicity = 1
        # C                     0.73465   0.        0.
        # C                     1.93465   0.        0.
        # C
        # ...
        #
        # It also lists fragments, if there are any, which is potentially valuable:
        #
        # Symbolic Z-matrix:
        # Charge =  0 Multiplicity = 1 in supermolecule
        # Charge =  0 Multiplicity = 1 in fragment      1.
        # Charge =  0 Multiplicity = 1 in fragment      2.
        # B(Fragment=1)         0.06457  -0.0279    0.01364
        # H(Fragment=1)         0.03117  -0.02317   1.21604
        # ...
        #
        # Note, however, that currently we only parse information for the whole system
        # or supermolecule as Gaussian calls it.
        if line.strip() == "Symbolic Z-matrix:":

            self.updateprogress(inputfile, "Symbolic Z-matrix", self.fupdate)

            line = inputfile.next()
            while line.split()[0] == 'Charge':

                # For the supermolecule, we can parse the charge and multicplicity.
                regex = ".*=(.*)Mul.*=\s*-?(\d+).*"
                match = re.match(regex, line)
                assert match, "Something unusual about the line: '%s'" % line

                self.set_attribute('charge', int(match.groups()[0]))
                self.set_attribute('mult', int(match.groups()[1]))

                if line.split()[-2] == "fragment":
                    self.nfragments = int(line.split()[-1].strip('.'))

                if line.strip()[-13:] == "model system.":
                    self.nmodels = getattr(self, 'nmodels', 0) + 1

                line = inputfile.next()

            # The remaining part will allow us to get the atom count.
            # When coordinates are given, there is a blank line at the end, but if
            # there is a Z-matrix here, there will also be variables and we need to
            # stop at those to get the right atom count.
            # Also, in older versions there is bo blank line (G98 regressions),
            # so we need to watch out for leaving the link.
            natom = 0
            while line.split() and not "Variables" in line and not "Leave Link" in line:
                natom += 1
                line = inputfile.next()
            self.set_attribute('natom', natom)

        # Continuing from above, there is not always a symbolic matrix, for example
        # if the Z-matrix was in the input file. In such cases, try to match the
        # line and get at the charge and multiplicity.
        #
        #   Charge =  0 Multiplicity = 1 in supermolecule
        #   Charge =  0 Multiplicity = 1 in fragment  1.
        #   Charge =  0 Multiplicity = 1 in fragment  2.
        if line[1:7] == 'Charge' and line.find("Multiplicity") >= 0:

            self.updateprogress(inputfile, "Charge and Multiplicity", self.fupdate)

            if line.split()[-1] == "supermolecule" or not "fragment" in line:

                regex = ".*=(.*)Mul.*=\s*-?(\d+).*"
                match = re.match(regex, line)
                assert match, "Something unusual about the line: '%s'" % line

                self.set_attribute('charge', int(match.groups()[0]))
                self.set_attribute('mult', int(match.groups()[1]))

            if line.split()[-2] == "fragment":
                self.nfragments = int(line.split()[-1].strip('.'))

        # Number of atoms is also explicitely printed after the above.
        if line[1:8] == "NAtoms=":

            self.updateprogress(inputfile, "Attributes", self.fupdate)

            natom = int(line.split()[1])
            self.set_attribute('natom', natom)

        # Catch message about completed optimization.
        if line[1:23] == "Optimization completed":

            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.geovalues) - 1)

            assert hasattr(self, "optstatus") and len(self.optstatus) > 0
            self.optstatus[-1] = data.ccData.OPT_DONE

        # Catch message about stopped optimization (not converged).
        if line[1:21] == "Optimization stopped":

            if not hasattr(self, "optdone"):
                self.optdone = []

            assert hasattr(self, "optstatus") and len(self.optstatus) > 0
            self.optstatus[-1] = data.ccData.OPT_UNCONVERGED

        # Extract the atomic numbers and coordinates from the input orientation,
        #   in the event the standard orientation isn't available.
        if line.find("Input orientation") > -1 or line.find("Z-Matrix orientation") > -1:

            # If this is a counterpoise calculation, this output means that
            #   the supermolecule is now being considered, so we can set:
            self.counterpoise = 0

            self.updateprogress(inputfile, "Attributes", self.cupdate)

            if not hasattr(self, "inputcoords"):
                self.inputcoords = []
            self.inputatoms = []

            self.skip_lines(inputfile, ['d', 'cols', 'cols', 'd'])

            atomcoords = []
            line = next(inputfile)
            while list(set(line.strip())) != ["-"]:
                broken = line.split()
                self.inputatoms.append(int(broken[1]))
                atomcoords.append(list(map(float, broken[3:6])))
                line = next(inputfile)

            self.inputcoords.append(atomcoords)

            self.set_attribute('atomnos', self.inputatoms)
            self.set_attribute('natom', len(self.inputatoms))

        # Extract the atomic masses.
        # Typical section:
        #                    Isotopes and Nuclear Properties:
        #(Nuclear quadrupole moments (NQMom) in fm**2, nuclear magnetic moments (NMagM)
        # in nuclear magnetons)
        #
        #  Atom         1           2           3           4           5           6           7           8           9          10
        # IAtWgt=          12          12          12          12          12           1           1           1          12          12
        # AtmWgt=  12.0000000  12.0000000  12.0000000  12.0000000  12.0000000   1.0078250   1.0078250   1.0078250  12.0000000  12.0000000
        # NucSpn=           0           0           0           0           0           1           1           1           0           0
        # AtZEff=  -3.6000000  -3.6000000  -3.6000000  -3.6000000  -3.6000000  -1.0000000  -1.0000000  -1.0000000  -3.6000000  -3.6000000
        # NQMom=    0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   0.0000000
        # NMagM=    0.0000000   0.0000000   0.0000000   0.0000000   0.0000000   2.7928460   2.7928460   2.7928460   0.0000000   0.0000000
        # ... with blank lines dividing blocks of ten, and Leave Link 101 at the end.
        # This is generally parsed before coordinates, so atomnos is not defined.
        # Note that in Gaussian03 the comments are not there yet and the labels are different.
        if line.strip() == "Isotopes and Nuclear Properties:":

            if not hasattr(self, "atommasses"):
                self.atommasses = []

            line = next(inputfile)
            while line[1:16] != "Leave Link  101":
                if line[1:8] == "AtmWgt=":
                    self.atommasses.extend(list(map(float, line.split()[1:])))
                line = next(inputfile)

        # Extract the atomic numbers and coordinates of the atoms.
        if line.strip() == "Standard orientation:":

            self.updateprogress(inputfile, "Attributes", self.cupdate)

            # If this is a counterpoise calculation, this output means that
            #   the supermolecule is now being considered, so we can set:
            self.counterpoise = 0

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []

            self.skip_lines(inputfile, ['d', 'cols', 'cols', 'd'])

            atomnos = []
            atomcoords = []
            line = next(inputfile)
            while list(set(line.strip())) != ["-"]:
                broken = line.split()
                atomnos.append(int(broken[1]))
                atomcoords.append(list(map(float, broken[-3:])))
                line = next(inputfile)
            self.atomcoords.append(atomcoords)

            self.set_attribute('natom', len(atomnos))
            self.set_attribute('atomnos', atomnos)

        # This is a bit of a hack for regression Gaussian09/BH3_fragment_guess.pop_minimal.log
        # to skip output for all fragments, assuming the supermolecule is always printed first.
        # Eventually we want to make this more general, or even better parse the output for
        # all fragment, but that will happen in a newer version of cclib.
        if line[1:16] == "Fragment guess:" and getattr(self, 'nfragments', 0) > 1:
            if not "full" in line:
                inputfile.seek(0, 2)

        # Another hack for regression Gaussian03/ortho_prod_prod_freq.log, which is an ONIOM job.
        # Basically for now we stop parsing after the output for the real system, because
        # currently we don't support changes in system size or fragments in cclib. When we do,
        # we will want to parse the model systems, too, and that is what nmodels could track.
        if "ONIOM: generating point" in line and line.strip()[-13:] == 'model system.' and getattr(self, 'nmodels', 0) > 0:
            inputfile.seek(0, 2)

        # With the gfinput keyword, the atomic basis set functios are:
        #
        # AO basis set in the form of general basis input (Overlap normalization):
        #  1 0
        # S   3 1.00       0.000000000000
        #      0.7161683735D+02  0.1543289673D+00
        #      0.1304509632D+02  0.5353281423D+00
        #      0.3530512160D+01  0.4446345422D+00
        # SP   3 1.00       0.000000000000
        #      0.2941249355D+01 -0.9996722919D-01  0.1559162750D+00
        #      0.6834830964D+00  0.3995128261D+00  0.6076837186D+00
        #      0.2222899159D+00  0.7001154689D+00  0.3919573931D+00
        # ****
        #  2 0
        # S   3 1.00       0.000000000000
        #      0.7161683735D+02  0.1543289673D+00
        # ...
        #
        # The same is also printed when the gfprint keyword is used, but the
        # interstitial lines differ and there are no stars between atoms:
        #
        # AO basis set (Overlap normalization):
        # Atom C1       Shell     1 S   3     bf    1 -     1          0.509245180608         -2.664678875191          0.000000000000
        #       0.7161683735D+02  0.1543289673D+00
        #       0.1304509632D+02  0.5353281423D+00
        #       0.3530512160D+01  0.4446345422D+00
        # Atom C1       Shell     2 SP   3    bf    2 -     5          0.509245180608         -2.664678875191          0.000000000000
        #       0.2941249355D+01 -0.9996722919D-01  0.1559162750D+00
        # ...

        #ONIOM calculations result basis sets reported for atoms that are not in order of atom number which breaks this code (line 390 relies on atoms coming in order)
        if line[1:13] == "AO basis set" and not self.oniom:

            self.gbasis = []

            # For counterpoise fragment calcualtions, skip these lines.
            if self.counterpoise != 0:
                return

            atom_line = inputfile.next()
            self.gfprint = atom_line.split()[0] == "Atom"
            self.gfinput = not self.gfprint

            # Note how the shell information is on a separate line for gfinput,
            # whereas for gfprint it is on the same line as atom information.
            if self.gfinput:
                shell_line = inputfile.next()

            shell = []
            while len(self.gbasis) < self.natom:

                if self.gfprint:
                    cols = atom_line.split()
                    subshells = cols[4]
                    ngauss = int(cols[5])
                else:
                    cols = shell_line.split()
                    subshells = cols[0]
                    ngauss = int(cols[1])

                parameters = []
                for ig in range(ngauss):
                    line = inputfile.next()
                    parameters.append(list(map(self.float, line.split())))
                for iss, ss in enumerate(subshells):
                    contractions = []
                    for param in parameters:
                        exponent = param[0]
                        coefficient = param[iss+1]
                        contractions.append((exponent, coefficient))
                    subshell = (ss, contractions)
                    shell.append(subshell)

                if self.gfprint:
                    line = inputfile.next()
                    if line.split()[0] == "Atom":
                        atomnum = int(re.sub(r"\D", "", line.split()[1]))
                        if atomnum == len(self.gbasis) + 2:
                            self.gbasis.append(shell)
                            shell = []
                        atom_line = line
                    else:
                        self.gbasis.append(shell)
                else:
                    line = inputfile.next()
                    if line.strip() == "****":
                        self.gbasis.append(shell)
                        shell = []
                        atom_line = inputfile.next()
                        shell_line = inputfile.next()
                    else:
                        shell_line = line

        # Find the targets for SCF convergence (QM calcs).
        if line[1:44] == 'Requested convergence on RMS density matrix':

            if not hasattr(self, "scftargets"):
                self.scftargets = []
            # The following can happen with ONIOM which are mixed SCF
            # and semi-empirical
            if type(self.scftargets) == type(numpy.array([])):
                self.scftargets = []

            scftargets = []
            # The RMS density matrix.
            scftargets.append(self.float(line.split('=')[1].split()[0]))
            line = next(inputfile)
            # The MAX density matrix.
            scftargets.append(self.float(line.strip().split('=')[1][:-1]))
            line = next(inputfile)
            # For G03, there's also the energy (not for G98).
            if line[1:10] == "Requested":
                scftargets.append(self.float(line.strip().split('=')[1][:-1]))

            self.scftargets.append(scftargets)

        # Extract SCF convergence information (QM calcs).
        if line[1:10] == 'Cycle   1':

            if not hasattr(self, "scfvalues"):
                self.scfvalues = []

            scfvalues = []
            line = next(inputfile)
            while line.find("SCF Done") == -1:

                self.updateprogress(inputfile, "QM convergence", self.fupdate)

                if line.find(' E=') == 0:
                    self.logger.debug(line)

                #  RMSDP=3.74D-06 MaxDP=7.27D-05 DE=-1.73D-07 OVMax= 3.67D-05
                # or
                #  RMSDP=1.13D-05 MaxDP=1.08D-04              OVMax= 1.66D-04
                if line.find(" RMSDP") == 0:

                    parts = line.split()
                    newlist = [self.float(x.split('=')[1]) for x in parts[0:2]]
                    energy = 1.0
                    if len(parts) > 4:
                        energy = parts[2].split('=')[1]
                        if energy == "":
                            energy = self.float(parts[3])
                        else:
                            energy = self.float(energy)
                    if len(self.scftargets[0]) == 3:  # Only add the energy if it's a target criteria
                        newlist.append(energy)
                    scfvalues.append(newlist)

                try:
                    line = next(inputfile)
                # May be interupted by EOF.
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF!')
                    break

            self.scfvalues.append(scfvalues)

        # Extract SCF convergence information (AM1, INDO and other semi-empirical calcs).
        # The output (for AM1) looks like this:
        # Ext34=T Pulay=F Camp-King=F BShift= 0.00D+00
        # It=  1 PL= 0.103D+01 DiagD=T ESCF=     31.564733 Diff= 0.272D+02 RMSDP= 0.152D+00.
        # It=  2 PL= 0.114D+00 DiagD=T ESCF=      7.265370 Diff=-0.243D+02 RMSDP= 0.589D-02.
        # ...
        # It= 11 PL= 0.184D-04 DiagD=F ESCF=      4.687669 Diff= 0.260D-05 RMSDP= 0.134D-05.
        # It= 12 PL= 0.105D-04 DiagD=F ESCF=      4.687669 Diff=-0.686D-07 RMSDP= 0.215D-05.
        # 4-point extrapolation.
        # It= 13 PL= 0.110D-05 DiagD=F ESCF=      4.687669 Diff=-0.111D-06 RMSDP= 0.653D-07.
        # Energy=    0.172272018655 NIter=  14.
        if line[1:4] == 'It=':

            scftargets = numpy.array([1E-7], "d")  # This is the target value for the rms
            scfvalues = [[]]

            while line.find(" Energy") == -1:

                self.updateprogress(inputfile, "AM1 Convergence")

                if line[1:4] == "It=":
                    parts = line.strip().split()
                    scfvalues[0].append(self.float(parts[-1][:-1]))

                line = next(inputfile)

                # If an AM1 or INDO guess is used (Guess=INDO in the input, for example),
                # this will be printed after a single iteration, so that is the line
                # that should trigger a break from this loop. At least that's what we see
                # for regression Gaussian/Gaussian09/guessIndo_modified_ALT.out
                if line[:14] == " Initial guess":
                    break

            # Attach the attributes to the object Only after the energy is found .
            if line.find(" Energy") == 0:
                self.scftargets = scftargets
                self.scfvalues = scfvalues

        # Note: this needs to follow the section where 'SCF Done' is used
        #   to terminate a loop when extracting SCF convergence information.
        if line[1:9] == 'SCF Done':

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []

            self.scfenergies.append(utils.convertor(self.float(line.split()[4]), "hartree", "eV"))
        # gmagoon 5/27/09: added scfenergies reading for PM3 case
        # Example line: " Energy=   -0.077520562724 NIter=  14."
        # See regression Gaussian03/QVGXLLKOCUKJST-UHFFFAOYAJmult3Fixed.out
        if line[1:8] == 'Energy=':
            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            self.scfenergies.append(utils.convertor(self.float(line.split()[1]), "hartree", "eV"))

        # Total energies after Moller-Plesset corrections.
        # Second order correction is always first, so its first occurance
        #   triggers creation of mpenergies (list of lists of energies).
        # Further MP2 corrections are appended as found.
        #
        # Example MP2 output line:
        #  E2 =    -0.9505918144D+00 EUMP2 =    -0.28670924198852D+03
        # Warning! this output line is subtly different for MP3/4/5 runs
        if "EUMP2" in line[27:34]:

            if not hasattr(self, "mpenergies"):
                self.mpenergies = []
            self.mpenergies.append([])
            mp2energy = self.float(line.split("=")[2])
            self.mpenergies[-1].append(utils.convertor(mp2energy, "hartree", "eV"))

        # Example MP3 output line:
        #  E3=       -0.10518801D-01     EUMP3=      -0.75012800924D+02
        if line[34:39] == "EUMP3":

            mp3energy = self.float(line.split("=")[2])
            self.mpenergies[-1].append(utils.convertor(mp3energy, "hartree", "eV"))

        # Example MP4 output lines:
        #  E4(DQ)=   -0.31002157D-02        UMP4(DQ)=   -0.75015901139D+02
        #  E4(SDQ)=  -0.32127241D-02        UMP4(SDQ)=  -0.75016013648D+02
        #  E4(SDTQ)= -0.32671209D-02        UMP4(SDTQ)= -0.75016068045D+02
        # Energy for most substitutions is used only (SDTQ by default)
        if line[34:42] == "UMP4(DQ)":

            mp4energy = self.float(line.split("=")[2])
            line = next(inputfile)
            if line[34:43] == "UMP4(SDQ)":
                mp4energy = self.float(line.split("=")[2])
                line = next(inputfile)
                if line[34:44] == "UMP4(SDTQ)":
                    mp4energy = self.float(line.split("=")[2])
            self.mpenergies[-1].append(utils.convertor(mp4energy, "hartree", "eV"))

        # Example MP5 output line:
        #  DEMP5 =  -0.11048812312D-02 MP5 =  -0.75017172926D+02
        if line[29:32] == "MP5":
            mp5energy = self.float(line.split("=")[2])
            self.mpenergies[-1].append(utils.convertor(mp5energy, "hartree", "eV"))

        # Total energies after Coupled Cluster corrections.
        # Second order MBPT energies (MP2) are also calculated for these runs,
        # but the output is the same as when parsing for mpenergies.
        # Read the consecutive correlated energies
        # but append only the last one to ccenergies.
        # Only the highest level energy is appended - ex. CCSD(T), not CCSD.
        if line[1:10] == "DE(Corr)=" and line[27:35] == "E(CORR)=":
            self.ccenergy = self.float(line.split()[3])
        if line[1:10] == "T5(CCSD)=":
            line = next(inputfile)
            if line[1:9] == "CCSD(T)=":
                self.ccenergy = self.float(line.split()[1])
        if line[12:53] == "Population analysis using the SCF density":
            if hasattr(self, "ccenergy"):
                if not hasattr(self, "ccenergies"):
                    self.ccenergies = []
                self.ccenergies.append(utils.convertor(self.ccenergy, "hartree", "eV"))
                del self.ccenergy

        if " Step number" in line:
            step = int(line.split()[2])
            if step == 1:
                if not hasattr(self, "optstatus"):
                    self.optstatus = []
                self.optstatus.append(data.ccData.OPT_NEW)

        # Geometry convergence information.
        if line[49:59] == 'Converged?':

            if not hasattr(self, "geotargets"):
                self.geovalues = []
                self.geotargets = numpy.array([0.0, 0.0, 0.0, 0.0], "d")

            newlist = [0]*4
            for i in range(4):
                line = next(inputfile)
                self.logger.debug(line)
                parts = line.split()
                try:
                    value = self.float(parts[2])
                except ValueError:
                    self.logger.error("Problem parsing the value for geometry optimisation: %s is not a number." % parts[2])
                else:
                    newlist[i] = value
                self.geotargets[i] = self.float(parts[3])

            self.geovalues.append(newlist)

            if not hasattr(self, "optstatus"):
                self.optstatus = []
            if len(self.optstatus) == len(self.geovalues) - 1:
                self.optstatus.append(data.ccData.OPT_UNKNOWN)
            else:
                assert self.optstatus[-1] == data.ccData.OPT_NEW

        # Gradients.
        # Read in the cartesian energy gradients (forces) from a block like this:
        # -------------------------------------------------------------------
        # Center     Atomic                   Forces (Hartrees/Bohr)
        # Number     Number              X              Y              Z
        # -------------------------------------------------------------------
        # 1          1          -0.012534744   -0.021754635   -0.008346094
        # 2          6           0.018984731    0.032948887   -0.038003451
        # 3          1          -0.002133484   -0.006226040    0.023174772
        # 4          1          -0.004316502   -0.004968213    0.023174772
        #           -2          -0.001830728   -0.000743108   -0.000196625
        # ------------------------------------------------------------------
        #
        # The "-2" line is for a dummy atom
        #
        # Then optimization is done in internal coordinates, Gaussian also
        # print the forces in internal coordinates, which can be produced from
        # the above. This block looks like this:
        # Variable       Old X    -DE/DX   Delta X   Delta X   Delta X     New X
        #                                 (Linear)    (Quad)   (Total)
        #   ch        2.05980   0.01260   0.00000   0.01134   0.01134   2.07114
        #   hch        1.75406   0.09547   0.00000   0.24861   0.24861   2.00267
        #   hchh       2.09614   0.01261   0.00000   0.16875   0.16875   2.26489
        #         Item               Value     Threshold  Converged?
        if line[37:43] == "Forces":

            if not hasattr(self, "grads"):
                self.grads = []

            self.skip_lines(inputfile, ['header', 'd'])

            forces = []
            line = next(inputfile)
            while list(set(line.strip())) != ['-']:
                tmpforces = []
                for N in range(3):  # Fx, Fy, Fz
                    force = line[23+N*15:38+N*15]
                    if force.startswith("*"):
                        force = "NaN"
                    tmpforces.append(float(force))
                forces.append(tmpforces)
                line = next(inputfile)
            self.grads.append(forces)

        #Extract PES scan data
        #Summary of the potential surface scan:
        #  N       A          SCF
        #----  ---------  -----------
        #   1   109.0000    -76.43373
        #   2   119.0000    -76.43011
        #   3   129.0000    -76.42311
        #   4   139.0000    -76.41398
        #   5   149.0000    -76.40420
        #   6   159.0000    -76.39541
        #   7   169.0000    -76.38916
        #   8   179.0000    -76.38664
        #   9   189.0000    -76.38833
        #  10   199.0000    -76.39391
        #  11   209.0000    -76.40231
        #----  ---------  -----------
        if "Summary of the potential surface scan:" in line:

            scanenergies = []
            scanparm = []
            colmnames = next(inputfile)
            hyphens = next(inputfile)
            line = next(inputfile)
            while line != hyphens:
                broken = line.split()
                scanenergies.append(float(broken[-1]))
                scanparm.append(map(float, broken[1:-1]))
                line = next(inputfile)
            if not hasattr(self, "scanenergies"):
                self.scanenergies = []
                self.scanenergies = scanenergies
            if not hasattr(self, "scanparm"):
                self.scanparm = []
                self.scanparm = scanparm
            if not hasattr(self, "scannames"):
                self.scannames = colmnames.split()[1:-1]

        # Orbital symmetries.
        if line[1:20] == 'Orbital symmetries:' and not hasattr(self, "mosyms"):

            # For counterpoise fragments, skip these lines.
            if self.counterpoise != 0:
                return

            self.updateprogress(inputfile, "MO Symmetries", self.fupdate)

            self.mosyms = [[]]
            line = next(inputfile)
            unres = False
            if line.find("Alpha Orbitals") == 1:
                unres = True
                line = next(inputfile)
            i = 0
            while len(line) > 18 and line[17] == '(':
                if line.find('Virtual') >= 0:
                    self.homos = numpy.array([i-1], "i")  # 'HOMO' indexes the HOMO in the arrays
                parts = line[17:].split()
                for x in parts:
                    self.mosyms[0].append(self.normalisesym(x.strip('()')))
                    i += 1
                line = next(inputfile)
            if unres:
                line = next(inputfile)
                # Repeat with beta orbital information
                i = 0
                self.mosyms.append([])
                while len(line) > 18 and line[17] == '(':
                    if line.find('Virtual') >= 0:
                        # Here we consider beta
                        # If there was also an alpha virtual orbital,
                        #  we will store two indices in the array
                        # Otherwise there is no alpha virtual orbital,
                        #  only beta virtual orbitals, and we initialize
                        #  the array with one element. See the regression
                        #  QVGXLLKOCUKJST-UHFFFAOYAJmult3Fixed.out
                        #  donated by Gregory Magoon (gmagoon).
                        if (hasattr(self, "homos")):
                            # Extend the array to two elements
                            # 'HOMO' indexes the HOMO in the arrays
                            self.homos.resize([2])
                            self.homos[1] = i-1
                        else:
                            # 'HOMO' indexes the HOMO in the arrays
                            self.homos = numpy.array([i-1], "i")
                    parts = line[17:].split()
                    for x in parts:
                        self.mosyms[1].append(self.normalisesym(x.strip('()')))
                        i += 1
                    line = next(inputfile)

            # Some calculations won't explicitely print the number of basis sets used,
            # and will occasionally drop some without warning. We can infer the number,
            # however, from the MO symmetries printed here. Specifically, this fixes
            # regression Gaussian/Gaussian09/dvb_sp_terse.log (#23 on github).
            self.set_attribute('nmo', len(self.mosyms[-1]))

        # Alpha/Beta electron eigenvalues.
        if line[1:6] == "Alpha" and line.find("eigenvalues") >= 0:

            # For counterpoise fragments, skip these lines.
            if self.counterpoise != 0:
                return

            # For ONIOM calcs, ignore this section in order to bypass assertion failure.
            if self.oniom:
                return

            self.updateprogress(inputfile, "Eigenvalues", self.fupdate)
            self.moenergies = [[]]
            HOMO = -2

            while line.find('Alpha') == 1:
                if line.split()[1] == "virt." and HOMO == -2:

                    # If there aren't any symmetries, this is a good way to find the HOMO.
                    HOMO = len(self.moenergies[0])-1
                    self.homos = numpy.array([HOMO], "i")

                # Convert to floats and append to moenergies, but sometimes Gaussian
                #  doesn't print correctly so test for ValueError (bug 1756789).
                part = line[28:]
                i = 0
                while i*10+4 < len(part):
                    s = part[i*10:(i+1)*10]
                    try:
                        x = self.float(s)
                    except ValueError:
                        x = numpy.nan
                    self.moenergies[0].append(utils.convertor(x, "hartree", "eV"))
                    i += 1
                line = next(inputfile)

            # If, at this point, self.homos is unset, then there were not
            # any alpha virtual orbitals
            if not hasattr(self, "homos"):
                HOMO = len(self.moenergies[0])-1
                self.homos = numpy.array([HOMO], "i")

            if line.find('Beta') == 2:
                self.moenergies.append([])

            HOMO = -2
            while line.find('Beta') == 2:
                if line.split()[1] == "virt." and HOMO == -2:

                    # If there aren't any symmetries, this is a good way to find the HOMO.
                    # Also, check for consistency if homos was already parsed.
                    HOMO = len(self.moenergies[1])-1
                    self.homos.resize([2])
                    self.homos[1] = HOMO

                part = line[28:]
                i = 0
                while i*10+4 < len(part):
                    x = part[i*10:(i+1)*10]
                    self.moenergies[1].append(utils.convertor(self.float(x), "hartree", "eV"))
                    i += 1
                line = next(inputfile)

            self.moenergies = [numpy.array(x, "d") for x in self.moenergies]

        # Start of the IR/Raman frequency section.
        # Caution is advised here, as additional frequency blocks
        #   can be printed by Gaussian (with slightly different formats),
        #   often doubling the information printed.
        # See, for a non-standard exmaple, regression Gaussian98/test_H2.log
        # If either the Gaussian freq=hpmodes keyword or IOP(7/33=1) is used,
        # an extra frequency block with higher-precision vibdisps is
        # printed before the normal frequency block.
        # Note that the code parses only the vibsyms and vibdisps
        # from the high-precision block, but parses vibsyms, vibfreqs,
        # vibramans and vibirs from the normal block. vibsyms parsed
        # from the high-precision block are discarded and replaced by those
        # from the normal block while the high-precision vibdisps, if present,
        # are used to overwrite default-precision vibdisps at the end of the parse.
        if line[1:14] == "Harmonic freq":  # This matches in both freq block types

            self.updateprogress(inputfile, "Frequency Information", self.fupdate)

            # The whole block should not have any blank lines.
            while line.strip() != "":

                # The line with indices
                if line[1:15].strip() == "" and line[15:60].split()[0].isdigit():
                    freqbase = int(line[15:60].split()[0])
                    if freqbase == 1 and hasattr(self, 'vibsyms'):
                        # we are coming accross duplicated information.
                        # We might be be parsing a default-precision block having
                        # already parsed (only) vibsyms and displacements from
                        # the high-precision block, or might be encountering
                        # a second low-precision block (see e.g. 25DMF_HRANH.log
                        # regression).
                        self.vibsyms = []
                        if hasattr(self, "vibirs"):
                            self.vibirs = []
                        if hasattr(self, 'vibfreqs'):
                            self.vibfreqs = []
                        if hasattr(self, 'vibramans'):
                            self.vibramans = []
                        if hasattr(self, 'vibdisps'):
                            self.vibdisps = []

                # Lines with symmetries and symm. indices begin with whitespace.
                if line[1:15].strip() == "" and not line[15:60].split()[0].isdigit():

                    if not hasattr(self, 'vibsyms'):
                        self.vibsyms = []
                    syms = line.split()
                    self.vibsyms.extend(syms)

                if line[1:15] == "Frequencies --":  # note: matches low-precision block, and

                    if not hasattr(self, 'vibfreqs'):
                        self.vibfreqs = []

                    freqs = [self.float(f) for f in line[15:].split()]
                    self.vibfreqs.extend(freqs)

                if line[1:15] == "IR Inten    --":  # note: matches only low-precision block

                    if not hasattr(self, 'vibirs'):
                        self.vibirs = []

                    irs = []
                    for ir in line[15:].split():
                        try:
                            irs.append(self.float(ir))
                        except ValueError:
                            irs.append(self.float('nan'))
                    self.vibirs.extend(irs)

                if line[1:15] == "Raman Activ --":  # note: matches only low-precision block

                    if not hasattr(self, 'vibramans'):
                        self.vibramans = []

                    ramans = []
                    for raman in line[15:].split():
                        try:
                            ramans.append(self.float(raman))
                        except ValueError:
                            ramans.append(self.float('nan'))

                    self.vibramans.extend(ramans)

                # Block with (default-precision) displacements should start with this.
                #                     1                      2                      3
                #                     A                      A                      A
                # Frequencies --   370.7936               370.7987               618.0103
                # Red. masses --     2.3022                 2.3023                 1.9355
                # Frc consts  --     0.1865                 0.1865                 0.4355
                # IR Inten    --     0.0000                 0.0000                 0.0000
                #  Atom  AN      X      Y      Z        X      Y      Z        X      Y      Z
                #     1   6     0.00   0.00  -0.04     0.00   0.00   0.19     0.00   0.00   0.12
                #     2   6     0.00   0.00   0.19     0.00   0.00  -0.06     0.00   0.00  -0.12

                if line.strip().split()[0:3] == ["Atom", "AN", "X"]:
                    if not hasattr(self, 'vibdisps'):
                        self.vibdisps = []
                    disps = []
                    for n in range(self.natom):
                        line = next(inputfile)
                        numbers = [float(s) for s in line[10:].split()]
                        N = len(numbers) // 3
                        if not disps:
                            for n in range(N):
                                disps.append([])
                        for n in range(N):
                            disps[n].append(numbers[3*n:3*n+3])
                    self.vibdisps.extend(disps)

                # Block with high-precision (freq=hpmodes) displacements should start with this.
                #                           1         2         3         4         5
                #                           A         A         A         A         A
                #       Frequencies ---   370.7936  370.7987  618.0103  647.7864  647.7895
                #    Reduced masses ---     2.3022    2.3023    1.9355    6.4600    6.4600
                #   Force constants ---     0.1865    0.1865    0.4355    1.5971    1.5972
                #    IR Intensities ---     0.0000    0.0000    0.0000    0.0000    0.0000
                # Coord Atom Element:
                #   1     1     6          0.00000   0.00000   0.00000  -0.18677   0.05592
                #   2     1     6          0.00000   0.00000   0.00000   0.28440   0.21550
                #   3     1     6         -0.04497   0.19296   0.11859   0.00000   0.00000
                #   1     2     6          0.00000   0.00000   0.00000   0.03243   0.37351
                #   2     2     6          0.00000   0.00000   0.00000   0.14503  -0.06117
                #   3     2     6          0.18959  -0.05753  -0.11859   0.00000   0.00000
                if line.strip().split()[0:3] == ["Coord", "Atom", "Element:"]:
                    # Wait until very end of parsing to assign vibdispshp to self.vibdisps
                    # as otherwise the higher precision displacements will be overwritten
                    # by low precision displacements which are printed further down file
                    if not hasattr(self, 'vibdispshp'):
                        self.vibdispshp = []

                    disps = []
                    for n in range(3*self.natom):
                        line = next(inputfile)
                        numbers = [float(s) for s in line[16:].split()]
                        atomindex = int(line[4:10])-1  # atom index, starting at zero
                        numbermodes = len(numbers)

                        if not disps:
                            for mode in range(numbermodes):
                                # For each mode, make list of list [atom][coord_index]
                                disps.append([[] for x in range(0, self.natom)])
                        for mode in range(numbermodes):
                            disps[mode][atomindex].append(numbers[mode])
                    self.vibdispshp.extend(disps)

                line = next(inputfile)

        # Electronic transitions.
        if line[1:14] == "Excited State":

            if not hasattr(self, "etenergies"):
                self.etenergies = []
                self.etoscs = []
                self.etsyms = []
                self.etsecs = []

            # Need to deal with lines like:
            # (restricted calc)
            # Excited State   1:   Singlet-BU     5.3351 eV  232.39 nm  f=0.1695
            # (unrestricted calc) (first excited state is 2!)
            # Excited State   2:   ?Spin  -A      0.1222 eV 10148.75 nm  f=0.0000
            # (Gaussian 09 ZINDO)
            # Excited State   1:      Singlet-?Sym    2.5938 eV  478.01 nm  f=0.0000  <S**2>=0.000
            p = re.compile(":(?P<sym>.*?)(?P<energy>-?\d*\.\d*) eV")
            groups = p.search(line).groups()
            self.etenergies.append(utils.convertor(self.float(groups[1]), "eV", "cm-1"))
            self.etoscs.append(self.float(line.split("f=")[-1].split()[0]))
            self.etsyms.append(groups[0].strip())

            line = next(inputfile)

            p = re.compile("(\d+)")
            CIScontrib = []
            while line.find(" ->") >= 0:  # This is a contribution to the transition
                parts = line.split("->")
                self.logger.debug(parts)
                # Has to deal with lines like:
                #       32 -> 38         0.04990
                #      35A -> 45A        0.01921
                frommoindex = 0  # For restricted or alpha unrestricted
                fromMO = parts[0].strip()
                if fromMO[-1] == "B":
                    frommoindex = 1  # For beta unrestricted
                fromMO = int(p.match(fromMO).group())-1  # subtract 1 so that it is an index into moenergies

                t = parts[1].split()
                tomoindex = 0
                toMO = t[0]
                if toMO[-1] == "B":
                    tomoindex = 1
                toMO = int(p.match(toMO).group())-1  # subtract 1 so that it is an index into moenergies

                percent = self.float(t[1])
                # For restricted calculations, the percentage will be corrected
                # after parsing (see after_parsing() above).
                CIScontrib.append([(fromMO, frommoindex), (toMO, tomoindex), percent])
                line = next(inputfile)
            self.etsecs.append(CIScontrib)

        # Circular dichroism data (different for G03 vs G09)
        #
        # G03
        #
        # ## <0|r|b> * <b|rxdel|0>  (Au), Rotatory Strengths (R) in
        # ## cgs (10**-40 erg-esu-cm/Gauss)
        # ##       state          X           Y           Z     R(length)
        # ##         1         0.0006      0.0096     -0.0082     -0.4568
        # ##         2         0.0251     -0.0025      0.0002     -5.3846
        # ##         3         0.0168      0.4204     -0.3707    -15.6580
        # ##         4         0.0721      0.9196     -0.9775     -3.3553
        #
        # G09
        #
        # ## 1/2[<0|r|b>*<b|rxdel|0> + (<0|rxdel|b>*<b|r|0>)*]
        # ## Rotatory Strengths (R) in cgs (10**-40 erg-esu-cm/Gauss)
        # ##       state          XX          YY          ZZ     R(length)     R(au)
        # ##         1        -0.3893     -6.7546      5.7736     -0.4568     -0.0010
        # ##         2       -17.7437      1.7335     -0.1435     -5.3845     -0.0114
        # ##         3       -11.8655   -297.2604    262.1519    -15.6580     -0.0332
        if line[1:52] == "<0|r|b> * <b|rxdel|0>  (Au), Rotatory Strengths (R)" or \
           line[1:50] == "1/2[<0|r|b>*<b|rxdel|0> + (<0|rxdel|b>*<b|r|0>)*]":

            self.etrotats = []

            self.skip_lines(inputfile, ['units'])

            headers = next(inputfile)
            Ncolms = len(headers.split())
            line = next(inputfile)
            parts = line.strip().split()
            while len(parts) == Ncolms:
                try:
                    R = self.float(parts[4])
                except ValueError:
                    # nan or -nan if there is no first excited state
                    # (for unrestricted calculations)
                    pass
                else:
                    self.etrotats.append(R)
                line = next(inputfile)
                temp = line.strip().split()
                parts = line.strip().split()
            self.etrotats = numpy.array(self.etrotats, "d")

        # Number of basis sets functions.
        # Has to deal with lines like:
        #  NBasis =   434 NAE=    97 NBE=    97 NFC=    34 NFV=     0
        # and...
        #  NBasis = 148  MinDer = 0  MaxDer = 0
        # Although the former is in every file, it doesn't occur before
        #   the overlap matrix is printed.
        if line[1:7] == "NBasis" or line[4:10] == "NBasis":

            # For counterpoise fragment, skip these lines.
            if self.counterpoise != 0:
                return

            # For ONIOM calcs, ignore this section in order to bypass assertion failure.
            if self.oniom:
                return

            # If nbasis was already parsed, check if it changed. If it did, issue a warning.
            # In the future, we will probably want to have nbasis, as well as nmo below,
            # as a list so that we don't need to pick one value when it changes.
            nbasis = int(line.split('=')[1].split()[0])
            if hasattr(self, "nbasis"):
                try:
                    assert nbasis == self.nbasis
                except AssertionError:
                    self.logger.warning("Number of basis functions (nbasis) has changed from %i to %i" % (self.nbasis, nbasis))
            self.nbasis = nbasis

        # Number of linearly-independent basis sets.
        if line[1:7] == "NBsUse":

            # For counterpoise fragment, skip these lines.
            if self.counterpoise != 0:
                return

            # For ONIOM calcs, ignore this section in order to bypass assertion failure.
            if self.oniom:
                return

            nmo = int(line.split('=')[1].split()[0])
            self.set_attribute('nmo', nmo)

        # For AM1 calculations, set nbasis by a second method,
        #   as nmo may not always be explicitly stated.
        if line[7:22] == "basis functions, ":

            nbasis = int(line.split()[0])
            self.set_attribute('nbasis', nbasis)

        # Molecular orbital overlap matrix.
        # Has to deal with lines such as:
        #   *** Overlap ***
        #   ****** Overlap ******
        # Note that Gaussian sometimes drops basis functions,
        #  causing the overlap matrix as parsed below to not be
        #  symmetric (which is a problem for population analyses, etc.)
        if line[1:4] == "***" and (line[5:12] == "Overlap" or line[8:15] == "Overlap"):

            # Ensure that this is the main calc and not a fragment
            if self.counterpoise != 0:
                return

            self.aooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")
            # Overlap integrals for basis fn#1 are in aooverlaps[0]
            base = 0
            colmNames = next(inputfile)
            while base < self.nbasis:

                self.updateprogress(inputfile, "Overlap", self.fupdate)

                for i in range(self.nbasis-base):  # Fewer lines this time
                    line = next(inputfile)
                    parts = line.split()
                    for j in range(len(parts)-1):  # Some lines are longer than others
                        k = float(parts[j+1].replace("D", "E"))
                        self.aooverlaps[base+j, i+base] = k
                        self.aooverlaps[i+base, base+j] = k
                base += 5
                colmNames = next(inputfile)
            self.aooverlaps = numpy.array(self.aooverlaps, "d")

        # Molecular orbital coefficients (mocoeffs).
        # Essentially only produced for SCF calculations.
        # This is also the place where aonames and atombasis are parsed.
        if line[5:35] == "Molecular Orbital Coefficients" or line[5:41] == "Alpha Molecular Orbital Coefficients" or line[5:40] == "Beta Molecular Orbital Coefficients":

            # If counterpoise fragment, return without parsing orbital info
            if self.counterpoise != 0:
                return
            # Skip this for ONIOM calcs
            if self.oniom:
                return

            if line[5:40] == "Beta Molecular Orbital Coefficients":
                beta = True
                if self.popregular:
                    return
                    # This was continue before refactoring the parsers.
                    #continue # Not going to extract mocoeffs
                # Need to add an extra array to self.mocoeffs
                self.mocoeffs.append(numpy.zeros((self.nmo, self.nbasis), "d"))
            else:
                beta = False
                self.aonames = []
                self.atombasis = []
                mocoeffs = [numpy.zeros((self.nmo, self.nbasis), "d")]

            base = 0
            self.popregular = False
            for base in range(0, self.nmo, 5):

                self.updateprogress(inputfile, "Coefficients", self.fupdate)

                colmNames = next(inputfile)

                if not colmNames.split():
                    self.logger.warning("Molecular coefficients header found but no coefficients.")
                    break

                if base == 0 and int(colmNames.split()[0]) != 1:
                    # Implies that this is a POP=REGULAR calculation
                    # and so, only aonames (not mocoeffs) will be extracted
                    self.popregular = True
                symmetries = next(inputfile)
                eigenvalues = next(inputfile)
                for i in range(self.nbasis):

                    line = next(inputfile)
                    if i == 0:
                        # Find location of the start of the basis function name
                        start_of_basis_fn_name = line.find(line.split()[3]) - 1
                    if base == 0 and not beta:  # Just do this the first time 'round
                        parts = line[:start_of_basis_fn_name].split()
                        if len(parts) > 1:  # New atom
                            if i > 0:
                                self.atombasis.append(atombasis)
                            atombasis = []
                            atomname = "%s%s" % (parts[2], parts[1])
                        orbital = line[start_of_basis_fn_name:20].strip()
                        self.aonames.append("%s_%s" % (atomname, orbital))
                        atombasis.append(i)

                    part = line[21:].replace("D", "E").rstrip()
                    temp = []
                    for j in range(0, len(part), 10):
                        temp.append(float(part[j:j+10]))
                    if beta:
                        self.mocoeffs[1][base:base + len(part) / 10, i] = temp
                    else:
                        mocoeffs[0][base:base + len(part) / 10, i] = temp

                if base == 0 and not beta:  # Do the last update of atombasis
                    self.atombasis.append(atombasis)
                if self.popregular:
                    # We now have aonames, so no need to continue
                    break
            if not self.popregular and not beta:
                self.mocoeffs = mocoeffs

        # Natural orbital coefficients (nocoeffs) and occupation numbers (nooccnos),
        # which are respectively define the eigenvectors and eigenvalues of the
        # diagnolized one-electron density matrix. These orbitals are formed after
        # configuration interact (CI) calculations, but not only. Similarly to mocoeffs,
        # we can parse and check aonames and atombasis here.
        #
        #     Natural Orbital Coefficients:
        #                           1         2         3         4         5
        #     Eigenvalues --     2.01580   2.00363   2.00000   2.00000   1.00000
        #   1 1   O  1S          0.00000  -0.15731  -0.28062   0.97330   0.00000
        #   2        2S          0.00000   0.75440   0.57746   0.07245   0.00000
        # ...
        #
        if line[5:33] == "Natural Orbital Coefficients":

            self.aonames = []
            self.atombasis = []
            nocoeffs = numpy.zeros((self.nmo, self.nbasis), "d")
            nooccnos = []

            base = 0
            self.popregular = False
            for base in range(0, self.nmo, 5):

                self.updateprogress(inputfile, "Natural orbitals", self.fupdate)

                colmNames = next(inputfile)
                if base == 0 and int(colmNames.split()[0]) != 1:
                    # Implies that this is a POP=REGULAR calculation
                    # and so, only aonames (not mocoeffs) will be extracted
                    self.popregular = True

                eigenvalues = next(inputfile)
                nooccnos.extend(map(float, eigenvalues.split()[2:]))

                for i in range(self.nbasis):

                    line = next(inputfile)

                    # Just do this the first time 'round.
                    if base == 0:

                        # Changed below from :12 to :11 to deal with Elmar Neumann's example.
                        parts = line[:11].split()
                        # New atom.
                        if len(parts) > 1:
                            if i > 0:
                                self.atombasis.append(atombasis)
                            atombasis = []
                            atomname = "%s%s" % (parts[2], parts[1])
                        orbital = line[11:20].strip()
                        self.aonames.append("%s_%s" % (atomname, orbital))
                        atombasis.append(i)

                    part = line[21:].replace("D", "E").rstrip()
                    temp = []

                    for j in range(0, len(part), 10):
                        temp.append(float(part[j:j+10]))

                    nocoeffs[base:base + len(part) / 10, i] = temp

                # Do the last update of atombasis.
                if base == 0:
                    self.atombasis.append(atombasis)

                # We now have aonames, so no need to continue.
                if self.popregular:
                    break

            if not self.popregular:
                self.nocoeffs = nocoeffs
                self.nooccnos = nooccnos

        # For FREQ=Anharm, extract anharmonicity constants
        if line[1:40] == "X matrix of Anharmonic Constants (cm-1)":
            Nvibs = len(self.vibfreqs)
            self.vibanharms = numpy.zeros((Nvibs, Nvibs), "d")

            base = 0
            colmNames = next(inputfile)
            while base < Nvibs:

                for i in range(Nvibs-base):  # Fewer lines this time
                    line = next(inputfile)
                    parts = line.split()
                    for j in range(len(parts)-1):  # Some lines are longer than others
                        k = float(parts[j+1].replace("D", "E"))
                        self.vibanharms[base+j, i+base] = k
                        self.vibanharms[i+base, base+j] = k
                base += 5
                colmNames = next(inputfile)

        # Pseudopotential charges.
        if line.find("Pseudopotential Parameters") > -1:

            self.skip_lines(inputfile, ['e', 'label1', 'label2', 'e'])

            line = next(inputfile)
            if line.find("Centers:") < 0:
                return
                # This was continue before parser refactoring.
                # continue

# Needs to handle code like the following:
#
#  Center     Atomic      Valence      Angular      Power                                                       Coordinates
#  Number     Number     Electrons     Momentum     of R      Exponent        Coefficient                X           Y           Z
# ===================================================================================================================================
# Centers:   1
# Centers:  16
# Centers:  21 24
# Centers:  99100101102
#    1         44           16                                                                      -4.012684 -0.696698  0.006750
#                                      F and up
#                                                     0      554.3796303       -0.05152700

            centers = []
            while line.find("Centers:") >= 0:
                temp = line[10:]
                for i in range(0, len(temp)-3, 3):
                    centers.append(int(temp[i:i+3]))
                line = next(inputfile)
            centers.sort()  # Not always in increasing order

            self.coreelectrons = numpy.zeros(self.natom, "i")

            for center in centers:
                front = line[:10].strip()
                while not (front and int(front) == center):
                    line = next(inputfile)
                    front = line[:10].strip()
                info = line.split()
                self.coreelectrons[center-1] = int(info[1]) - int(info[2])
                line = next(inputfile)

        # This will be printed for counterpoise calcualtions only.
        # To prevent crashing, we need to know which fragment is being considered.
        # Other information is also printed in lines that start like this.
        if line[1:14] == 'Counterpoise:':

            if line[42:50] == "fragment":
                self.counterpoise = int(line[51:54])

        # This will be printed only during ONIOM calcs; use it to set a flag
        # that will allow assertion failures to be bypassed in the code.
        if line[1:7] == "ONIOM:":
            self.oniom = True

        # Atomic charges are straightforward to parse, although the header
        # has changed over time somewhat.
        #
        # Mulliken charges:
        #                1
        #     1  C   -0.004513
        #     2  C   -0.077156
        # ...
        # Sum of Mulliken charges =   0.00000
        # Mulliken charges with hydrogens summed into heavy atoms:
        #               1
        #     1  C   -0.004513
        #     2  C    0.002063
        # ...
        #
        if line[1:25] == "Mulliken atomic charges:" or line[1:18] == "Mulliken charges:" or \
           line[1:23] == "Lowdin Atomic Charges:" or line[1:16] == "Lowdin charges:":

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}

            ones = next(inputfile)

            charges = []
            nline = next(inputfile)
            while not "Sum of" in nline:
                charges.append(float(nline.split()[2]))
                nline = next(inputfile)

            if "Mulliken" in line:
                self.atomcharges["mulliken"] = charges
            else:
                self.atomcharges["lowdin"] = charges

        if line.strip() == "Natural Population":
            if not hasattr(self, 'atomcharges'):
                self.atomcharges = {}
            line1 = next(inputfile)
            line2 = next(inputfile)
            if line1.split()[0] == 'Natural' and line2.split()[2] == 'Charge':
                dashes = next(inputfile)
                charges = []
                for i in range(self.natom):
                    nline = next(inputfile)
                    charges.append(float(nline.split()[2]))
                self.atomcharges["natural"] = charges

        #Extract Thermochemistry
        #Temperature   298.150 Kelvin.  Pressure   1.00000 Atm.
        #Zero-point correction=                           0.342233 (Hartree/
        #Thermal correction to Energy=                    0.
        #Thermal correction to Enthalpy=                  0.
        #Thermal correction to Gibbs Free Energy=         0.302940
        #Sum of electronic and zero-point Energies=           -563.649744
        #Sum of electronic and thermal Energies=              -563.636699
        #Sum of electronic and thermal Enthalpies=            -563.635755
        #Sum of electronic and thermal Free Energies=         -563.689037
        if "Sum of electronic and thermal Enthalpies" in line:
            self.set_attribute('enthalpy', float(line.split()[6]))
        if "Sum of electronic and thermal Free Energies=" in line:
            self.set_attribute('freenergy', float(line.split()[7]))
        if line[1:12] == "Temperature":
            self.set_attribute('temperature', float(line.split()[1]))


if __name__ == "__main__":
    import doctest, gaussianparser, sys

    if len(sys.argv) == 1:
        doctest.testmod(gaussianparser, verbose=False)

    if len(sys.argv) >= 2:
        parser = gaussianparser.Gaussian(sys.argv[1])
        data = parser.parse()

    if len(sys.argv) > 2:
        for i in range(len(sys.argv[2:])):
            if hasattr(data, sys.argv[2 + i]):
                print(getattr(data, sys.argv[2 + i]))
