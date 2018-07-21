"""
/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
"""

import argparse
import json
import sys

# Some globals:
targetName = 'LAMMPS'
mainExtension = 'lmp'
dataExtension = 'lmpdat'
debug = False


def getOptions():
    userOptions = {}

    userOptions['Title'] = {}
    userOptions['Title']['type'] = 'string'
    userOptions['Title']['default'] = ''

    userOptions['Atom Style'] = {}
    userOptions['Atom Style']['type'] = 'stringList'
    userOptions['Atom Style']['default'] = 2
    userOptions['Atom Style']['values'] = \
        ['angle', 'atomic', 'bond', 'charge', 'dipole', 'electron',
         'ellipsoid', 'full', 'line', 'meso', 'molecular', 'peri',
         'sphere', 'tri', 'wavepacket', 'full']

    userOptions['Units'] = {}
    userOptions['Units']['type'] = 'stringList'
    userOptions['Units']['default'] = 1
    userOptions['Units']['values'] = \
        ['lj', 'real', 'metal', 'si', 'cgs', 'u_electron']

    userOptions['Filename Base'] = {}
    userOptions['Filename Base']['type'] = 'string'
    userOptions['Filename Base']['default'] = 'job'

    userOptions['Ensemble'] = {}
    userOptions['Ensemble']['type'] = 'stringList'
    userOptions['Ensemble']['default'] = 0
    userOptions['Ensemble']['values'] = \
        ['NVE', 'NVT']

    userOptions['Temperature'] = {}
    userOptions['Temperature']['type'] = 'float'
    userOptions['Temperature']['default'] = 298.15
    userOptions['Temperature']['minimum'] = 0.0
    userOptions['Temperature']['maximum'] = 10000.0
    userOptions['Temperature']['precision'] = 2
    userOptions['Temperature']['suffix'] = ' K'

    userOptions['XBoundaryType'] = {}
    userOptions['XBoundaryType']['type'] = 'stringList'
    userOptions['XBoundaryType']['default'] = 0
    userOptions['XBoundaryType']['values'] = \
        ['p', 'f', 's', 'm', 'fs', 'fm']

    userOptions['YBoundaryType'] = {}
    userOptions['YBoundaryType']['type'] = 'stringList'
    userOptions['YBoundaryType']['default'] = 0
    userOptions['YBoundaryType']['values'] = \
        ['p', 'f', 's', 'm', 'fs', 'fm']

    userOptions['ZBoundaryType'] = {}
    userOptions['ZBoundaryType']['type'] = 'stringList'
    userOptions['ZBoundaryType']['default'] = 0
    userOptions['ZBoundaryType']['values'] = \
        ['p', 'f', 's', 'm', 'fs', 'fm']

    userOptions['XReplicate'] = {}
    userOptions['XReplicate']['type'] = 'integer'
    userOptions['XReplicate']['default'] = 1
    userOptions['XReplicate']['minimum'] = 1
    userOptions['XReplicate']['maximum'] = 100000

    userOptions['YReplicate'] = {}
    userOptions['YReplicate']['type'] = 'integer'
    userOptions['YReplicate']['default'] = 1
    userOptions['YReplicate']['minimum'] = 1
    userOptions['YReplicate']['maximum'] = 100000

    userOptions['ZReplicate'] = {}
    userOptions['ZReplicate']['type'] = 'integer'
    userOptions['ZReplicate']['default'] = 1
    userOptions['ZReplicate']['minimum'] = 1
    userOptions['ZReplicate']['maximum'] = 100000

    userOptions['Zero Linear Momentum'] = {}
    userOptions['Zero Linear Momentum']['type'] = 'boolean'
    userOptions['Zero Linear Momentum']['default'] = False

    userOptions['Zero Angular Momentum'] = {}
    userOptions['Zero Angular Momentum']['type'] = 'boolean'
    userOptions['Zero Angular Momentum']['default'] = False

    userOptions['Dimensions'] = {}
    userOptions['Dimensions']['type'] = 'stringList'
    userOptions['Dimensions']['default'] = 1
    userOptions['Dimensions']['values'] = \
        ['2D', '3D']

    userOptions['Time Step'] = {}
    userOptions['Time Step']['type'] = 'float'
    userOptions['Time Step']['default'] = 0.001
    userOptions['Time Step']['minimum'] = 0.001
    userOptions['Time Step']['maximum'] = 10000.000
    userOptions['Time Step']['precision'] = 3

    userOptions['Total Steps'] = {}
    userOptions['Total Steps']['type'] = 'integer'
    userOptions['Total Steps']['default'] = 1000
    userOptions['Total Steps']['minimum'] = 1
    userOptions['Total Steps']['maximum'] = 1000000

    userOptions['Dump Interval'] = {}
    userOptions['Dump Interval']['type'] = 'integer'
    userOptions['Dump Interval']['default'] = 10
    userOptions['Dump Interval']['minimum'] = 1
    userOptions['Dump Interval']['maximum'] = 1000000

    userOptions['Velocity Distribution'] = {}
    userOptions['Velocity Distribution']['type'] = 'stringList'
    userOptions['Velocity Distribution']['default'] = 0
    userOptions['Velocity Distribution']['values'] = \
        ['gaussian', 'uniform']

    opts = {'userOptions': userOptions}

    return opts


def generateInputFile(opts):
    # Extract options:
    title = opts['Title']
    unitType = opts['Units']
    dimensionType = opts['Dimensions'][0]
    xBoundaryType = opts['XBoundaryType']
    yBoundaryType = opts['YBoundaryType']
    zBoundaryType = opts['ZBoundaryType']
    atomStyle = opts['Atom Style']

    xReplicate = opts['XReplicate']
    yReplicate = opts['YReplicate']
    zReplicate = opts['ZReplicate']
    zeroLinearMomentum = opts['Zero Linear Momentum']
    zeroAngularMomentum = opts['Zero Angular Momentum']
    basis = opts['Dimensions']
    velocityDist = opts['Velocity Distribution']
    ensemble = opts['Ensemble']
    timeStep = opts['Time Step']
    dumpStep = opts['Dump Interval']
    runSteps = opts['Total Steps']

    baseName = opts['Filename Base']
    temperatureStart = opts['Temperature']
    velocityTemp = 298.15

    # Create input file
    output = ''

    output += "# LAMMPS Input file generated by Avogadro\n"
    output += "# " + title + "\n\n"

    output += "# Intialization\n";
    output += "units          " + unitType + "\n"
    output += "dimension      " + dimensionType + "\n"
    output += "boundary       " + xBoundaryType + " " + yBoundaryType + " " + zBoundaryType + "\n"
    output += "atom_style     " + atomStyle + "\n"
    output += "\n"

    output += "# Atom Definition\n"
    output += "read_data      " + baseName + ".lmpdat\n"
    output += "replicate      " + str(xReplicate) + " " + str(yReplicate) + " " + str(zReplicate) + "\n\n"

    # output += "\n" + getWaterPotential(waterPotential) + "\n"

    getYesNo = lambda x: "yes" if x else "no"

    output += "# Settings\n"
    output += "velocity       all create " + str(velocityTemp) + " 4928459 " + "rot " +\
              getYesNo(zeroLinearMomentum) + " " + "mom " + getYesNo(zeroAngularMomentum) +\
              " " + "dist " + velocityDist + "\n"
    if(ensemble == 'NVT'):
        output += "fix            ensemble all nvt temp " + str(temperatureStart) + " " +\
                  str(temperatureStart) + " 100 " + "\n"
    elif(ensemble == 'NVE'):
        output += "fix            ensemble all nve\n"
    output += "timestep       " + str(timeStep) + "\n"
    output += "\n";

    output += "# Output\n"
    output += "dump           dumpXYZ all xyz " + str(dumpStep) + " " + baseName + "_output.xyz" + "\n"
    output += "\n"

    output += "# Run the simulation\n"
    output += "run            " + str(runSteps) + "\n"
    output += "\n"

    return output


def generateInput():
    # Read options from stdin
    stdinStr = sys.stdin.read()

    # Parse the JSON strings
    opts = json.loads(stdinStr)

    # Generate the input file
    inp = generateInputFile(opts['options'])

    # Basename for input files:
    baseName = opts['options']['Filename Base']

    # Prepare the result
    result = {}
    # Input file text -- will appear in the same order in the GUI as they are
    # listed in the array:
    files = []
    files.append({'filename': '%s.%s' % (
        baseName, mainExtension), 'contents': inp})
    # files.append({'filename': '%s.lmpdat' % baseName, 'contents': inp[1]})
    if debug:
        files.append({'filename': 'debug_info', 'contents': stdinStr})
    result['files'] = files
    # Specify the main input file. This will be used by MoleQueue to determine
    # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
    result['mainFile'] = '%s.%s' % (baseName, mainExtension)
    result['dataFile'] = '%s.%s' % (baseName, dataExtension)
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Generate a %s input file.' % targetName)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--print-options', action='store_true')
    parser.add_argument('--generate-input', action='store_true')
    parser.add_argument('--display-name', action='store_true')
    args = vars(parser.parse_args())

    debug = args['debug']

    if args['display_name']:
        print(targetName)
    if args['print_options']:
        print(json.dumps(getOptions()))
    elif args['generate_input']:
        print(json.dumps(generateInput()))
