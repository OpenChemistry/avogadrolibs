"""
/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

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
debug = False


def getOptions():
    userOptions = {}

    userOptions['Test StringList'] = {}
    userOptions['Test StringList']['type'] = 'stringList'
    userOptions['Test StringList']['default'] = 0
    userOptions['Test StringList']['values'] = \
        ['Option 1', 'Option 2', 'Option 3']

    userOptions['Test String'] = {}
    userOptions['Test String']['type'] = 'string'
    userOptions['Test String']['default'] = 'default value'

    userOptions['Test Integer'] = {}
    userOptions['Test Integer']['type'] = 'integer'
    userOptions['Test Integer']['default'] = 5
    userOptions['Test Integer']['minimium'] = 0
    userOptions['Test Integer']['maximum'] = 10
    userOptions['Test Integer']['prefix'] = 'Throw '
    userOptions['Test Integer']['suffix'] = ' warnings'

    userOptions['Test Boolean'] = {}
    userOptions['Test Boolean']['type'] = 'boolean'
    userOptions['Test Boolean']['default'] = False

    userOptions['Test FilePath'] = {}
    userOptions['Test FilePath']['type'] = 'filePath'
    userOptions['Test FilePath']['default'] = ''

    # special parameters -- these should be moved to the top of the widget
    userOptions['Title'] = {}
    userOptions['Title']['type'] = 'string'
    userOptions['Title']['default'] = ''

    userOptions['Filename Base'] = {}
    userOptions['Filename Base']['type'] = 'string'
    userOptions['Filename Base']['default'] = 'job'

    userOptions['Processor Cores'] = {}
    userOptions['Processor Cores']['type'] = 'integer'
    userOptions['Processor Cores']['default'] = 4

    userOptions['Calculation Type'] = {}
    userOptions['Calculation Type']['type'] = "stringList"
    userOptions['Calculation Type']['default'] = 1
    userOptions['Calculation Type']['values'] = \
        ['Single Point',  'Equilibrium Geometry', 'Frequencies']

    userOptions['Theory'] = {}
    userOptions['Theory']['type'] = "stringList"
    userOptions['Theory']['default'] = 1
    userOptions['Theory']['values'] = ['RHF', 'B3LYP', 'MP2', 'CCSD']

    userOptions['Basis'] = {}
    userOptions['Basis']['type'] = "stringList"
    userOptions['Basis']['default'] = 2
    userOptions['Basis']['values'] = \
        ['STO-3G', '3-21 G', '6-31 G(d)', '6-31 G(d,p)', '6-31+ G(d)',
         '6-311 G(d)', 'cc-pVDZ', 'cc-pVTZ', 'LANL2DZ']

    userOptions['Multiplicity'] = {}
    userOptions['Multiplicity']['type'] = "integer"
    userOptions['Multiplicity']['default'] = 1
    userOptions['Multiplicity']['minimum'] = 1
    userOptions['Multiplicity']['maximum'] = 5

    userOptions['Charge'] = {}
    userOptions['Charge']['type'] = "integer"
    userOptions['Charge']['default'] = 0
    userOptions['Charge']['minimum'] = -9
    userOptions['Charge']['maximum'] = 9

    opts = {}
    opts['userOptions'] = userOptions

    return opts


def generateInputFile(opts):
    output = ''
    for key in opts:
        output += '%s: %s\n' % (key, opts[key])

    output += '\n\nCurrent molecule:\n$$coords:SZx1y1z0N$$\n'

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

    # Test for warnings:
    numWarnings = opts['options']['Test Integer']

    # Test filePath:
    filePath = opts['options']['Test FilePath']

    # Prepare the result
    result = {}
    # Input file text -- will appear in the same order in the GUI as they are
    # listed in the array:
    files = []
    files.append({'filename': '%s.opts' % baseName,
                  'contents': inp})
    files.append({'filename': '%s.testFilePath' % baseName,
                  'filePath': filePath})

    if debug:
        files.append({'filename': 'debug_info', 'contents': stdinStr})

    result['files'] = files

    # Specify the main input file. This will be used by MoleQueue to determine
    # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
    result['mainFile'] = '%s.opts' % baseName

    result['warnings'] = []
    for i in range(numWarnings):
        result['warnings'].append('Warning number %d...' % (i + 1))

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Generate a NWChem input file.')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--print-options', action='store_true')
    parser.add_argument('--generate-input', action='store_true')
    parser.add_argument('--display-name', action='store_true')
    parser.add_argument('--lang', nargs='?', default='en')
    args = vars(parser.parse_args())

    debug = args['debug']

    if args['display_name']:
        print("Input Generator Test")
    if args['print_options']:
        print(json.dumps(getOptions()))
    elif args['generate_input']:
        print(json.dumps(generateInput()))
