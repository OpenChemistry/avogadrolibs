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
warnings = []

def getOptions():
  userOptions = {}

  userOptions['Title'] = {}
  userOptions['Title']['type'] = 'string'
  userOptions['Title']['default'] = ''

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['type'] = "stringList"
  userOptions['Calculation Type']['default'] = 1
  userOptions['Calculation Type']['values'] = \
    ['Single Point', 'Equilibrium Geometry', 'Frequencies']

  userOptions['Theory'] = {}
  userOptions['Theory']['type'] = "stringList"
  userOptions['Theory']['default'] = 3
  userOptions['Theory']['values'] = \
    ['AM1', 'PM3', 'RHF', 'B3LYP', 'MP2', 'CCSD']

  userOptions['Basis'] = {}
  userOptions['Basis']['type'] = "stringList"
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = \
    ['STO-3G', '3-21 G', '6-31 G(d)', '6-31 G(d,p)', 'LANL2DZ']

  userOptions['Filename Base'] = {}
  userOptions['Filename Base']['type'] = 'string'
  userOptions['Filename Base']['default'] = 'job'

  userOptions['Processor Cores'] = {}
  userOptions['Processor Cores']['type'] = 'integer'
  userOptions['Processor Cores']['default'] = 1
  userOptions['Processor Cores']['minimum'] = 1

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

  userOptions['Output Format'] = {}
  userOptions['Output Format']['type'] = "stringList"
  userOptions['Output Format']['default'] = 0
  userOptions['Output Format']['values'] = ['Standard', 'Molden', 'Molekel']

  userOptions['Write Checkpoint File'] = {}
  userOptions['Write Checkpoint File']['type'] = "boolean"
  userOptions['Write Checkpoint File']['default'] = True

  # TODO Coordinate format (need zmatrix)

  opts = {'userOptions' : userOptions}

  return opts

def generateInputFile(opts):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  basis = opts['Basis']
  multiplicity = opts['Multiplicity']
  charge = opts['Charge']
  outputFormat = opts['Output Format']
  checkpoint = opts['Write Checkpoint File']
  nCores = int(opts['Processor Cores'])

  output = ''

  # Number of cores
  if nCores > 1:
    output += "%%NProcShared=%d\n"%nCores

  # Checkpoint
  if checkpoint:
    output += '%Chk=checkpoint.chk\n'

  # Theory/Basis
  if theory == 'AM1' or theory == 'PM3':
    output += '#n %s'%(theory)
    warnings.append('Ignoring basis set for semi-empirical calculation.')
  else:
    output += '#n %s/%s'%(theory, basis.replace(' ', ''))

  # Calculation type
  if calculate == 'Single Point':
    output += ' SP'
  elif calculate == 'Equilibrium Geometry':
    output += ' Opt'
  elif calculate == 'Frequencies':
    output += ' Opt Freq'
  else:
    raise Exception('Invalid calculation type: %s'%calculate)

  # Output format
  if outputFormat == 'Standard':
    pass
  elif outputFormat == 'Molden':
    output += ' gfprint pop=full'
  elif outputFormat == 'Molekel':
    output += ' gfoldprint pop=full'
  else:
    raise Exception('Invalid output format: %s'%outputFormat)

  # Title
  output += '\n\n %s\n\n'%title

  # Charge/Multiplicity
  output += "%d %d\n"%(charge, multiplicity)

  # Coordinates
  output += '$$coords:Sxyz$$\n'

  # The gaussian code is irritatingly fickle -- it *will* silently crash if
  # this extra, otherwise unnecessary newline is not present at the end of the
  # file.
  output += '\n'

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
  files.append({'filename': '%s.com'%baseName, 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = '%s.com'%baseName

  if len(warnings) > 0:
    result['warnings'] = warnings

  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a Gaussian input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print("Gaussian")
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
