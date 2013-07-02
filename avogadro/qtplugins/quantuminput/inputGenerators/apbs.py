@QUANTUMINPUT_PYTHON2_SHEBANG@

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

  userOptions['Input File'] = {}
  userOptions['Input File']['type'] = 'string'
  userOptions['Input File']['default'] = ''

  userOptions['Calculation'] = {}
  userOptions['Calculation']['type'] = 'string'
  userOptions['Calculation']['default'] = 'mg-auto'

  opts = {'userOptions' : userOptions}
  opts['allowCustomBaseName'] = True

  return opts

def generateInputFile(opts, settings):
  # Extract options:
  input_file = opts['Input File']
  calculation = opts['Calculation']

  output = ''

  output += 'read\n'
  output += '   mol pqr %s\n'%input_file
  output += 'end\n\n'

  output += 'elec\n'
  output += '    %s\n'%calculation
  output += '    dime 97 97 97\n'
  output += '    chgm spl0\n'
  output += '    fglen 150 115 160\n'
  output += '    cglen 156 121 162\n'
  output += '    cgcent mol 1\n'
  output += '    fgcent mol 1\n'
  output += '    mol 1\n'
  output += '    npbe\n'
  output += '    bcfl sdh\n'
  output += '    ion 1 0.150 2.0\n'
  output += '    ion -1 0.150 2.0\n'
  output += '    pdie 2.0\n'
  output += '    sdie 78.54\n'
  output += '    srfm mol\n'
  output += '    srad 1.4\n'
  output += '    sdens 10.0\n'
  output += '    temp 298.15\n'
  output += '    calcenergy total\n'
  output += '    calcforce no\n'
  output += '    write pot dx pot\n' # write potential output
  output += 'end\n\n'

  output += 'quit\n'

  return output

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['options'], opts['settings'])

  # Prepare the result
  result = {}
  # Input file text -- will appear in the same order in the GUI as they are
  # listed in the array:
  files = []
  files.append({'filename': 'apbs.in', 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = 'apbs.in'
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate an APBS input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print("APBS")
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
