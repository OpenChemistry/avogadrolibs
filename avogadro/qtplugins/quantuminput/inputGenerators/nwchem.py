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

def basisGuiToInput(gui):
  if gui == '3-21 G':
    return "3-21G"
  elif gui == '6-31 G(d)':
    return "6-31G*"
  elif gui == '6-31 G(d,p)':
    return "6-31G**"
  elif gui == '6-31+ G(d)':
    return "6-31+G*"
  elif gui == '6-311 G(d)':
    return "6-311G*"
  elif gui == 'LANL2DZ':
    return "LANL2DZ ECP"
  else:
    return gui

def getOptions():
  userOptions = {}

  userOptions['Title'] = {}
  userOptions['Title']['type'] = 'string'
  userOptions['Title']['default'] = ''

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['type'] = "stringList"
  userOptions['Calculation Type']['default'] = 1
  userOptions['Calculation Type']['values'] = []
  userOptions['Calculation Type']['values'].append('Single Point')
  userOptions['Calculation Type']['values'].append('Equilibrium Geometry')
  userOptions['Calculation Type']['values'].append('Frequencies')

  userOptions['Theory'] = {}
  userOptions['Theory']['type'] = "stringList"
  userOptions['Theory']['default'] = 1
  userOptions['Theory']['values'] = []
  userOptions['Theory']['values'].append('RHF')
  userOptions['Theory']['values'].append('B3LYP')
  userOptions['Theory']['values'].append('MP2')
  userOptions['Theory']['values'].append('CCSD')

  userOptions['Basis'] = {}
  userOptions['Basis']['type'] = "stringList"
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = []
  userOptions['Basis']['values'].append('STO-3G')
  userOptions['Basis']['values'].append('3-21 G')
  userOptions['Basis']['values'].append('6-31 G(d)')
  userOptions['Basis']['values'].append('6-31 G(d,p)')
  userOptions['Basis']['values'].append('6-31+ G(d)')
  userOptions['Basis']['values'].append('6-311 G(d)')
  userOptions['Basis']['values'].append('cc-pVDZ')
  userOptions['Basis']['values'].append('cc-pVTZ')
  userOptions['Basis']['values'].append('LANL2DZ')

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

  # highlighting options
  defaultRules = []

  # literal numbers
  numberRule = {
    "patterns": [
      { "regexp": "\\b[-+.0-9]+\\b" }
    ],
    "format": {
      "foreground": [ 255, 0, 255 ]
    }
  }

  defaultRules.append(numberRule)

  # Title highlighting
  titleRule = {
    "patterns": [
      { "wildcard": "title \"*\"" }
    ],
    "format": {
      "foreground": [ 0, 0, 0 ],
      "attributes": [ "bold" ],
      "family": "serif"
    }
  }

  defaultRules.append(titleRule)

  # Basis sets
  basisPatterns = []
  for basis in userOptions['Basis']['values']:
    basisPatterns.append( { "string": basisGuiToInput(basis) } )

  basisFormat = {
    "foreground": [ 25, 25, 220 ],
    "attributes": [ "bold" ],
    "family": [ "mono" ]
  }

  basisRule = {
    "patterns": basisPatterns,
    "format": basisFormat
  }

  defaultRules.append(basisRule)

  # Top level directives
  topLevelDirectives = [
  "start", "restart", "scratch_dir", "permanent_dir", "memory", "echo", "title",
  "print", "noprint", "set", "unset", "stop", "task", "ecce_print"]

  # These aren't top-level directives according to the manual, but
  # for now just stick them in that ruleset.
  topLevelDirectives.extend(["charge", "geometry", "basis", "spherical",
  "library", "end", "xc", "mult", "freeze atomic"])

  tldPatterns = []
  for tld in topLevelDirectives:
    tldPatterns.append( { "regexp": "\\b%s\\b"%tld } )

  tldRule = {
    "patterns": tldPatterns,
    "format": {
      "foreground": [80, 220, 80],
      "attributes": ["bold"],
      "family": "sans"
    }
  }

  defaultRules.append(tldRule)

  # Tasks
  tasks = ["energy", "optimize", "freq"]
  taskPatterns = []
  for task in tasks:
    taskPatterns.append( { "regexp": "\\b%s\\b"%task } )

  taskRule = {
    "patterns": taskPatterns,
    "format": {
      "foreground": [225, 128, 128],
      "background": [255, 220, 220],
      "attributes": ["bold", "italic"],
      "family": "mono"
    }
  }

  defaultRules.append(taskRule)

  # QM keywords
  qm = ["scf", "dft", "b3lyp", "mp2", "ccsd"]
  qmPatterns = []
  for word in qm:
    qmPatterns.append( { "regexp": "\\b%s\\b"%word } )

  qmRule = {
    "patterns": qmPatterns,
    "format": {
      "foreground": [63, 128, 255],
      "attributes": ["bold", "italic"],
      "family": "mono"
    }
  }

  defaultRules.append(qmRule)

  # Assemble default style:
  defaultStyle = {}
  defaultStyle["style"] = "default"
  defaultStyle["rules"] = defaultRules

  highlightStyles = [ defaultStyle ]

  opts = {}
  opts['userOptions'] = userOptions
  opts['highlightStyles'] = highlightStyles
  opts['allowCustomBaseName'] = True

  return opts

def generateInputFile(opts):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  basis = opts['Basis']
  multiplicity = opts['Multiplicity']
  charge = opts['Charge']

  # Preamble
  nwfile = ""
  nwfile += "echo\n\n"
  nwfile += "start molecule\n\n"
  nwfile += "title \"%s\"\n"%title

  # Charge
  nwfile += "charge %d\n\n"%charge

  # Coordinates
  nwfile += "geometry units angstroms print xyz autosym\n"
  nwfile += "$$coords:Sxyz$$\n"
  nwfile += "end\n\n"

  # Basis
  nwfile += "basis"
  if basis == "cc-pVDZ" or basis == "cc-pVTZ":
    nwfile += " spherical"
  nwfile += "\n"
  nwfile += "  * library "
  nwfile += basisGuiToInput(basis)
  nwfile += "\n"
  nwfile += "end\n\n"

  # Theory
  task = ""
  if theory == "RHF":
    task = "scf"
  elif theory == "B3LYP":
    task = "dft"
    nwfile += "dft\n"
    nwfile += "  xc b3lyp\n"
    nwfile += "  mult %d\n"%multiplicity
    nwfile += "end\n\n"
  elif theory == "MP2":
    task = "mp2"
    nwfile += "mp2\n"
    nwfile += "  # Exclude core electrons from MP2 treatment:\n"
    nwfile += "  freeze atomic\n"
    nwfile += "end\n\n"
  elif theory == "CCSD":
    task = "ccsd"
    nwfile += "ccsd\n"
    nwfile += "  # Exclude core electrons from MP2 treatment:\n"
    nwfile += "  freeze atomic\n"
    nwfile += "end\n\n"
  else:
    raise Exception("Invalid Theory: %s"%theory)

  # Task
  nwfile += "task %s "%task
  if calculate == 'Single Point':
    nwfile += "energy"
  elif calculate == 'Equilibrium Geometry':
    nwfile += "optimize"
  elif calculate == 'Frequencies':
    nwfile += "freq"
  else:
    raise Exception("Invalid calculation type: %s"%calculate)
  nwfile += "\n"

  return nwfile

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['options'])

  # Basename for input files:
  baseName = opts['settings']['baseName']

  # Prepare the result
  result = {}
  # Input file text -- will appear in the same order in the GUI as they are
  # listed in the array:
  files = []
  files.append({'filename': '%s.nw'%baseName,
                'contents': inp,
                'highlightStyles': [ 'default' ]})

  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = '%s.nw'%baseName
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a NWChem input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print("NWChem")
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
