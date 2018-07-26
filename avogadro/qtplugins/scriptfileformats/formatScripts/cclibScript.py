"""
/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

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

from cclib.io.ccio import ccopen
from cclib.io.cjsonwriter import CJSON


def getMetaData():
    metaData = {}
    metaData['inputFormat'] = 'cjson'
    metaData['outputFormat'] = 'cjson'
    metaData['operations'] = ['read']
    metaData['identifier'] = 'CJSON writer'
    metaData['name'] = 'CJSON'
    metaData['description'] = "The cclib script provided by the cclib repository is used to " +\
                              "write the CJSON format using the input file provided " +\
                              "to Avogadro2."
    metaData['fileExtensions'] = ['out', 'log', 'adfout', 'g09']
    metaData['mimeTypes'] = ['']
    return metaData


def read():
    # Pass the standard input to ccopen:
    log = ccopen(sys.stdin)
    ccdata = log.parse()

    output_obj = CJSON(ccdata, terse=True)
    output = output_obj.generate_repr()

    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser('Read files using cclib')
    parser.add_argument('--metadata', action='store_true')
    parser.add_argument('--read', action='store_true')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--display-name', action='store_true')
    parser.add_argument('--lang', nargs='?', default='en')
    args = vars(parser.parse_args())

    if args['metadata']:
        print(json.dumps(getMetaData()))
    elif args['display_name']:
        print(getMetaData()['name'])
    elif args['read']:
        print(read())
    elif args['write']:
        pass
