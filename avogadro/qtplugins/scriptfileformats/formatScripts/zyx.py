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


def getMetaData():
    metaData = {}
    metaData['inputFormat'] = 'xyz'
    metaData['outputFormat'] = 'xyz'
    metaData['operations'] = ['read', 'write']
    metaData['identifier'] = 'ZYX Example Format'
    metaData['name'] = 'ZYX'
    metaData['description'] = "Mostly useless file format that reads xyz-style " +\
                              "files with reversed coordinates. Demonstrates " +\
                              "the implementation of a user-scripted file format."
    metaData['fileExtensions'] = ['zyx']
    metaData['mimeTypes'] = ['chemical/x-zyx']
    return metaData


def write():
    result = ""

    # Just copy the first two lines: numAtoms and comment/title
    result += sys.stdin.readline()
    result += sys.stdin.readline()

    for line in sys.stdin:
        words = line.split()
        result += '%-3s %9.5f %9.5f %9.5f' %\
            (words[0], float(words[3]), float(words[2]), float(words[1]))
        if len(words) > 4:
            result += words[4:].join(' ')
        result += '\n'

    return result


def read():
    result = ""

    # Just copy the first two lines: numAtoms and comment/title
    result += sys.stdin.readline()
    result += sys.stdin.readline()

    for line in sys.stdin:
        words = line.split()
        result += '%-3s %9.5f %9.5f %9.5f' %\
            (words[0], float(words[3]), float(words[2]), float(words[1]))
        if len(words) > 4:
            result += words[4:].join(' ')
        result += '\n'

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser('Example file format script.')
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
        print(write())
