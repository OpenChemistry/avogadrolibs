"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""

import json
import os
import socket
import struct
import sys
import tempfile


class connect:
    """
    Send JSON-RPC requests to Avogadro through a named pipe.

    This class is intended to be used by external scripts that are
    run on the same machine as Avogadro.

    The named pipe is created by Avogadro and is named "avogadro".
    If it does not exist, Avogadro is not running.
    """

    def __init__(self, name="avogadro"):
        """
        Connect to the local named pipe

        :param name: The name of the named pipe.
        """
        # create socket and connect
        try:
            if os.name == "nt":
                self.sock = open("//./pipe/" + name, "w+b", 0)
            else:
                self.sock.connect(tempfile.gettempdir() + "/" + name)
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        except Exception as exception:
            print("error while connecting: " + str(exception))
            print("Is Avogadro running?")

    def __json(self, method, params={}):
        """
        Send a JSON-RPC request to the named pipe.
        :param method: The JSON-RPC request method.
        Send a message to the named pipe
        :param file: file corresponding to method.

        """
        if method == "receive_message":
            size = 1024
            if os.name == "nt":
                packet = self.sock.read(size)
            else:
                packet = self.sock.recv(size)

            try:
                return json.loads(str(packet[4:]))
            except Exception as exception:
                print("error: " + str(exception))
                return {}
        else:
            msg = {
                "jsonrpc": "2.0",
                "id": 0,
                "method": method,
                "params": params,
            }
            json_msg = json.dumps(msg)
            size = len(json_msg)
            header = struct.pack(">I", size)
            packet = header + json_msg.encode("ascii")
            if os.name == "nt":
                self.sock.write(packet)
                self.sock.seek(0)
            else:
                self.sock.send(packet)

    def open_file(self, file):
        """Opens file"""
        # param: file is filename input by the user in string
        method = "openFile"
        params = {"filename": file}
        self.__json(method, params)
        self.__json("receive_message")

    def save_graphic(self, file):
        """Save Graphic"""
        method = "saveGraphic"
        params = {"filename": file}
        self.__json(method, params)
        self.__json("receive_message")

    def close(self):
        """Close the socket to the named pipe"""
        self.sock.close()
