"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""
import json


def report_progress(message=None, value=None, maximum=None):
    """
    Report the progress of a running command script to Avogadro.

    Avogadro shows a progress dialog while a command script runs. Calling this
    function updates that dialog: pass a `message` to change the status text,
    and/or `value` and `maximum` to turn the spinner into a determinate
    progress bar.

    The update is written to standard output as a single line of JSON, which
    Avogadro removes from the script's output before parsing the result, so it
    will not interfere with the JSON the script prints when it finishes.

    Example:

        for i, conformer in enumerate(conformers, start=1):
            report_progress(f"Conformer {i} of {len(conformers)}",
                            i, len(conformers))
            optimize(conformer)

    :param message: status text to display, e.g. "Current energy: -135.2 eV"
    :param value: the current step of a determinate progress bar
    :param maximum: the total number of steps of a determinate progress bar
    """
    payload = {}
    if message is not None:
        payload["message"] = message
    if value is not None:
        payload["value"] = value
    if maximum is not None:
        payload["maximum"] = maximum

    # flush is required: Python block-buffers stdout when it is a pipe rather
    # than a terminal, so without it these updates would only arrive at exit.
    print(json.dumps({"avogadro": payload}), flush=True)
