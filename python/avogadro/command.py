"""
/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-clause BSD License, (the "License").
******************************************************************************/
"""
import json
import os

# Set by Avogadro when it is reading standard output for progress reports.
PROGRESS_ENVIRONMENT_VARIABLE = "AVO_PROGRESS_PROTOCOL"


def progress_supported():
    """
    Report whether the running version of Avogadro understands progress
    updates.

    Avogadro 2.0.0 and earlier read the whole of a script's standard output as
    a single JSON document, so progress lines would make that parse fail and
    the command would report an error instead of its result. Those versions do
    not set the environment variable, and report_progress() stays silent.
    """
    return bool(os.environ.get(PROGRESS_ENVIRONMENT_VARIABLE))


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

    This is a no-op on versions of Avogadro that do not support progress
    reporting, so it is always safe to call: a script that uses it still runs
    correctly on Avogadro 2.0.0, just without the progress bar.

    Example:

        for i, conformer in enumerate(conformers, start=1):
            report_progress(f"Conformer {i} of {len(conformers)}",
                            i, len(conformers))
            optimize(conformer)

    :param message: status text to display, e.g. "Current energy: -135.2 eV"
    :param value: the current step of a determinate progress bar
    :param maximum: the total number of steps of a determinate progress bar
    """
    # Checked on every call rather than at import, so that a script which is
    # imported before Avogadro's environment is in place still works.
    if not progress_supported():
        return

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
