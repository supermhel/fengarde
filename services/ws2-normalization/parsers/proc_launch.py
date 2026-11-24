"""Shared heuristic for process-launch events (Sysmon 1, Windows 4688): did a document/PDF host spawn a
shell or script host? A HEURISTIC over process names, not a classifier -- see contracts/rules/win_office_spawns_shell.yml."""
from __future__ import annotations

from typing import Optional

#: Lower-cased executable basenames. Parent = apps that open untrusted documents; child = shells / script hosts / LOLBins.
_PARENTS = frozenset((
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
    "acrord32.exe", "acrobat.exe", "foxitreader.exe",
))
_CHILDREN = frozenset((
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
))


def _base(path) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def launch_info(parent_image, image, command_line: Optional[str] = None) -> dict:
    """``{"parent", "image", "suspicious"}``; ``suspicious`` is True for a document host spawning a shell/script host.

    Also carries two lower-cased match keys for the process-creation rules (the rule engine compares case-sensitively and
    Windows command lines are not): ``image_base`` (executable basename, e.g. ``powershell.exe``) and ``command_line_lc``
    (the same text as ``command_line``, lower-cased). Each is present only when its source value is."""
    parent, child = _base(parent_image), _base(image)
    info: dict = {"suspicious": parent in _PARENTS and child in _CHILDREN}
    if parent_image:
        info["parent"] = str(parent_image)[:260]
    if image:
        info["image"] = str(image)[:260]
        if child:
            info["image_base"] = child
    if command_line:
        info["command_line"] = str(command_line)[:1000]
        info["command_line_lc"] = info["command_line"].lower()
    return info
