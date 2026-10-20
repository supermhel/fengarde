"""Shared heuristic for process-launch events (Sysmon 1, Windows 4688): did a document/browser host spawn a
shell or script host? A HEURISTIC over process names, not a classifier -- see win_process_launch_office_child.yml."""
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
    """``{"parent", "image", "suspicious"}``; ``suspicious`` is True for a document host spawning a shell/script host."""
    parent, child = _base(parent_image), _base(image)
    info = {"suspicious": parent in _PARENTS and child in _CHILDREN}
    if parent_image:
        info["parent"] = str(parent_image)[:260]
    if image:
        info["image"] = str(image)[:260]
    if command_line:
        info["command_line"] = str(command_line)[:1000]
    return info
