"""Separate immutable source checkouts from explicitly selected private projects."""
from __future__ import annotations
import json
import os
from pathlib import Path

ENV='A7CR_PROJECT_ROOT'
SCHEMA='a7cr-agent-project/1'


def source_root():return Path(__file__).resolve().parents[1]


def runtime_root(default=None):
    selected=os.environ.get(ENV)
    if not selected:return Path(default or source_root()).resolve()
    raw=Path(selected)
    if not raw.is_absolute() or raw.is_symlink():raise ValueError('Project root must be an explicit absolute directory')
    root=raw.resolve();manifest=root/'project.json'
    data=json.loads(manifest.read_text())
    if (data.get('schema')!=SCHEMA or data.get('model')!='ILCE-7CR' or data.get('firmware')!='2.01'
            or data.get('preset')!='fujifilm-portrait' or manifest.is_symlink()):
        raise ValueError('Unsupported local project manifest')
    return root
