#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods

from typing import List, Optional, Dict

from datetime import datetime

from .hash import uSwidHash, uSwidHashAlg
from .problem import uSwidProblem, _is_redacted


class uSwidEvidence:
    """Represents some SWID Evidence"""

    def __init__(
        self,
        date: Optional[datetime] = None,
        device_id: Optional[str] = None,
    ):
        """Initializes uSwidEvidence"""
        self.date: Optional[datetime] = date
        """Date and time when this evidence was collected """
        self.device_id: Optional[str] = device_id
        """Device ID, typically a machine hostname"""
        self._hashes: Dict[uSwidHashAlg, uSwidHash] = {}

    def add_hash(self, ihash: uSwidHash) -> None:
        """Adds a measured hash, deduplicating by algorithm ID"""
        self._hashes[ihash.alg_id or uSwidHashAlg.UNKNOWN] = ihash

    def remove_hash(self, alg_id: uSwidHashAlg) -> None:
        """Removes a measured hash by algorithm ID"""
        self._hashes.pop(alg_id)

    @property
    def hashes(self) -> List[uSwidHash]:
        """Returns all the measured hashes"""
        return list(self._hashes.values())

    def problems(self) -> List[uSwidProblem]:
        """Checks the payload for common problems"""

        problems: List[uSwidProblem] = []
        if not self.date:
            problems += [uSwidProblem("evidence", "No date", since="0.4.7")]
        if not self.device_id:
            problems += [uSwidProblem("evidence", "No device_id", since="0.4.7")]
        elif _is_redacted(self.device_id):
            problems += [uSwidProblem("evidence", "Redacted device_id", since="0.4.8")]
        return problems

    def __repr__(self) -> str:
        tmp = f'uSwidEvidence(date="{self.date}",device_id={self.device_id})'
        for ihash in self.hashes:
            tmp += f"\n - {ihash}"
        return tmp
