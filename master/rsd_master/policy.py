# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : master/rsd_master/policy.py
# Purpose : Uptime-limit policy: warn, then shut a machine down when its uptime exceeds the limit
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Parental-control policy engine.

Each machine has an effective uptime limit:

* ``inherit``   - the global ``default_limit_minutes`` setting (0 = unlimited);
* ``custom``    - its own ``limit_minutes``;
* ``unlimited`` - the "infinite override": never shut down by the policy.

Every ``interval`` seconds, for each UP agent with a limit, the engine computes the uptime
(now - boot time reported by the agent):

* ``warning_minutes`` before the limit, a popup warns the user (once per boot);
* at the limit, a ``SHUTDOWN`` with ``shutdown_delay_seconds`` of countdown is sent (once per
  boot; re-sent if the machine is still up two minutes after the countdown ended).

A reboot resets the uptime, which is the documented semantics of an *uptime* limit.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional

from .db import Database
from .hub import AgentHub

log = logging.getLogger(__name__)

RESEND_GRACE = 120


@dataclass
class _BootState:
    """What the policy already did for one boot of one machine."""

    boot_time: float
    warned: bool = False
    shutdown_sent_at: Optional[float] = None


def effective_limit(agent: Dict, default_minutes: int) -> int:
    """Return the effective uptime limit of an agent in minutes (0 = unlimited).

    Args:
        agent: Agent row (``limit_mode``, ``limit_minutes``).
        default_minutes: Global default limit.
    """
    mode = agent.get("limit_mode", "inherit")
    if mode == "unlimited":
        return 0
    if mode == "custom":
        return max(0, int(agent.get("limit_minutes") or 0))
    return max(0, int(default_minutes))


class PolicyEngine:
    """Periodic enforcement of the uptime limits."""

    def __init__(self, db: Database, hub: AgentHub) -> None:
        """Bind the engine to the database and the hub.

        Args:
            db: Database (agents and settings).
            hub: Agent hub used to send the messages.
        """
        self.db = db
        self.hub = hub
        self._state: Dict[str, _BootState] = {}

    async def tick(self, now: Optional[float] = None) -> None:
        """Run one evaluation round.

        Args:
            now: Current time (injectable for the tests).
        """
        now = time.time() if now is None else now
        settings = self.db.get_settings()
        for agent in self.db.list_agents():
            agent_id = agent["id"]
            boot = agent.get("boot_time")
            limit = effective_limit(agent, settings["default_limit_minutes"])
            if not limit or not boot or not self.hub.is_up(agent_id):
                continue
            state = self._state.get(agent_id)
            # A boot time that moved by more than a minute means the machine rebooted.
            if state is None or abs(state.boot_time - boot) > 60:
                state = self._state[agent_id] = _BootState(boot_time=boot)
            uptime_min = (now - boot) / 60
            warning = settings["warning_minutes"]
            if not state.warned and warning > 0 and limit - warning <= uptime_min < limit:
                remaining = max(1, round(limit - uptime_min))
                # "key"/"params" let the agent render the text in the language of the computer;
                # "text" is the English fallback for older agents.
                if await self.hub.send(agent_id, {
                    "type": "MESSAGE", "title": "Remote Shutdown", "key": "policy.warning",
                    "params": {"minutes": remaining},
                    "text": f"This computer will shut down in {remaining} minute(s) (uptime limit reached).",
                }):
                    state.warned = True
            if uptime_min >= limit:
                delay = settings["shutdown_delay_seconds"]
                due = state.shutdown_sent_at is None or now - state.shutdown_sent_at > delay + RESEND_GRACE
                if due and await self.hub.send(agent_id, {
                    "type": "SHUTDOWN", "delay": delay, "force": False,
                    "key": "policy.shutdown", "params": {"seconds": delay},
                    "message": f"Uptime limit reached: shutdown in {delay} seconds.",
                }):
                    state.shutdown_sent_at = now
                    self.db.audit("policy", "agent.shutdown", agent_id,
                                  {"reason": "uptime_limit", "limit_minutes": limit,
                                   "uptime_minutes": round(uptime_min)})
                    log.info("uptime limit reached, shutdown sent", extra={"agent": agent_id, "limit": limit})

    async def run(self, interval: float = 15.0) -> None:
        """Evaluate the policy forever.

        Args:
            interval: Period in seconds.
        """
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - the loop must survive a transient error
                log.exception("policy round failed")
            await asyncio.sleep(interval)
