from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class TimingProfile:
    start_hour: int = 8
    end_hour: int = 18
    weekend_multiplier: float = 0.25
    night_multiplier: float = 0.05

    def multiplier(self, dt: datetime) -> float:
        """
        Return a value in (0, 1] representing how likely an event is to
        occur at the given time relative to peak business-hours activity.

        Used for rejection-sampling in the noise generators so the volume
        of background events follows a realistic diurnal pattern.
        """
        is_weekend = dt.weekday() >= 5
        base = self.weekend_multiplier if is_weekend else 1.0
        if self.start_hour <= dt.hour < self.end_hour:
            return base
        return base * self.night_multiplier


def iso_z(dt: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC string ending in 'Z'."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# NOTE: poisson_next was defined here in a previous version as a placeholder
# for a Poisson-process noise model.  Noise generation currently uses uniform
# random sampling (see noise.py), so the function has been removed to avoid
# misleading future contributors into thinking a Poisson model is active.
