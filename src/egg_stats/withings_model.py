"""Models of Withings data."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Activity:
    steps: int
    distance: float
    elevation: float
    soft: float
    moderate: float
    intense: float
    active: float
    calories: float
    totalcalories: float
    hr_average: int
    hr_min: int
    hr_max: int
    hr_zone_0: int
    hr_zone_1: int
    hr_zone_3: int
    deviceid: None
    hash_deviceid: None
    timezone: str
    date: str
    modified: int
    brand: int
    is_tracker: bool
