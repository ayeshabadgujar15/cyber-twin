"""Summarize explicitly supplied place observations without inferring live GPS."""
import math
from datetime import datetime, timezone
from pydantic import BaseModel, Field, HttpUrl, field_validator


class PlaceObservation(BaseModel):
    latitude: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitude: float = Field(ge=-180, le=180, allow_inf_nan=False)
    source: str = Field(min_length=1, max_length=100)
    source_url: HttpUrl
    observed_at: datetime
    kind: str = Field(default='public_place', pattern=r'^(public_place|user_provided)$')

    @field_validator('observed_at')
    @classmethod
    def dated(cls, value):
        if value.tzinfo is None or value > datetime.now(timezone.utc):
            raise ValueError('Use a past date with an explicit timezone.')
        return value

    @field_validator('source_url')
    @classmethod
    def public_url(cls, value):
        if value.username or value.password or len(str(value)) > 2048:
            raise ValueError('Use a source URL without embedded credentials, up to 2048 characters.')
        return value


class LocationAnalysisRequest(BaseModel):
    observations: list[PlaceObservation] = Field(min_length=1, max_length=500)


def summarize_places(observations):
    # Repeated posts from one place should not overweight that place.
    places = {(round(p.latitude, 6), round(p.longitude, 6)) for p in observations}
    vectors = [(math.cos(math.radians(lat)) * math.cos(math.radians(lon)),
                math.cos(math.radians(lat)) * math.sin(math.radians(lon)),
                math.sin(math.radians(lat))) for lat, lon in sorted(places)]
    x, y, z = (sum(v[i] for v in vectors) / len(vectors) for i in range(3))
    note = 'Center and maximum great-circle distance of unique supplied places. Place coordinates describe those places, not the person’s GPS. No ownership, home, or current-location inference; no confidence percentage.'
    if math.sqrt(x*x + y*y + z*z) < 1e-8:
        center, spread = None, None
        note += ' Opposing observations have no meaningful center.'
    else:
        lat = math.degrees(math.atan2(z, math.hypot(x, y)))
        lon = math.degrees(math.atan2(y, x))
        center = {'latitude': lat, 'longitude': lon}
        def distance(point):
            a, b = map(math.radians, point)
            c, d = math.radians(lat), math.radians(lon)
            hav = math.sin((a-c)/2)**2 + math.cos(a)*math.cos(c)*math.sin((b-d)/2)**2
            return 6371.0088 * 2 * math.asin(math.sqrt(min(1, max(0, hav))))
        spread = max(distance(p) for p in places)
    return {'center': center, 'maximum_spread_km': spread, 'unique_places': len(places),
            'observation_count': len(observations), 'observations': observations,
            'earliest_observation': min(p.observed_at for p in observations),
            'latest_observation': max(p.observed_at for p in observations),
            'note': note, 'live_location': False}
