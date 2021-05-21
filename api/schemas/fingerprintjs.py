
from typing import Dict, Optional, Any
from pydantic import BaseModel, validator


FingerprintGenericFields = Dict[str, Any]


class FingerprintJSData(BaseModel):
    components: FingerprintGenericFields
    visitorId: str
    version: str


class GeoLocation(BaseModel):
    lat: float
    lon: float
    accuracy: float


class FingerprintJSGeoLocation(BaseModel):
    visitorId: str
    geoLocation: Optional[GeoLocation]
    geoError: Optional[str]

    # @validator('geoLocation')
    def check_data_or_error(cls, v, values):
        if 'geoError' not in values and not v:
            raise ValueError('Either geoLocation or geoError is required.')
        return v
