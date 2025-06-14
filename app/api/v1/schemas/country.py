from pydantic import BaseModel, constr, ConfigDict
from typing import Optional

class CountryBase(BaseModel):
    name: constr(min_length=1, max_length=100)
    iso2: constr(min_length=2, max_length=2)
    iso3: constr(min_length=3, max_length=3)
    continent: Optional[str] = None
    currency: Optional[str] = None
    phone_code: Optional[str] = None

class CountryCreate(CountryBase):
    pass

class CountryUpdate(BaseModel):
    name: Optional[constr(min_length=1, max_length=100)] = None
    iso2: Optional[constr(min_length=2, max_length=2)] = None
    iso3: Optional[constr(min_length=3, max_length=3)] = None
    continent: Optional[str] = None
    currency: Optional[str] = None
    phone_code: Optional[str] = None

class Country(CountryBase):
    id: int

    model_config = ConfigDict(from_attributes=True)

