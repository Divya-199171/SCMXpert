# schema/schema.py

from pydantic import BaseModel, Field, validator
from datetime import date

class Shipments(BaseModel):
    shipmentNumber: str
    route: str
    device: str
    poNumber: int
    ndcNumber: int
    serialNumber: int
    goodsType: str
    deliveryDate: date
    deliveryNumber: int
    batchId: str
    shipmentDesc: str

    # Optional: you can add extra validators if needed
    @validator('deliveryDate')
    def delivery_date_cannot_be_past(cls, v):
        from datetime import date as dt_date
        if v < dt_date.today():
            raise ValueError('Delivery date cannot be in the past')
        return v
