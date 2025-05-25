from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os
from fastapi import Form
from fastapi.responses import RedirectResponse
from core.schema import Shipments
from fastapi import HTTPException
from core.auth import get_required_current_user, get_current_admin_user
from fastapi import Depends
from typing import Optional
from fastapi import Query

# Load .env variables
load_dotenv()


router = APIRouter()
templates = Jinja2Templates(directory="templates")

# MongoDB connection using MONGO_URI from .env
client = MongoClient(os.getenv("MONGO_URI"))
db = client['projectfast']
shipments_collection = db['shipments']

@router.get("/allshipment")
async def allshipments(
    request: Request,
    created_by: Optional[str] = Query(None),
    user=Depends(get_required_current_user)
):
    query = {}
    if created_by:
        # Case-insensitive starts-with search on created_by
        query["created_by"] = {"$regex": f"^{created_by}", "$options": "i"}

    shipments = list(shipments_collection.find(query))

    for shipment in shipments:
        shipment['_id'] = str(shipment['_id'])

    return templates.TemplateResponse("allshipments.html", {
        "request": request,
        "shipments": shipments,
        "created_by": created_by or "",
    })


@router.get("/editshipment/{shipment_id}")
async def edit_shipment_form(request: Request, shipment_id: str, user=Depends(get_required_current_user)):
    shipment = shipments_collection.find_one({"_id": ObjectId(shipment_id)})
    if shipment:
        shipment['_id'] = str(shipment['_id'])
        return templates.TemplateResponse("editshipment.html", {"request": request, "shipment": shipment})
    else:
        raise HTTPException(status_code=404, detail="Shipment not found")


# Handle form submission
@router.post("/editshipment/{shipment_id}")
async def update_shipment(
    shipment_id: str,
    shipment_number: str = Form(...),
    route: str = Form(...),
    device: str = Form(...),
    po_number: int = Form(...),
    ndc_number: int = Form(...),
    serial_number: int = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    delivery_number: int = Form(...),
    batch_id: str = Form(...),
    shipment_description: str = Form(...),
    user=Depends(get_required_current_user)
):
    result = shipments_collection.update_one(
        {"_id": ObjectId(shipment_id)},
        {"$set": {
            "shipmentNumber": shipment_number,
            "route": route,
            "device": device,
            "poNumber": po_number,
            "ndcNumber": ndc_number,
            "serialNumber": serial_number,
            "goodsType": goods_type,
            "expected_delivery_date": expected_delivery_date,
            "deliveryNumber": delivery_number,
            "batchId": batch_id,
            "shipmentDesc": shipment_description
        }}
    )
    return RedirectResponse(url="/allshipment", status_code=303)


# Delete route
@router.post("/deleteshipments")
async def delete_selected_shipments(request: Request, user=Depends(get_required_current_user)):
    form_data = await request.form()
    selected_ids = form_data.getlist("selected_shipments")
    
    if selected_ids:
        for sid in selected_ids:
            # Delete from DB
            shipments_collection.delete_one({"_id": ObjectId(sid)})
    return RedirectResponse("/allshipment", status_code=303)