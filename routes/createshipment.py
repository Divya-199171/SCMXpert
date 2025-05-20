# app/routers/shipment.py

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime
from pymongo import DESCENDING
from pydantic import ValidationError
from fastapi import status
from core.database import shipments_collection
from core.auth import get_required_current_user, get_current_admin_user
from schema.schema import Shipments


router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/create-shipment", response_class=HTMLResponse)
async def get_create_shipment_form(request: Request, current_user: dict = Depends(get_required_current_user)):
    last_shipment = shipments_collection.find_one(sort=[("shipmentNumber", DESCENDING)])
    if last_shipment and "shipmentNumber" in last_shipment:
        last_id = last_shipment["shipmentNumber"]
        num_part = int(last_id.replace("exfscm", ""))
        new_id = f"exfscm{num_part+1:02}"
    else:
        new_id = "exfscm01"

    success_message = request.query_params.get("success")
    error_message = request.query_params.get("error")
    current_date = datetime.now().strftime('%Y-%m-%d')  #  generate current date in HTML5 format

    return templates.TemplateResponse("create_shipment.html", {
        "request": request,
        "shipment_id": new_id,
        "success": success_message,
        "error": error_message,
        "current_date": current_date  #  pass to template
    })


@router.post("/create-shipment")
async def create_shipment(request: Request,
    shipmentNumber: str = Form(...),
    route: str = Form(...),
    device: str = Form(...),
    poNumber: int = Form(...),  # accept as string first to validate with schema
    ndcNumber: int = Form(...),
    serialNumber: int = Form(...),
    goodsType: str = Form(...),
    deliveryDate: str = Form(...),
    deliveryNumber: int = Form(...),
    batchId: str = Form(...),
    shipmentDesc: str = Form(...),
    current_user: dict = Depends(get_required_current_user)
    
):

    # Try to create a Pydantic model for validation
    try:
        shipment_obj = Shipments(
            shipmentNumber=shipmentNumber,
            route=route,
            device=device,
            poNumber=poNumber,
            ndcNumber=ndcNumber,
            serialNumber=serialNumber,
            goodsType=goodsType,
            deliveryDate=datetime.strptime(deliveryDate, "%Y-%m-%d").date(),
            deliveryNumber=deliveryNumber,
            batchId=batchId,
            shipmentDesc=shipmentDesc
        )
    except ValueError as ve:
        # This can catch int casting errors or date parsing
        return RedirectResponse(
            url=f"/create-shipment?error=Invalid%20input:%20{ve}",
            status_code=status.HTTP_303_SEE_OTHER
        )
    except ValidationError as e:
        # Pydantic validation errors
        # Join all error messages into one string to send back
        
        errors = "; ".join([err['msg'] for err in e.errors()])
        return RedirectResponse(
            url=f"/create-shipment?error=Validation%20error:%20{errors}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Now, if all good, insert data to MongoDB
    shipment_data = shipment_obj.dict()
    shipment_data["created_at"] = datetime.utcnow()
    shipment_data["expected_delivery_date"] = shipment_data.pop("deliveryDate").strftime("%Y-%m-%d")  # keep same format for MongoDB

    shipments_collection.insert_one(shipment_data)

    return RedirectResponse(
        url="/create-shipment?success=Shipment%20created%20successfully",
        status_code=status.HTTP_303_SEE_OTHER
    )