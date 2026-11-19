from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Response, UploadFile

from auth.utils import get_current_user, get_db
from config import settings
from services.ids_analyzer import analyze_pcap

router = APIRouter()

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024


def _valid_object_id(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid scan ID")


def _serialize(doc: dict) -> dict:
    return {
        "id": str(doc["_id"]),
        "filename": doc["filename"],
        "status": doc["status"],
        "created_at": doc["created_at"],
        "completed_at": doc.get("completed_at"),
        "packet_statistics": doc.get("packet_statistics", {}),
        "alert_count": doc.get("alert_count", 0),
        "suspicious_ip_count": doc.get("suspicious_ip_count", 0),
        "error_message": doc.get("error_message"),
    }


@router.post("/upload", status_code=202)
async def upload_network_captures(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one PCAP file is required")

    capture_dir = Path(settings.workspace_dir) / "network_captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for upload in files:
        original_name = upload.filename or "capture"
        suffix = Path(original_name).suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"{original_name}: unsupported file extension")

        safe_name = f"{uuid.uuid4().hex}{suffix}"
        capture_path = capture_dir / safe_name
        size = 0

        try:
            with capture_path.open("wb") as output:
                while chunk := await upload.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_UPLOAD_SIZE:
                        raise HTTPException(
                            status_code=413,
                            detail=f"{original_name}: file exceeds the 50 MB upload limit",
                        )
                    output.write(chunk)
        except HTTPException:
            capture_path.unlink(missing_ok=True)
            raise
        except Exception:
            capture_path.unlink(missing_ok=True)
            raise HTTPException(status_code=500, detail="Failed to store the uploaded capture")

        now = datetime.utcnow()
        doc = {
            "user_id": str(current_user["_id"]),
            "filename": original_name,
            "status": "queued",
            "created_at": now,
            "completed_at": None,
            "packet_statistics": {},
            "alert_count": 0,
            "suspicious_ip_count": 0,
            "error_message": None,
        }
        inserted = await db.network_scans.insert_one(doc)
        scan_id = str(inserted.inserted_id)

        background_tasks.add_task(
            run_network_scan,
            db,
            scan_id,
            str(capture_path),
            str(current_user["_id"]),
        )
        results.append({"id": scan_id, "filename": original_name, "status": "queued"})

    return {"scans": results}


async def run_network_scan(db, scan_id: str, capture_path: str, user_id: str) -> None:
    scan_oid = ObjectId(scan_id)
    await db.network_scans.update_one(
        {"_id": scan_oid, "user_id": user_id},
        {"$set": {"status": "running", "error_message": None}},
    )

    try:
        result = await asyncio.to_thread(analyze_pcap, capture_path)
        statistics = result["packet_statistics"]
        now = datetime.utcnow()

        for alert in result["alerts"]:
            await db.network_alerts.insert_one({
                "scan_id": scan_id,
                "user_id": user_id,
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "source_ip": alert["source_ip"],
                "destination_ip": alert.get("destination_ip"),
                "description": alert["description"],
                "evidence": alert["evidence"],
                "created_at": now,
            })

        if result["ip_summaries"]:
            await db.network_hosts.insert_many([
                {
                    **summary,
                    "scan_id": scan_id,
                    "user_id": user_id,
                }
                for summary in result["ip_summaries"]
            ])

        await db.network_scans.update_one(
            {"_id": scan_oid, "user_id": user_id},
            {"$set": {
                "status": "completed",
                "completed_at": now,
                "packet_statistics": statistics,
                "alert_count": statistics["alert_count"],
                "suspicious_ip_count": statistics["suspicious_ip_count"],
                "error_message": None,
            }},
        )
    except Exception:
        await db.network_scans.update_one(
            {"_id": scan_oid, "user_id": user_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow(),
                "error_message": "The capture could not be analyzed",
            }},
        )
    finally:
        try:
            os.unlink(capture_path)
        except FileNotFoundError:
            pass


@router.get("/scans")
async def list_network_scans(
    db=Depends(get_db),
    current_user=Depends(get_current_user),
    skip: int = 0,
    limit: int = 20,
):
    skip = max(skip, 0)
    limit = max(1, min(limit, 100))
    cursor = db.network_scans.find(
        {"user_id": str(current_user["_id"])}
    ).sort("created_at", -1).skip(skip).limit(limit)
    scans = await cursor.to_list(length=limit)
    return [_serialize(scan) for scan in scans]


@router.get("/scans/{scan_id}")
async def get_network_scan(
    scan_id: str,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    scan_oid = _valid_object_id(scan_id)
    scan = await db.network_scans.find_one({"_id": scan_oid})
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    if scan["user_id"] != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return _serialize(scan)


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_network_scan(
    scan_id: str,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    scan_oid = _valid_object_id(scan_id)
    scan = await db.network_scans.find_one({"_id": scan_oid})
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    if scan["user_id"] != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Access denied")
    if scan["status"] in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Cannot delete a scan while analysis is active")

    scan_query = {
        "scan_id": scan_id,
        "user_id": str(current_user["_id"]),
    }
    await db.network_alerts.delete_many(scan_query)
    await db.network_hosts.delete_many(scan_query)
    await db.network_scans.delete_one({"_id": scan_oid, "user_id": str(current_user["_id"])})
    return Response(status_code=204)


@router.get("/scans/{scan_id}/alerts")
async def get_network_alerts(
    scan_id: str,
    skip: int = 0,
    limit: int = 1000,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    scan_oid = _valid_object_id(scan_id)
    scan = await db.network_scans.find_one({"_id": scan_oid})
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    if scan["user_id"] != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Access denied")

    skip = max(skip, 0)
    limit = max(1, min(limit, 1000))
    cursor = db.network_alerts.find(
        {"scan_id": scan_id, "user_id": str(current_user["_id"])}
    ).sort("created_at", 1).skip(skip).limit(limit)
    alerts = await cursor.to_list(length=limit)
    return [
        {
            "id": str(alert["_id"]),
            "alert_type": alert["alert_type"],
            "severity": alert["severity"],
            "source_ip": alert["source_ip"],
            "destination_ip": alert.get("destination_ip"),
            "description": alert["description"],
            "evidence": alert.get("evidence", {}),
            "created_at": alert["created_at"],
        }
        for alert in alerts
    ]


@router.get("/scans/{scan_id}/ips")
async def get_network_ips(
    scan_id: str,
    kind: str = "all",
    skip: int = 0,
    limit: int = 100,
    db=Depends(get_db),
    current_user=Depends(get_current_user),
):
    if kind not in {"all", "suspicious", "normal"}:
        raise HTTPException(status_code=400, detail="kind must be 'all', 'suspicious', or 'normal'")

    scan_oid = _valid_object_id(scan_id)
    scan = await db.network_scans.find_one({"_id": scan_oid})
    if not scan:
        raise HTTPException(status_code=404, detail="Network scan not found")
    if scan["user_id"] != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Access denied")

    query = {
        "scan_id": scan_id,
        "user_id": str(current_user["_id"]),
    }
    if kind == "suspicious":
        query["suspicious"] = True
    elif kind == "normal":
        query["suspicious"] = False

    skip = max(skip, 0)
    limit = max(1, min(limit, 200))
    total = await db.network_hosts.count_documents(query)
    inventory_total = await db.network_hosts.count_documents({
        "scan_id": scan_id,
        "user_id": str(current_user["_id"]),
    })
    cursor = db.network_hosts.find(query, {"_id": 0}).sort("ip", 1).skip(skip).limit(limit)
    ips = await cursor.to_list(length=limit)
    return {
        "ips": ips,
        "total": total,
        "inventory_total": inventory_total,
        "skip": skip,
        "limit": limit,
    }
