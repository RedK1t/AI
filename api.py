#!/usr/bin/env python3
"""
SQL Injection Scanner WebSocket API

This module provides a WebSocket API for real-time SQL injection scanning.
The scanner analyzes web forms and inputs, tests payloads, and reports
vulnerabilities as they are discovered.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Set

import websockets
from typing import Any

from core.config import get_config
from test import run_scan

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

config = get_config()

connected_clients: Dict[str, Any] = {}
active_scans: Dict[str, dict] = {}


async def send_to_client(client_id: str, message: dict):
    """Send a JSON message to a specific client."""
    if client_id in connected_clients:
        try:
            await connected_clients[client_id].send(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending to client {client_id}: {e}")


async def broadcast_to_scan(scan_id: str, message: dict):
    """Broadcast message to all clients watching a specific scan."""
    if scan_id in active_scans:
        for client_id in active_scans[scan_id].get('watchers', []):
            await send_to_client(client_id, message)


async def handle_scan_request(client_id: str, scan_id: str, target_url: str):
    """
    Handle a scan request by running the scan and streaming results.
    
    When a vulnerability is found, it immediately notifies the client
    and stops testing further payloads for that specific parameter.
    """
    try:
        await send_to_client(client_id, {
            "type": "scan_start",
            "scan_id": scan_id,
            "target_url": target_url,
            "timestamp": datetime.now().isoformat()
        })

        progress_messages = []
        vulnerabilities = []
        
        # Store reference to main event loop for callbacks
        main_loop = asyncio.get_event_loop()

        def progress_callback(msg: str, current = None, total = None):
            progress_messages.append({
                "timestamp": datetime.now().isoformat(),
                "message": msg,
                "current": current,
                "total": total
            })
            try:
                msg_data = {
                    "type": "progress",
                    # "message": msg,
                    "current": current,
                    "total": total,
                    "timestamp": datetime.now().isoformat()
                }
                # Schedule on main event loop from worker thread
                asyncio.run_coroutine_threadsafe(
                    send_to_client(client_id, msg_data),
                    main_loop
                )
            except Exception as e:
                logger.error(f"Error sending progress: {e}")

        def result_callback(vuln_details: dict):
            vuln_data = {
                **vuln_details,
                "timestamp": datetime.now().isoformat()
            }
            vulnerabilities.append(vuln_data)
            try:
                # Schedule on main event loop from worker thread
                asyncio.run_coroutine_threadsafe(
                    send_to_client(client_id, {
                        "type": "vulnerability_found",
                        "vulnerability": vuln_data
                    }),
                    main_loop
                )
            except Exception as e:
                logger.error(f"Error sending vulnerability: {e}")

        # Run scan in executor to avoid blocking event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, 
            run_scan, 
            target_url, 
            progress_callback, 
            result_callback
        )

        await send_to_client(client_id, {
            "type": "scan_complete",
            "scan_id": scan_id,
            "result": result,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Scan error for {scan_id}: {e}")
        await send_to_client(client_id, {
            "type": "error",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        })


async def handle_client(websocket: Any):
    """Handle incoming WebSocket client connections."""
    client_id = str(uuid.uuid4())
    connected_clients[client_id] = websocket
    
    logger.info(f"Client connected: {client_id} from {websocket.remote_address}")
    
    await send_to_client(client_id, {
        "type": "connected",
        "client_id": client_id,
        "message": "Connected to SQL Injection Scanner API"
    })

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")
                
                if msg_type == "start_scan":
                    target_url = data.get("url")
                    if not target_url:
                        await send_to_client(client_id, {
                            "type": "error",
                            "error": "Missing 'url' parameter",
                            "timestamp": datetime.now().isoformat()
                        })
                        continue
                    
                    scan_id = str(uuid.uuid4())
                    active_scans[scan_id] = {
                        "target_url": target_url,
                        "client_id": client_id,
                        "watchers": [client_id],
                        "start_time": datetime.now()
                    }
                    
                    logger.info(f"Starting scan {scan_id} for {target_url}")
                    await handle_scan_request(client_id, scan_id, target_url)
                    del active_scans[scan_id]
                    
                elif msg_type == "watch_scan":
                    scan_id = data.get("scan_id")
                    if scan_id and scan_id in active_scans:
                        active_scans[scan_id]["watchers"].append(client_id)
                        await send_to_client(client_id, {
                            "type": "watching_scan",
                            "scan_id": scan_id,
                            "timestamp": datetime.now().isoformat()
                        })
                    else:
                        await send_to_client(client_id, {
                            "type": "error",
                            "error": f"Scan {scan_id} not found",
                            "timestamp": datetime.now().isoformat()
                        })
                
                elif msg_type == "ping":
                    await send_to_client(client_id, {
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif msg_type == "list_scans":
                    await send_to_client(client_id, {
                        "type": "scans_list",
                        "scans": [
                            {
                                "scan_id": sid,
                                "target_url": info["target_url"],
                                "start_time": info["start_time"].isoformat()
                            }
                            for sid, info in active_scans.items()
                        ],
                        "timestamp": datetime.now().isoformat()
                    })
                
                else:
                    await send_to_client(client_id, {
                        "type": "error",
                        "error": f"Unknown message type: {msg_type}",
                        "timestamp": datetime.now().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await send_to_client(client_id, {
                    "type": "error",
                    "error": "Invalid JSON message",
                    "timestamp": datetime.now().isoformat()
                })
                
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Client {client_id} disconnected")
    finally:
        if client_id in connected_clients:
            del connected_clients[client_id]
        for scan_id in active_scans:
            if client_id in active_scans[scan_id].get("watchers", []):
                active_scans[scan_id]["watchers"].remove(client_id)


async def main():
    """Start the WebSocket server."""
    host = config.API_HOST
    port = config.API_PORT
    
    logger.info(f"Starting SQL Injection Scanner WebSocket API on {host}:{port}")
    
    async with websockets.serve(handle_client, host, port):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
