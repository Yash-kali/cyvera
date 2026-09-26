import httpx
import websockets
import asyncio
import json

async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # 1. Login
        login_res = await client.post("/api/v1/auth/login", json={"email_or_username": "Yash", "password": "Yash@4050"})
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        access_token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        print("[PASS] User Login: Successfully authenticated operator 'Yash'")

        # 2. Get Scan 22 Details
        scan_res = await client.get("/api/v1/scans/22", headers=headers)
        assert scan_res.status_code == 200
        scan_data = scan_res.json()
        print(f"[PASS] Scan Details API: ID={scan_data['id']}, Status={scan_data['status']}, Score={scan_data['security_score']}, Grade={scan_data['security_grade']}")

        # 3. Get Security Score API
        score_res = await client.get("/api/v1/security-score/22", headers=headers)
        if score_res.status_code != 200:
            print("Score API Error:", score_res.status_code, score_res.text)
        assert score_res.status_code == 200
        score_data = score_res.json()
        print(f"[PASS] Security Score API: Score={score_data['score']}, Grade={score_data['grade']}, Risk={score_data['risk_level']}")

        # 4. Issue WebSocket Short-Lived Ticket
        ticket_res = await client.post("/api/v1/auth/ws-ticket", headers=headers)
        assert ticket_res.status_code == 200
        ticket_data = ticket_res.json()
        ws_ticket = ticket_data["ticket"]
        print(f"[PASS] Short-Lived WS Ticket: Issued ticket with expires_in={ticket_data['expires_in']}s")

        # 5. Verify WS Ticket cannot access REST APIs
        rest_probe = await client.get("/api/v1/scans/22", headers={"Authorization": f"Bearer {ws_ticket}"})
        assert rest_probe.status_code == 401, f"Expected 401, got {rest_probe.status_code}"
        print(f"[PASS] Token Isolation: Short-lived WS ticket strictly rejected from REST endpoint (Status: {rest_probe.status_code})")

        # 6. Connect to WebSocket using the short-lived ticket
        ws_url = f"ws://127.0.0.1:8000/ws/scans/22?token={ws_ticket}"
        async with websockets.connect(ws_url) as ws:
            first_msg = await ws.recv()
            evt = json.loads(first_msg)
            print(f"[PASS] WebSocket Connected: Event={evt['type']}, Stage={evt['stage']}, Status={evt['status']}")
            print(f"       Requests Used={evt['data'].get('requests_used')}, Requests Remaining={evt['data'].get('requests_remaining')}, Score={evt['data'].get('score')}")
            
            # Send ping
            await ws.send("ping")
            pong = await ws.recv()
            assert pong == "pong"
            print(f"[PASS] WebSocket Keepalive: Received '{pong}'")

        # 7. Check Reports List for Scan 22
        rep_res = await client.get("/api/v1/reports/22", headers=headers)
        assert rep_res.status_code == 200, f"Expected 200, got {rep_res.status_code}: {rep_res.text}"
        rep_data = rep_res.json()
        assert len(rep_data) > 0, "Expected at least 1 report artifact for scan 22"
        rep_item = rep_data[0]
        print(f"[PASS] Report Artifact: ID={rep_item['id']}, Title='{rep_item['title']}', Pages={rep_item['pages']}")

        # 8. Check Report Download PDF
        download_url = f"/api/v1/reports/download/{rep_item['id']}"
        pdf_res = await client.get(download_url, headers=headers)
        assert pdf_res.status_code == 200
        assert pdf_res.headers.get("content-type") == "application/pdf"
        assert len(pdf_res.content) > 1000
        print(f"[PASS] PDF Report Download: Size={len(pdf_res.content)} bytes, Content-Type={pdf_res.headers.get('content-type')}")

if __name__ == "__main__":
    asyncio.run(main())
