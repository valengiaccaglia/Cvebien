"""
Simula el worker: busca CVEs recientes para una app y manda el mail si hay match.
Uso: python test_worker.py apache
     python test_worker.py nginx
     python test_worker.py "google chrome"
"""
import asyncio
import sys
from datetime import datetime, timedelta, timezone

from app.cve_client import fetch_recent_cve_ids, build_cve_record, _nvd_sleep
from app.email_service import send_cve_alert

EMAIL = "valengiaccaglia@gmail.com"


async def main():
    app_name = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "apache"
    print(f"Buscando CVEs recientes para: {app_name}")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=30)   # últimos 30 días para tener más chance

    cve_ids = await fetch_recent_cve_ids(window_start, now)
    print(f"CVEs encontradas en los últimos 30 días: {len(cve_ids)}")

    sent = 0
    for cve_id in cve_ids[:50]:   # máximo 50 para no spamear la API
        try:
            cve = await build_cve_record(cve_id)
        except Exception as e:
            print(f"  {cve_id}: error ({e})")
            await asyncio.sleep(_nvd_sleep())
            continue

        text = " ".join([
            cve.get("description", ""),
            *( cve.get("affected_products", []) or [] ),
            *( cve.get("affected_vendors", []) or [] ),
        ]).lower()

        if app_name.lower() in text:
            print(f"  MATCH: {cve_id} — severity={cve['severity']} cvss={cve['cvss_score']}")
            await send_cve_alert(
                EMAIL,
                {"unsubscribe_token": "test-token", "app_name": app_name},
                cve,
            )
            print(f"  -> Mail mandado a {EMAIL}")
            sent += 1
            if sent >= 3:
                print("(Límite de 3 mails de prueba alcanzado)")
                break

        await asyncio.sleep(_nvd_sleep())

    if sent == 0:
        print(f"No se encontraron CVEs recientes que mencionen '{app_name}'.")
        print("Probá con otro nombre (nginx, apache, chrome, curl, etc.)")


asyncio.run(main())
