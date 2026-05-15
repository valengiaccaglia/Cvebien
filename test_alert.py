"""
Manda un email de alerta de prueba.
Uso: python test_alert.py tu@email.com
"""
import asyncio
import sys

from app.email_service import send_cve_alert, send_subscription_confirmation

FAKE_CVE = {
    "cve_id": "CVE-2025-99999",
    "description": "Buffer overflow in nginx HTTP/3 frame parser allows remote code execution via crafted QUIC packet.",
    "severity": "critical",
    "cvss_score": "9.8",
    "fixed_version": "1.27.5",
    "patched": True,
}

FAKE_SUB = {
    "app_name": "nginx",
    "unsubscribe_token": "test-token-no-funciona",
}


async def main():
    email = sys.argv[1] if len(sys.argv) > 1 else "valengiaccaglia@gmail.com"
    print(f"Mandando alert de prueba a {email}...")
    await send_cve_alert(email, FAKE_SUB, FAKE_CVE)
    print("Alert mandado.")

    print(f"Mandando confirmación de suscripción a {email}...")
    await send_subscription_confirmation(email, "nginx", ["critical", "high"], "test-token-no-funciona")
    print("Confirmación mandada.")


asyncio.run(main())
