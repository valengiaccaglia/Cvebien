import resend

from app.config import settings


resend.api_key = settings.RESEND_API_KEY


def build_unsubscribe_url(token: str) -> str:
    return f"{settings.BASE_URL.rstrip('/')}/unsubscribe/{token}"


def build_cve_email_html(subscription: dict, cve: dict) -> str:
    unsubscribe_url = build_unsubscribe_url(subscription["unsubscribe_token"])
    fixed_text = cve["fixed_version"] or "Not patched yet"
    return f"""
    <div style='font-family: Arial, sans-serif; color: #111; line-height: 1.6;'>
      <h1>CVE Alert: {cve['cve_id']} for {subscription['app_name']}</h1>
      <p><strong>Severity:</strong> {cve['severity'].title()}</p>
      <p><strong>CVSS Score:</strong> {cve['cvss_score'] or 'N/A'}</p>
      <p><strong>Description:</strong><br>{cve['description']}</p>
      <p><strong>Fixed version:</strong> {fixed_text}</p>
      <p><a href='{unsubscribe_url}' style='display:inline-block;padding:12px 18px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none;'>Unsubscribe</a></p>
      <p style='font-size:0.9rem;color:#555;margin-top:24px;'>You are receiving this because you subscribed to {subscription['app_name']} alerts.</p>
    </div>
    """


async def send_cve_alert(to_email: str, subscription: dict, cve: dict) -> None:
    subject = f"CVE Alert: {cve['cve_id']} for {subscription['app_name']}"
    html = build_cve_email_html(subscription, cve)
    await resend.Emails.send_async({
        "from": "alerts@cvenamenazas.app",
        "to": [to_email],
        "subject": subject,
        "html": html,
    })
