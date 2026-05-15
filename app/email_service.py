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
        "from": "alerts@threattrackersupport.app",
        "to": [to_email],
        "subject": subject,
        "html": html,
    })


async def send_subscription_confirmation(to_email: str, app_name: str, severities: list[str], unsubscribe_token: str) -> None:
    unsubscribe_url = build_unsubscribe_url(unsubscribe_token)
    sev_list = ", ".join(s.title() for s in severities)
    html = f"""
    <div style='font-family:Arial,sans-serif;color:#111;line-height:1.6;max-width:520px;margin:0 auto'>
      <div style='background:#0B1730;padding:32px;border-radius:12px;text-align:center'>
        <div style='width:14px;height:14px;border-radius:7px;background:#fff;display:inline-block;margin-bottom:16px'></div>
        <h1 style='color:#EAEFFC;font-size:22px;font-weight:400;margin:0 0 8px'>Alerta registrada</h1>
        <p style='color:rgba(234,239,252,0.55);font-size:14px;margin:0'>Ya estás suscripto a <strong style='color:#EAEFFC'>{app_name}</strong></p>
      </div>
      <div style='padding:28px 0'>
        <table style='width:100%;border-collapse:collapse;font-size:14px'>
          <tr style='border-bottom:1px solid #eee'>
            <td style='padding:10px 0;color:#888'>Aplicación</td>
            <td style='padding:10px 0;font-weight:600'>{app_name}</td>
          </tr>
          <tr style='border-bottom:1px solid #eee'>
            <td style='padding:10px 0;color:#888'>Email</td>
            <td style='padding:10px 0'>{to_email}</td>
          </tr>
          <tr>
            <td style='padding:10px 0;color:#888'>Severidades</td>
            <td style='padding:10px 0'>{sev_list}</td>
          </tr>
        </table>
        <p style='font-size:13px;color:#888;margin-top:24px'>
          Te vamos a avisar cada vez que se publique una nueva CVE que afecte a <strong>{app_name}</strong> con severidad {sev_list}.
        </p>
        <p style='margin-top:24px'>
          <a href='{unsubscribe_url}' style='font-size:13px;color:#888;text-decoration:underline'>Cancelar suscripción</a>
        </p>
      </div>
    </div>
    """
    await resend.Emails.send_async({
        "from": "alerts@threattrackersupport.app",
        "to": [to_email],
        "subject": f"Suscripción confirmada — {app_name}",
        "html": html,
    })
