"""Explainable, user-performed steps based on service history and mailbox clues."""


def security_plan(services, checks):
    by_domain = {check['domain']: check for check in checks}
    plans = []
    for service in services:
        domain = service['domain']
        check = by_domain.get(domain, {})
        checked = check.get('status') == 'checked'
        breached = checked and check.get('known_breach') is True
        exposed = {value.lower() for breach in check.get('breaches', []) for value in breach.get('data_exposed', [])}
        alert = service.get('security_alert', False)
        password = service.get('password_event', False)
        steps = [{'id':'open', 'title':'Open the service directly', 'detail':'Use its official app or a trusted bookmark. Confirm this is your account and look for its security settings or official breach notice.'}]
        if breached or alert or password:
            steps.append({'id':'password', 'title':'Review and update your password', 'detail':'If the current password may have been exposed, or you find unfamiliar account activity, replace it with a unique password. Update other accounts where you reused that password. Cyber Twin does not know your passwords or whether you reused them.'})
        else:
            steps.append({'id':'password', 'title':'Use a unique password', 'detail':'Check that this account has its own strong password, preferably generated and stored by a password manager.'})
        steps.extend([
            {'id':'mfa', 'title':'Enable stronger sign-in protection', 'detail':'Use a passkey, security key or two-factor authentication if the service supports it. Save recovery codes somewhere safe.'},
            {'id':'sessions', 'title':'Review devices and recent activity', 'detail':'Inspect active sessions and security events. Sign out unfamiliar devices and follow the service’s recovery process if you find activity you did not authorize.'},
            {'id':'recovery', 'title':'Check recovery details and connected apps', 'detail':'Confirm recovery email and phone details are yours. Review third-party access and remove connections you no longer recognize or use.'},
        ])
        if breached and any('email' in value or 'phone' in value for value in exposed):
            steps.append({'id':'phishing', 'title':'Watch for convincing follow-up scams', 'detail':'Exposed contact details can be used in phishing. Verify unexpected requests through the service directly; never share sign-in codes.'})
        plans.append({'domain':domain, 'service_name':service.get('service_name') or domain,
                      'priority':'review_first' if breached or alert else 'routine',
                      'reason':'Service breach history found; your personal exposure is not established.' if breached else
                               'A mailbox alert needs your review; it is not proof of compromise.' if alert else
                               'No service breach match was returned; routine protections still matter.' if checked else
                               'Breach lookup was not completed. These are general security steps.',
                      'steps':steps})
    return sorted(plans, key=lambda item: (item['priority'] != 'review_first', item['domain']))
