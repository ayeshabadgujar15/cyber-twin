"""Self-contained local reports. Red means review needed, not proven compromise."""
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
import re

from app.security.security_plan import security_plan

TITLE='Digital Footprint & Security Report'


def report_data(snapshot):
    accounts=[]
    for item in snapshot.get('accounts',[]):
        if item.get('finding_status')=='dismissed':continue
        check=item.get('breach_check') or {}
        reasons=[]
        if check.get('known_breach'):
            reasons.append('Service breach history found; personal exposure unverified')
        if item.get('security_alert'):reasons.append('Security-notification evidence needs review')
        if item.get('password_event'):reasons.append('Password-event evidence needs review')
        status='action' if reasons else 'unknown' if check.get('status')!='checked' else 'neutral'
        reason='; '.join(reasons) if reasons else 'Breach lookup not completed or unavailable' if status=='unknown' else 'No flagged signals in the available evidence; not a safety guarantee'
        accounts.append({**item,'review_status':status,'review_reason':reason})
    accounts.sort(key=lambda item:({'action':0,'unknown':1,'neutral':2}[item['review_status']],item['domain']))
    checks=[]
    for item in accounts:
        check={**(item.get('breach_check') or {}),'domain':item['domain']}
        if check.get('known_breach'):check['status']='checked' # Retain last-known positive findings after a failed refresh.
        checks.append(check)
    return {**snapshot,'accounts':accounts,'generated_at':datetime.now(timezone.utc).isoformat(),
            'action_count':sum(item['review_status']=='action' for item in accounts),
            'unknown_count':sum(item['review_status']=='unknown' for item in accounts),
            'security_plan':security_plan(accounts,checks)}


def html_report(snapshot):
    data=report_data(snapshot)
    e=lambda value:escape(str(value if value is not None else 'Not available'),quote=True)
    sections=['<!doctype html><html lang="en"><meta charset="utf-8"><title>'+TITLE+'</title>',
      '''<style>body{font:14px/1.6 Arial,sans-serif;color:#182230;max-width:1100px;margin:40px auto;padding:0 24px}h1{font-size:28px}h2{margin-top:30px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d8dee6;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef2f6}.action{background:#fff0ef}.action .status{color:#a82020;font-weight:bold}.unknown{background:#fff8e7}.unknown .status{color:#795400}.note{color:#526071}.demo{padding:14px;background:#fff1cf;font-weight:bold}.card{border:1px solid #d8dee6;padding:15px;margin:14px 0}@media print{button{display:none}body{margin:0;font-size:10pt}thead{display:table-header-group}tr,.card{break-inside:avoid}*{print-color-adjust:exact;-webkit-print-color-adjust:exact}}</style>''',
      '<button onclick="window.print()">Print / save as PDF</button><h1>'+TITLE+'</h1>']
    if data.get('is_demo'):sections.append('<p class="demo">FICTIONAL DEMO - example data only. No personal mailbox or real incident is represented.</p>')
    sections.extend(['<p>Mailbox: '+e(data.get('email') or 'Loaded scan')+'<br>Generated: '+e(data['generated_at'])+'</p>',
      '<p><b>'+str(len(data['accounts']))+' discovered services</b> | '+str(data['action_count'])+' need review | '+str(data['unknown_count'])+' not checked</p>',
      '<p class="note">Red = action/review needed. Amber = not checked. Other rows = no flagged signals, not a guarantee of safety. Service clues do not prove account ownership. Breach dates are reported incident dates.</p>',
      '<h2>Coverage and monitoring</h2><p>Last successful inbox check: '+e(data.get('gmail_checked_at'))+'<br>Last breach-check attempt: '+e(data.get('breach_checked_at'))+'</p>',
      '<p class="note">'+e(coverage_note(data.get('coverage',{})))+'</p>',
      '<h2>All discovered services</h2><table><thead><tr><th>Service</th><th>First evidence</th><th>Last evidence</th><th>Review status and reason</th></tr></thead><tbody>'])
    for item in data['accounts']:
        label={'action':'ACTION NEEDED','unknown':'NOT CHECKED','neutral':'NO FLAGGED SIGNALS'}[item['review_status']]
        sections.append('<tr class="'+item['review_status']+'"><td>'+e(item.get('service_name') or item['domain'])+'<br>'+e(item['domain'])+'</td><td>'+e(item.get('first_seen'))+'</td><td>'+e(item.get('last_seen'))+'</td><td><span class="status">'+label+'</span><br>'+e(item['review_reason'])+'</td></tr>')
    sections.append('</tbody></table><h2>Breach findings</h2>')
    for item in data['accounts']:
        check=item.get('breach_check') or {}
        for breach in check.get('breaches',[]):
            sections.append('<section class="card"><h3>'+e(item['domain'])+' - '+e(breach.get('name'))+'</h3><p>Reported date: '+e(breach.get('breach_date'))+' | '+('Verified by provider' if breach.get('verified') else 'Unverified / demo report')+'</p><p>'+e(breach.get('description'))+'</p><p>Exposed data: '+e(', '.join(breach.get('data_exposed',[])))+'<br>Provider records: '+e(breach.get('affected_records'))+'</p><p class="note">Source: '+e(breach.get('source_url') or 'Fictional demo')+'<br>Last successful check: '+e(check.get('last_success_at') or data.get('breach_checked_at'))+'</p>'+('<p>Last-known finding: the latest provider refresh was unavailable.</p>' if check.get('status')!='checked' else '')+'</section>')
    sections.append('<h2>Recommended actions</h2>')
    for plan in data['security_plan']:
        if not any(item['domain']==plan['domain'] and item['review_status']=='action' for item in data['accounts']):continue
        sections.append('<h3>'+e(plan['service_name'])+'</h3><ol>'+''.join('<li><b>'+e(step['title'])+'</b>: '+e(step['detail'])+'</li>' for step in plan['steps'])+'</ol>')
    sections.append('<h2>Recent monitoring alerts</h2><p class="note">Up to the latest 100 saved alerts are included; acknowledged does not mean an account has been secured.</p>')
    for alert in data.get('alerts',[]):
        sections.append('<p><b>'+e(alert.get('title'))+'</b> - '+e(alert.get('created_at'))+'<br>'+e(alert.get('detail'))+'</p>')
    sections.append('<h2>Limitations</h2><p>Results depend on mailbox coverage, mainly English subject rules and the provider catalogue. Missing mail or a missing breach match is not proof of inactivity or safety. Monitoring runs only while the local server and Gmail authorization remain available. Cyber Twin does not change passwords or account settings. This report contains personal account metadata: keep it private.</p></html>')
    return ''.join(sections)


def coverage_note(coverage):
    parts=[]
    complete=coverage.get('initial_scan_complete',coverage.get('scan_complete'))
    parts.append('The initial scan reached the mailbox end.' if complete else 'Initial mailbox coverage is partial or not established; this is not a complete account inventory.')
    if coverage.get('history_gap'):parts.append(coverage.get('gap_note') or 'A Gmail history gap was recorded.')
    if coverage.get('backlog_pending'):parts.append('A new-message backlog is pending processing.')
    if coverage.get('unavailable_messages'):parts.append(str(coverage['unavailable_messages'])+' messages were unavailable during the latest check.')
    parts.append('Evidence dates describe received notifications, not verified account creation or login times.')
    return ' '.join(parts)


def pdf_report(snapshot):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,LongTable,TableStyle,PageBreak,KeepTogether
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    data=report_data(snapshot);out=BytesIO();styles=getSampleStyleSheet()
    use_unicode=False
    font_path=Path('C:/Windows/Fonts/arial.ttf');bold_path=Path('C:/Windows/Fonts/arialbd.ttf')
    if font_path.exists() and bold_path.exists():
        if 'CyberTwinArial' not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont('CyberTwinArial',str(font_path)))
            pdfmetrics.registerFont(TTFont('CyberTwinArialBold',str(bold_path)))
        use_unicode=True
    styles.add(ParagraphStyle(name='BodySmall',fontName='Helvetica',fontSize=9,leading=13,spaceAfter=7,splitLongWords=True))
    styles.add(ParagraphStyle(name='CellSmall',fontName='Helvetica',fontSize=8,leading=11,spaceAfter=0,splitLongWords=True))
    styles.add(ParagraphStyle(name='ReportTitle',fontName='Helvetica-Bold',fontSize=23,leading=27,spaceAfter=15,textColor=colors.HexColor('#182230')))
    styles.add(ParagraphStyle(name='ActionText',parent=styles['CellSmall'],textColor=colors.HexColor('#a82020')))
    styles.add(ParagraphStyle(name='UnknownText',parent=styles['CellSmall'],textColor=colors.HexColor('#795400')))
    if use_unicode:
        for name in ['BodySmall','CellSmall','ActionText','UnknownText']:
            styles[name].fontName='CyberTwinArial'
        for name in ['ReportTitle','Heading2','Heading3']:
            styles[name].fontName='CyberTwinArialBold'
    def ascii_text(value):
        text=str(value if value is not None else 'Not available').replace('\u2014',' - ').replace('\u2013','-').replace('\u2019',"'").replace('\u2018',"'").replace('\u201c','"').replace('\u201d','"')
        text=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',text)
        return text if use_unicode else text.encode('latin-1','replace').decode('latin-1')
    def para(value,style='BodySmall'):
        return Paragraph(escape(ascii_text(value)).replace('\n','<br/>'),styles[style])
    story=[para(TITLE,'ReportTitle')]
    if data.get('is_demo'):story.append(para('FICTIONAL DEMO - all services and incidents are examples only.','Heading2'))
    story.extend([para('Mailbox: '+str(data.get('email') or 'Loaded scan')),para('Generated (UTC): '+data['generated_at']),
                  para(f"{len(data['accounts'])} discovered services | {data['action_count']} need review | {data['unknown_count']} not checked",'Heading2'),
                  para('Red = action/review needed. Amber = not checked. Neutral = no flagged signals, not a safety guarantee. A service breach does not prove personal exposure.'),
                  para('Coverage and monitoring','Heading2'),para(coverage_note(data.get('coverage',{}))),
                  para('Last successful inbox check: '+str(data.get('gmail_checked_at') or 'Not available')),
                  para('Last breach-check attempt: '+str(data.get('breach_checked_at') or 'Not available')),
                  para('All discovered services','Heading2')])
    rows=[[para(value,'CellSmall') for value in ['Service / domain','First evidence','Last evidence','Review status and reason']]]
    commands=[('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eaf0f6')),('VALIGN',(0,0),(-1,-1),'TOP'),
              ('GRID',(0,0),(-1,-1),.4,colors.HexColor('#d6dde5')),('LEFTPADDING',(0,0),(-1,-1),7),
              ('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]
    for index,item in enumerate(data['accounts'],1):
        status=item['review_status'];label={'action':'ACTION NEEDED','unknown':'NOT CHECKED','neutral':'NO FLAGGED SIGNALS'}[status]
        cell_style='ActionText' if status=='action' else 'UnknownText' if status=='unknown' else 'CellSmall'
        rows.append([para((item.get('service_name') or item['domain'])+'\n'+item['domain'],'CellSmall'),
                     para((item.get('first_seen') or 'Unknown')[:10],'CellSmall'),para((item.get('last_seen') or 'Unknown')[:10],'CellSmall'),
                     para(label+' - '+item['review_reason'],cell_style)])
        if status in {'action','unknown'}:commands.append(('BACKGROUND',(0,index),(-1,index),colors.HexColor('#fff0ef' if status=='action' else '#fff8e7')))
    table=LongTable(rows,colWidths=[150,64,64,245],repeatRows=1,hAlign='LEFT');table.setStyle(TableStyle(commands));story.append(table)
    story.extend([Spacer(1,12),para('Breach findings','Heading2')])
    found=False
    for item in data['accounts']:
        check=item.get('breach_check') or {}
        for breach in check.get('breaches',[]):
            found=True
            story.append(KeepTogether([para(item['domain']+' - '+str(breach.get('name')),'Heading3'),
                                      para('Reported incident date: '+str(breach.get('breach_date') or 'Unknown')+' | '+('Verified by provider' if breach.get('verified') else 'Unverified / demo report'))]))
            story.extend([para(breach.get('description') or 'No description supplied.'),
                          para('Exposed data: '+', '.join(breach.get('data_exposed',[]))),
                          para('Records indexed by provider: '+str(breach.get('affected_records') or 'Not supplied')),
                          para('Source: '+str(breach.get('source_url') or 'Fictional demo'))])
            if check.get('status')!='checked':story.append(para('This is a last-known finding. The latest provider refresh was unavailable.'))
    if not found:story.append(para('No breach records are available in this snapshot. This does not establish safety.'))
    story.extend([PageBreak(),para('Recommended actions','Heading2')])
    actions={item['domain'] for item in data['accounts'] if item['review_status']=='action'}
    if not actions:story.append(para('Use unique passwords, enable MFA/passkeys where supported, and periodically review sessions and recovery details.'))
    for plan in data['security_plan']:
        if plan['domain'] not in actions:continue
        story.append(para(plan['service_name'],'Heading3'))
        for index,step in enumerate(plan['steps'],1):story.append(para(str(index)+'. '+step['title']+': '+step['detail']))
    if data.get('alerts'):
        story.append(para('Recent monitoring alerts','Heading2'));story.append(para('Latest 100 saved alerts at most. Acknowledged does not mean an account has been secured.'))
        for alert in data['alerts']:story.extend([para(str(alert.get('title'))+' | '+str(alert.get('created_at')),'Heading3'),para(alert.get('detail'))])
    story.extend([para('Limitations and privacy','Heading2'),para('Mailbox rules are heuristic and mainly English. Sender identity, ownership, account use and personal exposure are not verified. Missing evidence is not proof of safety. Monitoring requires the local server and valid Google permission. Cyber Twin does not change account settings. Keep this report private.')])
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#667085'))
        canvas.drawString(36,23,'Cyber Twin | '+('FICTIONAL DEMO | ' if data.get('is_demo') else '')+'Personal report - not a security certification')
        canvas.drawRightString(A4[0]-36,23,'Page '+str(doc.page));canvas.restoreState()
    doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=42,title=TITLE,author='Cyber Twin')
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return out.getvalue()
