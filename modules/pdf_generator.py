import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(dataframe, compliance_score):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    elements = []
    styles = getSampleStyleSheet()

    # Custom Header Styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=14
    )
    cell_style = ParagraphStyle(
        'GridCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10
    )

    # Document Header
    elements.append(Paragraph("AWS Cloud Security & GRC Posture Assessment", title_style))
    elements.append(Paragraph(f"Framework Alignment: NIST CSF 2.0 & CIS AWS Foundations | Overall Posture Score: <b>{compliance_score}%</b>", subtitle_style))
    elements.append(Spacer(1, 10))

    # Build Audit Table
    headers = ["Control", "Framework", "Resource", "Status", "Severity", "Remediation Action"]
    data = [headers]

    for _, row in dataframe.iterrows():
        data.append([
            Paragraph(str(row.get('Control_ID', '')), cell_style),
            Paragraph(str(row.get('Framework', '')), cell_style),
            Paragraph(str(row.get('Resource', '')), cell_style),
            Paragraph(str(row.get('Status', '')), cell_style),
            Paragraph(str(row.get('Severity', '')), cell_style),
            Paragraph(str(row.get('Remediation', '')), cell_style)
        ])

    table = Table(data, colWidths=[55, 95, 110, 45, 55, 180])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
    ]))

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer
