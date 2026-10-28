"""Render immutable run snapshots without querying current threat or asset data."""
import csv
import io
import json
from html import escape
from .diagnostics import cvss_admission
from .profiles import identify_profile, profile_label

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, PageBreak, CondPageBreak


def csv_cell(value):
    text = '' if value is None else str(value)
    # Prevent spreadsheet programs from interpreting imported text as a formula.
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def render_csv(payload: dict) -> bytes:
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['ejecucion', 'fecha', 'modelo', 'posicion', 'hallazgo', 'activo', 'puerto', 'cves', 'estado', 'indice', 'cvss', 'epss', 'kev', 'criticidad', 'exposicion', 'pesos_json', 'aportes_json', 'datos_ausentes_json', 'evidencias_json', 'explicacion', 'perfil', 'severidad_original', 'vectores_originales_json', 'admision_cvss'])
    run = payload['run']
    for position, result in enumerate(payload['items'], 1):
        snapshot = result['snapshot']
        finding = snapshot['finding']
        inputs = snapshot.get('inputs', {})
        values = [run['id'], run['created_at'], run['version'], position if result['score'] is not None else '', finding['name'], finding['host'], finding['port'], '; '.join(finding.get('cves', [])), result['status'], result['score']]
        values += [inputs.get(key) for key in ('cvss', 'epss', 'kev', 'criticality', 'exposure')]
        values += [json.dumps(value, ensure_ascii=False) for value in (run['configuration']['weights'], snapshot.get('contributions', {}), snapshot.get('missing', []), snapshot.get('evidence', []))]
        writer.writerow([csv_cell(value) for value in values + [result['explanation'], run['configuration'].get('profile_id', identify_profile(run['configuration']['weights'])), finding.get('severity'), json.dumps(finding.get('original_vectors'), ensure_ascii=False), cvss_admission(finding)['message']]])
    return output.getvalue().encode('utf-8-sig')


LABELS = {'cvss': 'Severidad técnica (CVSS)', 'epss': 'Probabilidad de explotación (EPSS)',
          'kev': 'Explotación conocida (KEV)', 'criticality': 'Criticidad del activo', 'exposure': 'Exposición del activo'}


def render_pdf(payload: dict) -> bytes:
    """Create a reader-facing report from the frozen execution, without raw JSON."""
    from datetime import datetime

    output = io.BytesIO()
    graphite, orange = '#27272A', '#C2410C'
    muted, line, pale = '#62616B', '#E4E4E7', '#FFF7ED'
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='ReportTitle', fontName='Helvetica-Bold', fontSize=22, leading=27, textColor=colors.HexColor(graphite), spaceAfter=12))
    styles.add(ParagraphStyle(name='Section', fontName='Helvetica-Bold', fontSize=13, leading=17, textColor=colors.HexColor(graphite), spaceBefore=11, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle(name='Text', fontName='Helvetica', fontSize=9.5, leading=13, textColor=colors.HexColor(graphite), spaceAfter=6))
    styles.add(ParagraphStyle(name='SmallText', parent=styles['Text'], fontSize=8, leading=11, textColor=colors.HexColor(muted), wordWrap='CJK'))
    styles.add(ParagraphStyle(name='Cell', parent=styles['Text'], fontSize=8.5, leading=11.5, spaceAfter=0, wordWrap='CJK'))
    styles.add(ParagraphStyle(name='HeadCell', parent=styles['Cell'], fontName='Helvetica-Bold', textColor=colors.white))
    story = []
    width = 174 * mm
    run = payload['run']
    weights = run['configuration']['weights']

    def p(value, style='Text'):
        return Paragraph(escape(str(value)), styles[style])

    def add(value, style='Text', *, keep_with_next=False):
        paragraph = p(value, style)
        if keep_with_next:
            paragraph.keepWithNext = True
        story.append(paragraph)

    def date_label(value):
        if not value:
            return 'No registrada'
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.strftime('%d/%m/%Y %H:%M UTC%z') if 'T' in value else parsed.strftime('%d/%m/%Y')
        except ValueError:
            return str(value)

    def table(headers, rows, widths):
        cells = [[p(text, 'HeadCell') for text in headers]]
        cells.extend([[p(text, 'Cell') for text in row] for row in rows])
        element = Table(cells, colWidths=[width * fraction for fraction in widths], repeatRows=1, hAlign='LEFT', splitInRow=1)
        element.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(graphite)),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(pale)]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10), ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor(orange)),
            ('LINEBELOW', (0, 1), (-1, -1), 0.4, colors.HexColor(line)),
        ]))
        story.append(element)

    def value_label(key, value):
        if value is None:
            return 'Desconocido'
        if key == 'kev':
            return 'En catálogo KEV' if value else 'No figura en el catálogo consultado'
        if key == 'epss':
            return f'{value * 100:.3f} %'
        if key == 'cvss':
            return f'{value:g} / 10'
        return f'{value:g} / 5'

    calculated = [row for row in payload['items'] if row['score'] is not None]
    pending = len(payload['items']) - len(calculated)
    add('INFORME DE RESULTADOS', 'SmallText')
    add('Priorización de vulnerabilidades', 'ReportTitle')
    add('RiskEngine | Modelo experimental')
    add(f"Ejecución {run['id'][:8]} | {date_label(run['created_at'])}", 'SmallText')
    table(['Hallazgos', 'Con índice', 'Pendientes'], [[payload['total'], len(calculated), pending]], [1/3, 1/3, 1/3])
    add('01 / Cómo leer este informe', 'Section')
    add('Perfil: ' + profile_label(weights))
    if identify_profile(weights) == 'cvss-only-v1':
        add('Esta ejecución prioriza únicamente por CVSS Base 3.1. EPSS, KEV y contexto no influyen porque tienen peso cero. El índice es CVSS multiplicado por diez, no una probabilidad de riesgo.')
    else:
        add('El índice combina únicamente los criterios con peso positivo. Es una ayuda para organizar la revisión; no expresa un porcentaje de riesgo ni confirma que el equipo haya sido atacado.')
    add('Cada ficha muestra los datos guardados y cuántos puntos aportó cada criterio. Los pesos son decisiones del modelo y deben justificarse antes de la evaluación académica.')
    add('Pesos de esta ejecución', 'Section')
    table(['Criterio', 'Peso', 'Aporte máximo'], [[label, f'{weights[key]*100:g} %', f'{weights[key]*100:g} puntos'] for key, label in LABELS.items()], [.62, .18, .20])
    add('Los ejemplos identificados como sintéticos son datos de prueba; no acreditan vulnerabilidades detectadas en un entorno real.', 'SmallText')
    story.append(PageBreak())
    add('02 / Orden de atención', 'Section')
    add('Los índices mayores aparecen primero. Un resultado pendiente necesita datos adicionales y no debe interpretarse como prioridad baja. La posición de los empates es solo de presentación.')
    rows = []
    for position, result in enumerate(payload['items'], 1):
        finding = result['snapshot']['finding']
        score = 'Pendiente' if result['score'] is None else f"{result['score']:.2f}"
        rows.append([str(position) if result['score'] is not None else '-', finding['name'], finding['host'], score])
    table(['Orden', 'Hallazgo', 'Activo', 'Índice / 100'], rows or [['-', 'Sin hallazgos', '-', '-']], [.10, .46, .25, .19])
    if calculated:
        first = calculated[0]
        add(f"Primer resultado del orden calculado: {first['snapshot']['finding']['name']} ({first['score']:.2f} puntos).")

    for position, result in enumerate(payload['items'], 1):
        story.append(PageBreak())
        snapshot = result['snapshot']
        finding = snapshot['finding']
        inputs = snapshot.get('inputs', {})
        contributions = snapshot.get('contributions', {})
        add(f'FICHA {position:02d} / HALLAZGO', 'SmallText', keep_with_next=True)
        add(finding['name'], 'ReportTitle')
        add(f"Activo: {finding['host']} | Servicio: {finding['port']}")
        add(f"Identificadores: {', '.join(finding.get('cves', [])) or 'Sin CVE registrado'}")
        add(f"Severidad original del escáner: {finding.get('severity') if finding.get('severity') is not None else 'No registrada'}", 'SmallText')
        add(cvss_admission(finding)['message'], 'SmallText')
        score = 'Pendiente de cálculo' if result['score'] is None else f"{result['score']:.2f} / 100 puntos"
        table(['Resultado', 'Interpretación'], [[score, 'Revisar el motivo indicado en esta ficha.' if result['score'] is None else 'Índice experimental calculado con los pesos elegidos.']], [.34, .66])
        add('Por qué obtuvo este resultado', 'Section')
        if result['score'] is None:
            missing = ', '.join(LABELS.get(key, key) for key in snapshot.get('missing', []))
            if missing:
                add(f'Falta información en criterios con peso activo: {missing}. Se conserva el hallazgo sin asignarle un índice.')
            else:
                add(result['explanation'])
        else:
            contextual = sum(contributions.get(key, 0) for key in ('criticality', 'exposure'))
            add(f'La criticidad y exposición del activo aportaron {contextual:.2f} puntos. El resto proviene de la severidad técnica y de las señales de amenaza activadas en esta ejecución.')
        rows = []
        for key, label in LABELS.items():
            contribution = contributions.get(key)
            points = f'{contribution:.4f}'.rstrip('0').rstrip('.') if contribution is not None else ('Desactivado' if weights[key] == 0 else 'Sin calcular')
            rows.append([label, (cvss_admission(finding)['message'] if key == 'cvss' and inputs.get(key) is None else value_label(key, inputs.get(key))), f'{weights[key]*100:g} %', points])
        table(['Criterio', 'Dato utilizado', 'Peso', 'Puntos'], rows, [.40, .32, .12, .16])
        add('Los puntos se suman y el total se redondea a dos decimales. Criticidad y exposición: nivel 1 aporta cero; nivel 5 aporta el máximo permitido por su peso.', 'SmallText')
        story.append(CondPageBreak(65 * mm))
        add('Evidencias de fuentes externas', 'Section')
        evidence_rows = []
        for evidence in snapshot.get('evidence', []):
            entry = evidence.get('entry') or {}
            source = evidence.get('source', '')
            use = 'Admisible' if evidence.get('admissible') else 'No admisible'
            value = 'No figura en KEV' if source == 'kev' and entry.get('value') is False else value_label(source, entry.get('value'))
            evidence_rows.append([evidence.get('cve', '-'), source.upper(), value, date_label(entry.get('data_date')), use])
        if evidence_rows:
            # Keep citations before the splittable table so they cannot become an isolated trailing page.
            add('Admisible indica que la evidencia cumple las reglas de vigencia y disponibilidad. Solo los criterios con peso mayor que cero influyen en el índice.', 'SmallText')
            for source, name in [('epss', 'FIRST / EPSS'), ('kev', 'CISA / KEV')]:
                records = [e.get('entry') for e in snapshot.get('evidence', []) if e.get('source') == source and e.get('entry')]
                if records:
                    entry = records[0]
                    label = f"{name} | Consulta: {date_label(entry.get('fetched_at'))}"
                    url = entry.get('provenance', 'Procedencia no registrada')
                    story.append(Paragraph(f'{escape(label)}<br/>{escape(str(url))}', styles['SmallText']))
            table(['CVE', 'Fuente', 'Valor', 'Fecha del dato', 'Evidencia'], evidence_rows, [.25, .12, .25, .20, .18])
        else:
            add('Sin evidencias externas asociadas. Un hallazgo sin CVE no permite consultar EPSS o KEV mediante ese identificador.')

    story.append(PageBreak())
    add('TRAZABILIDAD', 'SmallText')
    add('Método y registro de ejecución', 'ReportTitle')
    add('El informe utiliza la información congelada al calcular. Las modificaciones posteriores de activos o fuentes no alteran estos resultados.')
    add('Reglas del cálculo', 'Section')
    for text in [
        'Se transforma cada entrada a una escala de 0 a 1 y se multiplica por su peso. La suma se multiplica por 100.',
        'CVSS 3.1 se divide por 10. EPSS se utiliza entre 0 y 1. KEV conocido se representa con 1 (incluido) o 0 (no incluido).',
        'Criticidad y exposición se normalizan mediante (nivel - 1) / 4.',
        'Si falta un dato con peso activo, no se asigna índice. Peso cero desactiva ese criterio.',
        'Con varios CVE: EPSS utiliza el máximo solo si todos son conocidos; KEV es positivo si alguno lo es, negativo si todos son negativos y desconocido en los demás casos.',
    ]:
        add(text)
    add('Identificación y vigencia', 'Section')
    config = run['configuration']
    table(['Campo', 'Valor guardado'], [
        ['Ejecución', run['id']], ['Versión del modelo', run['version']],
        ['Fecha de ejecución', date_label(run['created_at'])], ['Importación', config.get('import_id', 'No registrada')],
        ['Fecha de corte de evidencias', date_label(config.get('cut_off'))],
        ['Antigüedad máxima de evidencias', f"{config.get('max_evidence_age_days', 'No registrada')} días"],
    ], [.38, .62])
    add('Alcance académico', 'Section')
    add('Modelo experimental pendiente de validación. Un orden diferente al de CVSS no demuestra por sí mismo una mejora. El JSON conserva los detalles estructurados y los identificadores de cada evidencia para análisis y reproducción.')

    document = SimpleDocTemplate(output, pagesize=(210*mm, 297*mm), leftMargin=18*mm, rightMargin=18*mm, topMargin=24*mm, bottomMargin=20*mm, title='RiskEngine - Priorización de vulnerabilidades', author='RiskEngine')

    def frame(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(graphite))
        canvas.rect(0, 282*mm, 210*mm, 15*mm, fill=1, stroke=0)
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.white)
        canvas.drawString(18*mm, 287*mm, 'RiskEngine')
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(192*mm, 287*mm, 'CVSS 3.1 SOLO' if identify_profile(weights) == 'cvss-only-v1' else 'PRIORIZACIÓN CON CONTEXTO')
        canvas.setStrokeColor(colors.HexColor(line))
        canvas.line(18*mm, 15*mm, 192*mm, 15*mm)
        canvas.setFillColor(colors.HexColor(muted))
        canvas.setFont('Helvetica', 8)
        canvas.drawString(18*mm, 10*mm, f"Ejecución {run['id'][:8]} | Modelo experimental")
        canvas.drawRightString(192*mm, 10*mm, f'Página {doc.page}')
        canvas.restoreState()

    document.build(story, onFirstPage=frame, onLaterPages=frame)
    return output.getvalue()
