import markdown
from xhtml2pdf import pisa
import os

BASE = os.path.dirname(os.path.abspath(__file__))
MD = os.path.join(BASE, 'interview_notes.md')
PDF = os.path.join(BASE, 'DPI_Interview_Notes.pdf')

with open(MD, 'r', encoding='utf-8') as f:
    text = f.read()

html_body = markdown.markdown(text, extensions=['tables', 'fenced_code', 'toc'])

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@page {{ size: A4; margin: 1.6cm 1.4cm; }}
body {{ font-family: Helvetica, Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }}
h1 {{ font-size: 17pt; color: #0b3d6e; margin: 6px 0 2px 0; }}
h2 {{ font-size: 13.5pt; color: #0b3d6e; border-bottom: 2px solid #0b3d6e; padding-bottom: 3px; margin-top: 18px; }}
h3 {{ font-size: 11.5pt; color: #11508f; margin-top: 12px; }}
h4 {{ font-size: 10.5pt; color: #333; }}
p {{ margin: 5px 0; }}
ul, ol {{ margin: 5px 0 5px 0; padding-left: 20px; }}
li {{ margin: 2.5px 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9.5pt; }}
th {{ background: #0b3d6e; color: white; padding: 4px 6px; text-align: left; }}
td {{ border: 1px solid #b8c4d0; padding: 4px 6px; vertical-align: top; }}
tr:nth-child(even) td {{ background: #eef3f8; }}
pre {{ background: #f2f2f2; border: 1px solid #d0d0d0; padding: 7px; font-family: "Courier New", monospace; font-size: 8.5pt; white-space: pre-wrap; word-wrap: break-word; }}
code {{ font-family: "Courier New", monospace; font-size: 9pt; background: #f2f2f2; }}
hr {{ border: none; border-top: 1px solid #999; margin: 14px 0; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

with open(PDF, 'wb') as out:
    status = pisa.CreatePDF(html, dest=out, encoding='utf-8')

if status.err:
    raise SystemExit(f'PDF generation failed: {status.err}')

print(f'PDF created: {PDF} ({os.path.getsize(PDF)} bytes)')
