#!/usr/bin/env python3
"""Render a note from notes/ as a standalone HTML page.

Usage: md2html.py <input.md> <output.html>

Handles the Markdown subset used in notes/: headings, paragraphs,
bullet lists (two-space indentation per level), pipe tables, fenced
code blocks, inline code, and links.  The page is self-contained
(inline CSS, no external resources) so it can be shared as one file.
"""
import html
import re
import sys

src = open(sys.argv[1]).read().splitlines()


def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\[([^\]]+)\]\((https?://[^)\s]+)\)', r'<a href="\2">\1</a>', t)
    return t


out, i, para = [], 0, []


def flush():
    global para
    if para:
        out.append('<p>' + inline(' '.join(para)) + '</p>')
        para = []


while i < len(src):
    line = src[i]
    if line.startswith('```'):
        flush()
        i += 1
        block = []
        while i < len(src) and not src[i].startswith('```'):
            block.append(src[i])
            i += 1
        out.append('<pre>' + html.escape('\n'.join(block), quote=False) + '</pre>')
    elif line.startswith('# '):
        flush(); out.append(f'<h1>{inline(line[2:])}</h1>')
    elif line.startswith('### '):
        flush(); out.append(f'<h3>{inline(line[4:])}</h3>')
    elif line.startswith('## '):
        flush(); out.append(f'<h2>{inline(line[3:])}</h2>')
    elif line.startswith('|'):
        flush(); rows = []
        while i < len(src) and src[i].startswith('|'):
            cells = [c.strip() for c in src[i].strip().strip('|').split('|')]
            if not all(re.fullmatch(r':?-+:?', c) for c in cells):
                rows.append(cells)
            i += 1
        out.append('<table>')
        out.append('<thead><tr>' + ''.join(f'<th>{inline(c)}</th>' for c in rows[0]) + '</tr></thead><tbody>')
        for r in rows[1:]:
            out.append('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>')
        out.append('</tbody></table>')
        continue
    elif re.match(r'^\s*- ', line):
        flush(); out.append('<ul>'); depth = 0; open_li = False
        while i < len(src) and (re.match(r'^\s*- ', src[i]) or (open_li and src[i].startswith('  ') and src[i].strip())):
            m = re.match(r'^(\s*)- (.*)$', src[i])
            if not m:  # continuation line of the current item
                out[-1] += ' ' + inline(src[i].strip())
                i += 1
                continue
            d = len(m.group(1)) // 2
            if d > depth:
                out.append('<ul>'); depth = d; open_li = False
            while d < depth:
                if open_li: out.append('</li>')
                out.append('</ul></li>'); depth -= 1; open_li = False
            if open_li: out.append('</li>')
            out.append(f'<li>{inline(m.group(2))}'); open_li = True
            i += 1
        if open_li: out.append('</li>')
        while depth > 0:
            out.append('</ul></li>'); depth -= 1
        out.append('</ul>')
        continue
    elif line.strip() == '':
        flush()
    else:
        para.append(line.strip())
    i += 1
flush()

css = """
body { font-family: Helvetica, Arial, sans-serif; font-size: 15px; line-height: 1.45; color: #111; background: #fff;
       max-width: 62em; margin: 2em auto; padding: 0 1.5em; }
h1 { font-size: 1.5em; margin: 0 0 0.3em; }
h2 { font-size: 1.15em; margin: 1.8em 0 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
h3 { font-size: 1em; margin: 1.2em 0 0.4em; }
ul ul { margin-top: 0.2em; }
p { margin: 0.6em 0; }
table { border-collapse: collapse; width: 100%; margin: 0.8em 0 1.2em; font-size: 0.93em; }
th, td { border: 1px solid #999; padding: 0.3em 0.5em; vertical-align: top; text-align: left; }
th { background: #eee; font-weight: bold; }
code { font-family: Menlo, Consolas, monospace; font-size: 0.92em; background: #f2f2f2; padding: 0 0.2em; white-space: nowrap; }
pre { font-family: Menlo, Consolas, monospace; font-size: 0.86em; line-height: 1.35; background: #f6f6f6; border: 1px solid #ddd;
      padding: 0.6em 0.8em; overflow-x: auto; margin: 0.6em 0 1em; }
a { color: #0645ad; }
ul { margin: 0.5em 0 0.5em 1.4em; padding: 0; }
li { margin: 0.25em 0; }
@media print { body { max-width: none; margin: 0; font-size: 11pt; } h2 { page-break-after: avoid; } table, pre { page-break-inside: avoid; } }
"""
title = next((l[2:] for l in src if l.startswith('# ')), 'Document')
doc = ('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
       '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
       f'<title>{html.escape(title)}</title>\n<style>{css}</style>\n</head>\n<body>\n'
       + '\n'.join(out) + '\n</body>\n</html>\n')
open(sys.argv[2], 'w').write(doc)
