"""EXPOSE dashboard UI — server-rendered with FastAPI + Jinja2 + HTMX + Alpine.js.

Progressive-enhancement UI for the EXPOSE EASI platform. The dashboard
renders a split-pane layout: an observation graph (D3.js) on the left and
a filterable entity table on the right, both updated in real-time during
active pipeline runs via SSE.

Design language: "darkroom reveal" — elements emerge from a near-black
background as data arrives, using an amber-to-wheat-gold palette that
evokes a photograph developing.
"""
