# Earth map data (third-party)

These datasets are bundled locally (no CDN) for the Earth / flat-map views.

## `cables.geo.json` — submarine cables

- Source: **TeleGeography**, via https://www.submarinecablemap.com/
- Format: `{"type": "cables", "lines": [[[lon, lat], ...], ...]}` — cable route
  polylines only (names and metadata stripped).
- Please retain attribution to TeleGeography / submarinecablemap.com when
  reusing this data (it is shown in the visualization's legend).

Known issue: a few trans-Pacific routes terminate at exactly `-180.0`
longitude, i.e. they are split at the antimeridian. Renderers that do not
split geometry at +/-180 draw a long streak across the Pacific, which is why
the cables near Hawaii can look wrong. Fixing this means either handling the
dateline in the renderer or re-importing the cables split cleanly at +/-180.

## `land-110m.geo.json` — coastlines / land

- Source: **Natural Earth** (1:110m land), https://www.naturalearthdata.com/
- Natural Earth is in the public domain; attribution is appreciated but not
  required.
