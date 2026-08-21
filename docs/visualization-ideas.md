# Where to look for future visualization ideas

The animated status page (`--visualize`) now carries ~650 geometry/overlay views.
This is a running catalog of where the *next* ideas come from, grouped from
"just add a formula" to "make the art mean something about the mixnet."

## 1. Reference catalogs (formulas ready to drop into a `G.create`)

- **Paul Bourke** (paulbourke.net/geometry) - curves, surfaces, fractals,
  attractors, polyhedra, all with explicit parametric formulas. The single
  richest source for this kind of work.
- **Wolfram MathWorld** - curves, surfaces, fractals, plane/space curves,
  polyhedra; each page has parametric equations.
- **3D-XplorMath / Virtual Math Museum** - hundreds of curated curves and
  surfaces with parameters.
- **Wikipedia lists** - "list of surfaces", "list of curves", "list of fractals
  by Hausdorff dimension", "list of uniform polyhedra", "list of regular
  polytopes", "list of periodic/aperiodic tilings".
- **OEIS** - any integer sequence becomes a spiral/plot (Recaman, Ulam, Stern-
  Brocot, primes, partition numbers).

## 2. Mathematical families not yet covered (concrete)

- **Dynamical systems:** Sprott's ~19 minimal chaotic flows, Aizawa, Dadras,
  Halvorsen, Thomas, Nose-Hoover; iterated maps: Ikeda, Chirikov standard map,
  Gumowski-Mira, Hopalong, Martin, Tinkerbell, Gingerbreadman.
- **Complex dynamics:** Newton/Nova/Magnet fractals, Lyapunov (Markus) fractals,
  Julia/Mandelbrot variants, Kleinian/Schottky limit sets.
- **Number theory:** Ulam & Sacks spirals, Gaussian primes, Recaman, modular
  multiplication circles (n*k mod m chords), Collatz trees, Farey/Ford circles.
- **Symmetry & groups:** Cayley graphs of finite groups, wallpaper/frieze
  groups, root systems + Coxeter-plane projections, Lie-group orbits.
- **Tilings:** Penrose, Ammann-Beenker, pinwheel, substitution/Wang/Truchet
  tiles, and hyperbolic {p,q} tilings on the Poincare disk.
- **Knots & topology:** the Rolfsen table, torus/Lissajous/cable knots, braids,
  Seifert surfaces, Chmutov surfaces; nonorientable immersions (Klein, Boy,
  Roman, cross-cap).
- **Graphs:** named graphs (Petersen, Kneser, de Bruijn, circulant, hypercube
  Qn, Ramanujan/expander) and their symmetric embeddings.
- **Surfaces:** minimal surfaces (Costa, Enneper-n, Scherk), triply-periodic
  minimal surfaces (gyroid, diamond, primitive), spherical harmonics Y_lm.
- **4D+ and fibrations:** 24-cell, 120/600-cell, duoprisms, the Hopf fibration,
  Clifford tori, stereographic projections.

## 3. Physics- and growth-inspired (often the best-looking)

- Reaction-diffusion (Gray-Scott / Turing patterns), Belousov-Zhabotinsky.
- Chladni figures / cymatics, standing waves, wavefunctions and orbital shapes.
- Diffusion-limited aggregation, space-colonization venation, Physarum (slime-
  mold) networks, differential growth, phyllotaxis, L-system plants.
- Flow fields / curl-noise, boids/flocking, N-body gravity, magnetic field lines.
- Packings: Apollonian gaskets, circle/sphere packings, Voronoi/Delaunay (also
  on the sphere and torus), Lloyd relaxation, Poisson-disk sampling.

## 4. Mixnet-meaningful ideas (make the geometry MEAN something)

The strongest views map the real Katzenpost network onto the geometry rather
than being decorative. These reuse data we already ship in the payload:

- **Latency-space embedding** - MDS/force layout of the ping/traceroute matrix,
  so distance on screen = network distance.
- **Traceroute path bundles / vantage arcs** - real hop paths as great-circle
  arcs (partly planned in the geo work).
- **Sphinx / Loopix internals** - onion-layer peeling (we have ripples),
  Poisson mix-delay distributions, cover-traffic vs real-traffic ratios,
  path-selection probability heatmaps, per-hop anonymity-set / entropy growth.
- **Epoch dynamics** - key-rotation timelines, consensus churn between epochs,
  node arrival/departure over time.
- **AS/geo topology** - submarine-cable style routes, AS-level graph, country
  clustering.

## 5. Generative-art communities

- Inigo Quilez (iquilezles.org) - SDFs, domain warping, noise.
- Shadertoy, OpenProcessing, "The Nature of Code" (Shiffman), Structure Synth /
  Context Free, Hvidtfeldt's "Generative Art".

## 6. Systematic generation - multiply what we already have

Often the cheapest wins: parameterize an existing family and sweep it.

- Sweep params: superformula (m, n1..n3), Lissajous ratios, knot (p, q),
  attractor coefficients -> dozens of variants + a "random params" generator.
- Transform existing solids: duals, compounds, truncations, stellations.
- Compose: apply an attractor's flow to a lattice; knot/stellate existing
  curves; re-project 4D forms with different rotations.

## Practical constraints when adding views

- Coordinates bounded (|coord| <~ 22); attractors must converge (drop transients,
  clamp NaN/blow-ups).
- Every edge needs a themeable `color` from the palette - balls now take their
  nearest edge's hue, and packets route along the edges (see
  `9e-geo3d.js` and the `viz-view-system` memory).
- View ids are `[a-z0-9-]+` only (no underscores - the deep-link regex rejects
  them).
- ASCII-only source; keep the dense one-view-per-line style; one commit per view.
