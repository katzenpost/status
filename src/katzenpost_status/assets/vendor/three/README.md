# Vendored three.js (r128)

These files are third-party assets, bundled unmodified so the status page loads
everything locally (no CDN). They are licensed under the MIT License, separate
from this project's AGPL-3.0 license; see `LICENSE` in this directory.

- Upstream: https://github.com/mrdoob/three.js (release r128)
- Copyright 2010-2021 three.js authors, SPDX-License-Identifier: MIT

| File | Upstream path |
|------|---------------|
| `three.min.js` | `build/three.min.js` |
| `OrbitControls.js` | `examples/js/controls/OrbitControls.js` |
| `EffectComposer.js` | `examples/js/postprocessing/EffectComposer.js` |
| `RenderPass.js` | `examples/js/postprocessing/RenderPass.js` |
| `ShaderPass.js` | `examples/js/postprocessing/ShaderPass.js` |
| `UnrealBloomPass.js` | `examples/js/postprocessing/UnrealBloomPass.js` |
| `CopyShader.js` | `examples/js/shaders/CopyShader.js` |
| `LuminosityHighPassShader.js` | `examples/js/shaders/LuminosityHighPassShader.js` |

`three.min.js` carries its upstream `@license` banner; the `examples/js` files
shipped without one, so an equivalent MIT banner was prepended to each. No code
was changed.
