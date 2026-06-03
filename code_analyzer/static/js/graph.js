/**
 * graph.js — force-directed dependency graph on <canvas>
 * No external deps. Nodes = files, edges = imports.
 */

class DependencyGraph {
  constructor(canvasEl, tooltipEl) {
    this.canvas  = canvasEl;
    this.tooltip = tooltipEl;
    this.ctx     = canvasEl.getContext("2d");
    this.nodes   = [];
    this.edges   = [];
    this.sim     = null;
    this._drag   = null;
    this._hover  = null;
    this._selected = null;
    this._onSelect = null;  // callback(node)
    this._offset = { x: 0, y: 0 };
    this._scale  = 1;
    this._panStart = null;
    this._animId = null;
    this._highlighted = new Set(); // node ids highlighted by file selection

    this._bindEvents();
  }

  // ── Public API ────────────────────────────────────────────────────────────

  load(graphData, onSelect) {
    this._onSelect = onSelect;
    this.nodes = graphData.nodes.map(n => ({
      ...n,
      x: Math.random() * 400 - 200,
      y: Math.random() * 400 - 200,
      vx: 0, vy: 0,
      radius: this._nodeRadius(n),
    }));
    this.edges = graphData.edges;
    this._offset = { x: 0, y: 0 };
    this._scale  = 1;
    this._startSim();
    this._resize();
  }

  highlight(nodeIds) {
    this._highlighted = new Set(nodeIds);
  }

  selectByPath(path) {
    const node = this.nodes.find(n => n.path === path);
    if (node) { this._selected = node; this._onSelect?.(node); }
  }

  // ── Simulation ────────────────────────────────────────────────────────────

  _nodeRadius(n) {
    const base = 6;
    const extra = Math.min(Math.sqrt((n.lines || 50) / 50) * 3, 10);
    return base + extra;
  }

  _startSim() {
    let ticks = 0;
    const maxTicks = 300;
    const run = () => {
      this._tick();
      this._draw();
      ticks++;
      if (ticks < maxTicks || this._drag) {
        this._animId = requestAnimationFrame(run);
      } else {
        this._animId = null;
        this._drawLoop(); // idle: redraw only on events
      }
    };
    if (this._animId) cancelAnimationFrame(this._animId);
    this._animId = requestAnimationFrame(run);
  }

  _drawLoop() {
    this._draw();
    this._animId = requestAnimationFrame(() => this._drawLoop());
  }

  _tick() {
    const nodes = this.nodes;
    const k = 0.03;
    const repel = 1800;

    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist2 = dx * dx + dy * dy + 0.01;
        const force = repel / dist2;
        const fx = dx / Math.sqrt(dist2) * force;
        const fy = dy / Math.sqrt(dist2) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    // Attraction along edges
    for (const e of this.edges) {
      const a = nodes[e.source], b = nodes[e.target];
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const target = 120;
      const force = (dist - target) * k;
      const fx = dx / dist * force, fy = dy / dist * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }

    // Center gravity
    for (const n of nodes) {
      n.vx += -n.x * 0.005;
      n.vy += -n.y * 0.005;
    }

    // Integrate
    for (const n of nodes) {
      if (this._drag === n) continue;
      n.vx *= 0.85; n.vy *= 0.85;
      n.x += n.vx; n.y += n.vy;
    }
  }

  // ── Drawing ───────────────────────────────────────────────────────────────

  _draw() {
    const { ctx, canvas } = this;
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(W / 2 + this._offset.x, H / 2 + this._offset.y);
    ctx.scale(this._scale, this._scale);

    // Edges
    for (const e of this.edges) {
      const a = this.nodes[e.source], b = this.nodes[e.target];
      if (!a || !b) continue;
      const isHighlighted = this._highlighted.has(a.id) || this._highlighted.has(b.id);
      const isSelected = this._selected && (this._selected.id === a.id || this._selected.id === b.id);

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);

      if (isSelected) {
        ctx.strokeStyle = "#bc8cff";
        ctx.lineWidth = 2;
        ctx.globalAlpha = 1;
      } else if (isHighlighted) {
        ctx.strokeStyle = "#58a6ff";
        ctx.lineWidth = 1.5;
        ctx.globalAlpha = .8;
      } else {
        ctx.strokeStyle = "#30363d";
        ctx.lineWidth = 1;
        ctx.globalAlpha = .5;
      }
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Arrow
      if (isSelected || isHighlighted) {
        const dx = b.x - a.x, dy = b.y - a.y;
        const len = Math.sqrt(dx * dx + dy * dy);
        const ux = dx / len, uy = dy / len;
        const tx = b.x - ux * b.radius;
        const ty = b.y - uy * b.radius;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(tx - ux * 8 + uy * 4, ty - uy * 8 - ux * 4);
        ctx.lineTo(tx - ux * 8 - uy * 4, ty - uy * 8 + ux * 4);
        ctx.closePath();
        ctx.fillStyle = isSelected ? "#bc8cff" : "#58a6ff";
        ctx.fill();
      }
    }

    // Nodes
    for (const n of this.nodes) {
      const isSelected  = this._selected?.id === n.id;
      const isHighlighted = this._highlighted.has(n.id);
      const isHover     = this._hover?.id === n.id;
      const r = n.radius;

      // Glow ring
      if (isSelected) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 5, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(188,140,255,.25)";
        ctx.fill();
      } else if (isHighlighted) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(88,166,255,.2)";
        ctx.fill();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = n.color || "#8b949e";
      ctx.globalAlpha = isSelected || isHighlighted ? 1 : 0.75;
      ctx.fill();
      ctx.globalAlpha = 1;

      if (isSelected || isHover) {
        ctx.strokeStyle = "#fff";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Label
      if (isSelected || isHighlighted || isHover || this._scale > 1.2) {
        ctx.font = `${isSelected ? "bold " : ""}${Math.max(9, 10 / this._scale)}px sans-serif`;
        ctx.fillStyle = "#e6edf3";
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillText(n.label, n.x, n.y + r + 3);
      }
    }

    ctx.restore();
  }

  // ── Events ────────────────────────────────────────────────────────────────

  _bindEvents() {
    const c = this.canvas;
    c.addEventListener("mousedown", e => this._onMouseDown(e));
    c.addEventListener("mousemove", e => this._onMouseMove(e));
    c.addEventListener("mouseup",   e => this._onMouseUp(e));
    c.addEventListener("mouseleave",() => { this._hover = null; this.tooltip.classList.add("hidden"); });
    c.addEventListener("wheel",     e => this._onWheel(e), { passive: false });
    c.addEventListener("dblclick",  e => this._onDblClick(e));
    window.addEventListener("resize", () => this._resize());
  }

  _worldPos(e) {
    const rect = this.canvas.getBoundingClientRect();
    const cx = this.canvas.width / 2 + this._offset.x;
    const cy = this.canvas.height / 2 + this._offset.y;
    return {
      x: (e.clientX - rect.left - cx) / this._scale,
      y: (e.clientY - rect.top  - cy) / this._scale,
    };
  }

  _nodeAt(e) {
    const { x, y } = this._worldPos(e);
    let best = null, bestD2 = Infinity;
    for (const n of this.nodes) {
      const d2 = (n.x - x) ** 2 + (n.y - y) ** 2;
      if (d2 < (n.radius + 4) ** 2 && d2 < bestD2) { best = n; bestD2 = d2; }
    }
    return best;
  }

  _onMouseDown(e) {
    const node = this._nodeAt(e);
    if (node) {
      this._drag = node;
    } else {
      this._panStart = { mx: e.clientX, my: e.clientY, ox: this._offset.x, oy: this._offset.y };
    }
  }

  _onMouseMove(e) {
    if (this._drag) {
      const p = this._worldPos(e);
      this._drag.x = p.x; this._drag.y = p.y;
      this._drag.vx = 0; this._drag.vy = 0;
      return;
    }
    if (this._panStart) {
      this._offset.x = this._panStart.ox + (e.clientX - this._panStart.mx);
      this._offset.y = this._panStart.oy + (e.clientY - this._panStart.my);
      return;
    }
    const node = this._nodeAt(e);
    this._hover = node;
    if (node) {
      this._showTooltip(e, node);
    } else {
      this.tooltip.classList.add("hidden");
    }
  }

  _onMouseUp(e) {
    if (this._drag) {
      const node = this._drag;
      this._drag = null;
      this._selected = node;
      this._onSelect?.(node);
    }
    this._panStart = null;
  }

  _onDblClick(e) {
    const node = this._nodeAt(e);
    if (!node) { this._offset = { x: 0, y: 0 }; this._scale = 1; }
  }

  _onWheel(e) {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    this._scale = Math.min(4, Math.max(0.2, this._scale * factor));
  }

  _showTooltip(e, node) {
    const tt = this.tooltip;
    const symCount = (node.symbols?.functions?.length || 0) + (node.symbols?.classes?.length || 0);
    tt.innerHTML = `
      <div class="tt-title">${node.label}</div>
      <div class="tt-row">Type: <span>${node.lang}</span></div>
      <div class="tt-row">Lignes: <span>${node.lines || "?"}</span></div>
      <div class="tt-row">Symboles: <span>${symCount}</span></div>
      <div class="tt-row">Complexité: <span>${node.symbols?.complexity || "?"}</span></div>
    `;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    tt.style.left = (e.clientX - rect.left + 10) + "px";
    tt.style.top  = (e.clientY - rect.top  + 10) + "px";
    tt.classList.remove("hidden");
  }

  _resize() {
    const p = this.canvas.parentElement;
    if (!p) return;
    this.canvas.width  = p.clientWidth;
    this.canvas.height = p.clientHeight;
    this._draw();
  }
}
