/**
 * EXPOSE Observation Graph — D3.js Force-Directed Renderer
 *
 * Visual metaphor: DARKROOM REVEAL
 *
 * Entities appear as dim, blurred points — like an unexposed photograph
 * submerged in developer fluid. As the scan progresses and attribution
 * confidence increases, nodes sharpen and brighten, their colors warming
 * from cool gray through blue to amber-gold and finally bright wheat.
 *
 * The near-black background (#0a0a0f) is the darkness of the darkroom.
 * Each node is a grain of silver halide being reduced to metallic silver
 * by the evidence flowing through the pipeline. Confirmed entities glow.
 * Unattributed discoveries hover as ghosts. Assets classified as not-yours
 * fade back into the developer bath and dissolve.
 *
 * Color system (from expose.css):
 *   Seed:            dim amber    #b8860b  opacity 0.3
 *   Unattributed:    cool gray    #4a5568  opacity 0.5
 *   Medium:          warmer blue  #5b7ca3  opacity 0.7
 *   High:            amber-gold   #d4a020  opacity 0.9
 *   Confirmed:       wheat-gold   #f5deb3  opacity 1.0  (glow)
 *   Not-yours:       dark navy    #1a1a2e  opacity 0.15
 *   Requires review: alert amber  #e6a817  (pulsing)
 *
 * Usage:
 *   ExposeGraph.init('#observation-graph', { width: 960, height: 600 });
 *   ExposeGraph.updateData(graphData);
 *
 * @module graph
 */

/* global d3 */

const ExposeGraph = (() => {
    "use strict";

    // --- Constants --------------------------------------------------------
    const COLORS = {
        confirmed:       "#f5deb3",
        high:            "#d4a020",
        medium:          "#5b7ca3",
        requires_review: "#e6a817",
        unattributed:    "#4a5568",
        seed:            "#b8860b",
        not_yours:       "#1a1a2e",
    };

    const BACKGROUND = "#0a0a0f";

    const LABELED_STATUSES = new Set(["confirmed", "high", "requires_review"]);

    /** Normal node radius baseline. Highest-risk node gets 2x. */
    const DERU_KUI_RADIUS_MULTIPLIER = 2;

    /** Muted steel-blue for provider (supply chain) context nodes. */
    const PROVIDER_COLOR = "#6b7d94";

    /** Link distance by relationship type; fallback for unknown types. */
    const LINK_DISTANCES = {
        resolves_to:     80,
        belongs_to:      60,
        hosts:           90,
        certificate_for: 70,
        mx_for:          100,
        ns_for:          100,
        depends_on:      120,
        acquired_by:     110,
        default:         90,
    };

    /** Per-edge-type stroke colors; unlisted types use the default. */
    const EDGE_COLORS = {
        resolves_to:     "#4CAF50",  // green
        cname_for:       "#2196F3",  // blue
        mx_for:          "#FF9800",  // orange
        ns_for:          "#9C27B0",  // purple
        acquired_by:     "#F44336",  // red
        depends_on:      "#795548",  // brown
        certificate_for: "#00BCD4",  // cyan
        hosts:           "#607D8B",  // blue-grey
        belongs_to:      "#FFEB3B",  // yellow
        default:         "#5b7ca3",
    };

    const EMERGE_DURATION    = 800;
    const CHANGE_DURATION    = 500;
    const FADEOUT_DURATION   = 1500;
    const EDGE_DRAW_DURATION = 600;

    // --- Module state -----------------------------------------------------
    let svg = null, container = null, simulation = null;
    let width = 960, height = 600;
    let nodeMap = new Map();   // id -> node datum
    let edgeData = [];
    let linkGroup = null, nodeGroup = null, labelGroup = null;
    let tooltip = null;
    let deruKuiTooltip = null;

    // --- Filter state ----------------------------------------------------
    /** Active filter criteria.  Updated by setFilters(). */
    let activeFilters = {
        entityTypes:     new Set(["domain", "ip", "cloud_resource_id", "certificate_fingerprint", "organization", "provider"]),
        edgeTypes:       new Set(["resolves_to", "cname_for", "mx_for", "ns_for", "certificate_for", "hosts", "belongs_to", "acquired_by", "depends_on"]),
        attributionTiers: new Set(["confirmed", "high", "medium", "unattributed"]),
        minConfidence:   0.0,
    };

    /** Listeners notified when visible counts change after filtering. */
    let filterChangeListeners = [];

    // --- Visual property helpers ------------------------------------------

    /** Base 6 px, +2 px per collector signal, capped at 10 signals.
     *  Highest-risk node (deru-kui) gets 2x radius. */
    function nodeRadius(d) {
        const base = 6 + Math.min(d.collector_count || 1, 10) * 2;
        return d.highest_risk ? base * DERU_KUI_RADIUS_MULTIPLIER : base;
    }

    function nodeColor(d) {
        if (d.highest_risk) return "#ef4444";
        // Provider nodes (supply chain context) get a distinct muted color.
        if (d.entity_type === "provider") return PROVIDER_COLOR;
        return COLORS[d.attribution_status] || COLORS.unattributed;
    }

    /** Confidence 0->0.2, 1.0->1.0. */
    function nodeOpacity(d) {
        return 0.2 + (d.attribution_confidence || 0) * 0.8;
    }

    /** Higher confidence = less blur (sharper = more revealed). */
    function nodeFilterId(d) {
        const conf = d.attribution_confidence || 0;
        const blur = Math.max(0, 4 - conf * 4);
        if (blur >= 3) return "expose-blur-4";
        if (blur >= 1.5) return "expose-blur-2";
        if (blur >= 0.5) return "expose-blur-1";
        return "expose-blur-0";
    }

    function nodeFilter(d) {
        // Highest-risk node uses CSS-driven drop-shadow via deru-kui class.
        if (d.highest_risk) return null;
        if (d.attribution_status === "confirmed") return "url(#expose-glow)";
        return `url(#${nodeFilterId(d)})`;
    }

    function linkDistance(d) {
        return LINK_DISTANCES[d.relationship_type] || LINK_DISTANCES.default;
    }

    function linkColor(d) {
        return EDGE_COLORS[d.relationship_type] || EDGE_COLORS.default;
    }

    // --- Filter helpers ----------------------------------------------------

    /**
     * Determine whether a node passes the current filter criteria.
     * A node is visible when its entity_type, attribution_status, and
     * attribution_confidence all satisfy the active filters.
     *
     * @param {object} d  D3 node datum
     * @returns {boolean}
     */
    function nodePassesFilter(d) {
        if (!activeFilters.entityTypes.has(d.entity_type)) return false;

        // Map attribution_status to the tier buckets used by the filter panel.
        // "seed", "requires_review", and "not_yours" map to "unattributed".
        const tier = (d.attribution_status === "confirmed" ||
                      d.attribution_status === "high" ||
                      d.attribution_status === "medium")
            ? d.attribution_status
            : "unattributed";
        if (!activeFilters.attributionTiers.has(tier)) return false;

        if ((d.attribution_confidence || 0) < activeFilters.minConfidence) return false;

        return true;
    }

    /**
     * Determine whether an edge passes the current filter criteria.
     * An edge is visible when its relationship_type is enabled AND both
     * its source and target nodes are themselves visible.
     *
     * @param {object} d  D3 link datum (source/target may be objects or ids)
     * @returns {boolean}
     */
    function edgePassesFilter(d) {
        if (!activeFilters.edgeTypes.has(d.relationship_type)) return false;

        // D3 resolves source/target to objects after the first tick.
        const srcId = typeof d.source === "object" ? d.source.id : d.source;
        const tgtId = typeof d.target === "object" ? d.target.id : d.target;

        const srcNode = nodeMap.get(srcId);
        const tgtNode = nodeMap.get(tgtId);

        if (srcNode && !nodePassesFilter(srcNode)) return false;
        if (tgtNode && !nodePassesFilter(tgtNode)) return false;

        return true;
    }

    /**
     * Apply current filters to all rendered nodes, edges, and labels.
     * Uses CSS display to hide/show rather than removing DOM elements,
     * so the force simulation is unaffected and positions are preserved.
     *
     * After applying, notifies listeners with the visible node/edge counts.
     */
    function applyFilters() {
        if (!svg) return;

        let visibleNodes = 0;
        let visibleEdges = 0;

        nodeGroup.selectAll("circle").each(function (d) {
            const visible = nodePassesFilter(d);
            d3.select(this).style("display", visible ? null : "none");
            if (visible) visibleNodes++;
        });

        labelGroup.selectAll("text").each(function (d) {
            d3.select(this).style("display", nodePassesFilter(d) ? null : "none");
        });

        linkGroup.selectAll("line").each(function (d) {
            const visible = edgePassesFilter(d);
            d3.select(this).style("display", visible ? null : "none");
            if (visible) visibleEdges++;
        });

        // Notify listeners
        for (let i = 0; i < filterChangeListeners.length; i++) {
            filterChangeListeners[i](visibleNodes, visibleEdges);
        }
    }

    // --- SVG scaffold — defs, filters, groups ------------------------------

    function buildSvg(selector, opts) {
        width  = opts.width  || 960;
        height = opts.height || 600;

        svg = d3.select(selector)
            .append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", `0 0 ${width} ${height}`)
            .attr("preserveAspectRatio", "xMidYMid meet")
            .style("background", BACKGROUND);

        // ---- Filters (blur levels + glow) ----
        const defs = svg.append("defs");

        // No-op filter (sharp).
        defs.append("filter").attr("id", "expose-blur-0");

        [1, 2, 4].forEach((sigma) => {
            defs.append("filter")
                .attr("id", `expose-blur-${sigma}`)
                .append("feGaussianBlur")
                .attr("in", "SourceGraphic")
                .attr("stdDeviation", sigma);
        });

        // Glow filter for confirmed nodes.
        const glow = defs.append("filter").attr("id", "expose-glow");
        glow.append("feGaussianBlur")
            .attr("in", "SourceGraphic")
            .attr("stdDeviation", 3)
            .attr("result", "blur");
        const merge = glow.append("feMerge");
        merge.append("feMergeNode").attr("in", "blur");
        merge.append("feMergeNode").attr("in", "SourceGraphic");

        // ---- Zoom behaviour ----
        const zoom = d3.zoom()
            .scaleExtent([0.2, 5])
            .on("zoom", (event) => {
                container.attr("transform", event.transform);
            });
        svg.call(zoom);

        // ---- Layer container (translated by zoom) ----
        container = svg.append("g").attr("class", "expose-graph-container");

        // Edges below nodes; labels above nodes.
        linkGroup  = container.append("g").attr("class", "expose-links");
        nodeGroup  = container.append("g").attr("class", "expose-nodes");
        labelGroup = container.append("g").attr("class", "expose-labels");

        // ---- Tooltip ----
        tooltip = d3.select(selector)
            .append("div")
            .attr("class", "expose-tooltip")
            .style("position", "absolute")
            .style("pointer-events", "none")
            .style("background", "rgba(10, 10, 15, 0.92)")
            .style("border", "1px solid #d4a020")
            .style("border-radius", "4px")
            .style("padding", "8px 12px")
            .style("font-family", "monospace")
            .style("font-size", "11px")
            .style("color", "#f5deb3")
            .style("opacity", 0)
            .style("transition", "opacity 150ms ease")
            .style("z-index", 10);

        // ---- Deru-kui tooltip (highest-risk rich tooltip) ----
        deruKuiTooltip = d3.select("body")
            .append("div")
            .attr("class", "deru-kui-tooltip")
            .style("opacity", 0);
    }

    // --- Force simulation --------------------------------------------------

    function createSimulation(nodes, edges) {
        simulation = d3.forceSimulation(nodes)
            .alphaDecay(0.02)            // slow settle for dramatic reveal
            .force("link", d3.forceLink(edges)
                .id((d) => d.id)
                .distance(linkDistance))
            .force("charge", d3.forceManyBody().strength(-100))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide()
                .radius((d) => nodeRadius(d) + 4))
            .on("tick", ticked);
    }

    // --- Tick — position circles, links, labels each frame ----------------

    function ticked() {
        linkGroup.selectAll("line")
            .attr("x1", (d) => d.source.x)
            .attr("y1", (d) => d.source.y)
            .attr("x2", (d) => d.target.x)
            .attr("y2", (d) => d.target.y);

        nodeGroup.selectAll("circle")
            .attr("cx", (d) => d.x)
            .attr("cy", (d) => d.y);

        labelGroup.selectAll("text")
            .attr("x", (d) => d.x)
            .attr("y", (d) => d.y + nodeRadius(d) + 14);
    }

    // --- Drag behaviour ----------------------------------------------------

    function drag() {
        return d3.drag()
            .on("start", (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on("drag", (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on("end", (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            });
    }

    // --- Interaction — hover + click ----------------------------------------

    function onNodeHover(event, d) {
        // Highlight connected edges.
        linkGroup.selectAll("line")
            .attr("stroke-opacity", (l) =>
                (l.source.id === d.id || l.target.id === d.id) ? 0.9 : 0.08);

        if (d.highest_risk && deruKuiTooltip) {
            // Show rich deru-kui tooltip for the highest-risk node.
            const tierLabel = d.attribution_status
                ? d.attribution_status.replace(/_/g, " ")
                : "unknown";
            const scoreDisplay = d.lead_score != null
                ? d.lead_score
                : (d.attribution_confidence != null
                    ? ((d.attribution_confidence * 100).toFixed(0) + "%")
                    : "—");

            deruKuiTooltip
                .html(
                    '<div class="deru-kui-kanji">「出る杭は打たれる」</div>' +
                    '<div class="deru-kui-english">The nail that sticks out gets hammered</div>' +
                    '<div class="deru-kui-entity">' + (d.label || d.id) + '</div>' +
                    '<div class="deru-kui-score">Lead Score: ' + scoreDisplay + ' | ' + tierLabel + '</div>'
                )
                .style("left", (event.pageX + 16) + "px")
                .style("top", (event.pageY - 16) + "px")
                .style("opacity", 1);

            // Hide the standard tooltip.
            tooltip.style("opacity", 0);
        } else {
            // Build standard tooltip content.
            const lines = [
                `<strong>${d.label}</strong>`,
                `Type: ${d.entity_type}`,
                `Status: ${d.attribution_status}`,
                `Confidence: ${((d.attribution_confidence || 0) * 100).toFixed(0)}%`,
                `Signals: ${d.collector_count || 0}`,
            ];
            if (d.first_observed) {
                lines.push(`First seen: ${d.first_observed.substring(0, 19)}`);
            }

            tooltip
                .html(lines.join("<br>"))
                .style("left", `${event.offsetX + 14}px`)
                .style("top", `${event.offsetY - 10}px`)
                .style("opacity", 1);

            // Hide deru-kui tooltip if visible.
            if (deruKuiTooltip) deruKuiTooltip.style("opacity", 0);
        }
    }

    function onNodeHoverOut() {
        linkGroup.selectAll("line").attr("stroke-opacity", 0.25);
        tooltip.style("opacity", 0);
        if (deruKuiTooltip) deruKuiTooltip.style("opacity", 0);
    }

    function onNodeClick(_event, d) {
        const detail = { ...d };
        // Remove D3 simulation fields from dispatched data.
        delete detail.x;
        delete detail.y;
        delete detail.vx;
        delete detail.vy;
        delete detail.fx;
        delete detail.fy;
        delete detail.index;
        window.dispatchEvent(
            new CustomEvent("expose:node-selected", { detail })
        );
    }

    // --- Render — D3 general update pattern (enter / update / exit) -------

    function render(nodes, edges, isInit) {

        // ---- Edges ----
        const links = linkGroup.selectAll("line")
            .data(edges, (d) => `${d.source.id || d.source}-${d.target.id || d.target}`);

        // Exit.
        links.exit()
            .transition().duration(FADEOUT_DURATION)
            .attr("stroke-opacity", 0)
            .remove();

        // Enter.
        const linksEnter = links.enter()
            .append("line")
            .attr("stroke", linkColor)
            .attr("stroke-width", 1)
            .attr("stroke-opacity", 0);

        if (!isInit) {
            // Edge draw-in: stroke-dasharray trick.
            linksEnter.each(function () {
                const el = d3.select(this);
                const len = 200; // generous estimate
                el.attr("stroke-dasharray", `${len} ${len}`)
                  .attr("stroke-dashoffset", len)
                  .transition().duration(EDGE_DRAW_DURATION)
                  .attr("stroke-dashoffset", 0)
                  .attr("stroke-opacity", 0.25)
                  .on("end", function () {
                      d3.select(this).attr("stroke-dasharray", null);
                  });
            });
        } else {
            linksEnter.attr("stroke-opacity", 0.25);
        }

        // Update (merge).
        linksEnter.merge(links).attr("stroke-width", 1);

        // ---- Nodes ----
        const circles = nodeGroup.selectAll("circle")
            .data(nodes, (d) => d.id);

        // Exit — fade out (not-yours or removed).
        circles.exit()
            .transition().duration(FADEOUT_DURATION)
            .attr("r", 0)
            .attr("opacity", 0)
            .remove();

        // Enter — emerge animation.
        const circlesEnter = circles.enter()
            .append("circle")
            .attr("r", 0)
            .attr("fill", nodeColor)
            .attr("opacity", 0)
            .attr("filter", nodeFilter)
            .attr("cursor", "pointer")
            .call(drag())
            .on("mouseenter", onNodeHover)
            .on("mousemove", onNodeHover)
            .on("mouseleave", onNodeHoverOut)
            .on("click", onNodeClick);

        if (!isInit) {
            circlesEnter
                .transition().duration(EMERGE_DURATION)
                .attr("r", nodeRadius)
                .attr("opacity", (d) => d.highest_risk ? 1 : nodeOpacity(d));
        } else {
            circlesEnter
                .attr("r", nodeRadius)
                .attr("opacity", (d) => d.highest_risk ? 1 : nodeOpacity(d));
        }

        // Update — attribution changes (smooth transition).
        circles
            .classed("expose-pulse", (d) => d.attribution_status === "requires_review")
            .classed("deru-kui", (d) => d.highest_risk === true)
            .transition().duration(CHANGE_DURATION)
            .attr("r", nodeRadius)
            .attr("fill", nodeColor)
            .attr("opacity", (d) => d.highest_risk ? 1 : nodeOpacity(d))
            .attr("filter", nodeFilter);

        // Merge enter + update for tick positioning.
        circlesEnter.merge(circles);

        // Apply pulse / deru-kui classes on entering nodes too.
        circlesEnter
            .classed("expose-pulse", (d) => d.attribution_status === "requires_review")
            .classed("deru-kui", (d) => d.highest_risk === true);

        // ---- Labels ----
        const labels = labelGroup.selectAll("text")
            .data(
                nodes.filter((d) => LABELED_STATUSES.has(d.attribution_status)),
                (d) => d.id,
            );

        labels.exit()
            .transition().duration(FADEOUT_DURATION)
            .attr("opacity", 0)
            .remove();

        const labelsEnter = labels.enter()
            .append("text")
            .text((d) => d.label)
            .attr("font-family", "monospace")
            .attr("font-size", "12px")
            .attr("text-anchor", "middle")
            .attr("fill", (d) => nodeColor(d))
            .attr("opacity", 0)
            .attr("pointer-events", "none");

        if (!isInit) {
            labelsEnter
                .transition().duration(EMERGE_DURATION)
                .attr("opacity", (d) => nodeOpacity(d) * 0.7);
        } else {
            labelsEnter
                .attr("opacity", (d) => nodeOpacity(d) * 0.7);
        }

        // Update existing labels on attribution change.
        labels
            .transition().duration(CHANGE_DURATION)
            .attr("fill", (d) => nodeColor(d))
            .attr("opacity", (d) => nodeOpacity(d) * 0.7);
    }

    // --- CSS injection — pulse animation for requires_review ---------------

    function injectStyles() {
        if (document.getElementById("expose-graph-styles")) return;
        const style = document.createElement("style");
        style.id = "expose-graph-styles";
        style.textContent = `
            @keyframes expose-pulse-glow {
                0%, 100% { filter: url(#expose-glow); opacity: 0.7; }
                50%      { filter: url(#expose-blur-0); opacity: 1.0; }
            }
            .expose-pulse {
                animation: expose-pulse-glow 2s ease-in-out infinite;
            }
        `;
        document.head.appendChild(style);
    }

    // --- Public API ---------------------------------------------------------

    /** Initialise the graph inside the given DOM selector. */
    function init(selector, opts = {}) {
        injectStyles();
        buildSvg(selector, opts);
    }

    /** Progressive data update — diffs + darkroom animations. */
    function updateData(data) {
        if (!svg) {
            throw new Error("ExposeGraph.init() must be called before updateData().");
        }

        const incomingNodes = data.nodes || [];
        const incomingEdges = data.edges || [];
        const isInit = nodeMap.size === 0;

        // ---- Diff nodes ----
        const incomingIds = new Set(incomingNodes.map((n) => n.id));
        const currentIds  = new Set(nodeMap.keys());

        // Nodes to remove (present now, absent in incoming data).
        for (const id of currentIds) {
            if (!incomingIds.has(id)) {
                nodeMap.delete(id);
            }
        }

        // Add new and update existing.
        for (const n of incomingNodes) {
            if (nodeMap.has(n.id)) {
                // Preserve simulation position, update data fields.
                const existing = nodeMap.get(n.id);
                Object.assign(existing, n, {
                    x: existing.x,
                    y: existing.y,
                    vx: existing.vx,
                    vy: existing.vy,
                });
            } else {
                // New node — random initial position near center.
                n.x = width / 2 + (Math.random() - 0.5) * 80;
                n.y = height / 2 + (Math.random() - 0.5) * 80;
                nodeMap.set(n.id, n);
            }
        }

        const nodes = Array.from(nodeMap.values());
        edgeData = incomingEdges;

        // ---- Simulation ----
        if (isInit) {
            createSimulation(nodes, edgeData);
        } else {
            // Restart with merged data.
            simulation.nodes(nodes);
            simulation.force("link").links(edgeData);
            simulation.alpha(0.5).restart();
        }

        // ---- Render ----
        render(nodes, edgeData, isInit);

        // Re-apply any active filters to newly rendered elements.
        applyFilters();
    }

    /** Tear down graph, stop simulation, remove DOM elements. */
    function destroy() {
        if (simulation) { simulation.stop(); simulation = null; }
        if (svg) { svg.remove(); svg = null; }
        if (tooltip) { tooltip.remove(); tooltip = null; }
        if (deruKuiTooltip) { deruKuiTooltip.remove(); deruKuiTooltip = null; }
        nodeMap.clear();
        edgeData = [];
        filterChangeListeners = [];
        container = linkGroup = nodeGroup = labelGroup = null;
    }

    // --- Public filter API --------------------------------------------------

    /**
     * Update one or more filter dimensions and re-apply visibility.
     * Accepts a partial filter object — only the provided keys are merged.
     *
     * @param {object} filters  Partial filter update:
     *   - entityTypes:      string[]  (replaces the set)
     *   - edgeTypes:        string[]  (replaces the set)
     *   - attributionTiers: string[]  (replaces the set)
     *   - minConfidence:    number    (0.0 – 1.0)
     */
    function setFilters(filters) {
        if (filters.entityTypes != null) {
            activeFilters.entityTypes = new Set(filters.entityTypes);
        }
        if (filters.edgeTypes != null) {
            activeFilters.edgeTypes = new Set(filters.edgeTypes);
        }
        if (filters.attributionTiers != null) {
            activeFilters.attributionTiers = new Set(filters.attributionTiers);
        }
        if (filters.minConfidence != null) {
            activeFilters.minConfidence = filters.minConfidence;
        }
        applyFilters();
    }

    /**
     * Read the current filter state (returns a plain-object snapshot).
     * @returns {object}
     */
    function getFilters() {
        return {
            entityTypes:      Array.from(activeFilters.entityTypes),
            edgeTypes:        Array.from(activeFilters.edgeTypes),
            attributionTiers: Array.from(activeFilters.attributionTiers),
            minConfidence:    activeFilters.minConfidence,
        };
    }

    /**
     * Register a callback invoked after every filter application.
     * Signature: callback(visibleNodeCount, visibleEdgeCount)
     *
     * @param {function} fn
     */
    function onFilterChange(fn) {
        if (typeof fn === "function") {
            filterChangeListeners.push(fn);
        }
    }

    return Object.freeze({
        init,
        updateData,
        destroy,
        setFilters,
        getFilters,
        onFilterChange,
        applyFilters,
    });
})();
