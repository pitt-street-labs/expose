/**
 * EXPOSE Dashboard — client-side initialization.
 *
 * Alpine.js data store for UI state, HTMX SSE configuration,
 * and D3.js observation graph placeholder.
 *
 * Progressive enhancement: the page renders meaningful content
 * without JavaScript; this script adds interactivity on top.
 */

/* =========================================================================
   Alpine.js application state
   ========================================================================= */

/**
 * Root Alpine component for the EXPOSE dashboard.
 * Manages tenant selection, active run tracking, entity filtering,
 * and graph layout state.
 */
function exposeApp() {
    return {
        // Tenant selection
        selectedTenantId: "",

        // Active run tracking
        activeRunId: null,

        // Entity filtering
        entityFilter: "",
        entityCount: 0,

        // Graph layout mode
        graphLayout: "force",

        /**
         * Handle tenant selection change.
         * Updates HTMX polling targets and resets graph state.
         */
        onTenantChange() {
            if (!this.selectedTenantId) {
                this.entityCount = 0;
                this.activeRunId = null;
                return;
            }

            // Trigger HTMX reload of entity list for the new tenant
            var entityList = document.getElementById("entity-list");
            if (entityList && typeof htmx !== "undefined") {
                htmx.ajax("GET", "/partials/entities?tenant_id=" + this.selectedTenantId, {
                    target: "#entity-list",
                    swap: "innerHTML",
                });
            }
        },

        /**
         * Initialize on mount — read any pre-set values from the DOM.
         */
        init() {
            // Listen for HTMX events to update entity count
            document.addEventListener("htmx:afterSwap", function (event) {
                if (event.detail.target && event.detail.target.id === "entity-list") {
                    var rows = event.detail.target.querySelectorAll(".entity-row");
                    // Update entity count via Alpine's reactivity
                    var appEl = document.querySelector("[x-data]");
                    if (appEl && appEl.__x) {
                        appEl.__x.$data.entityCount = rows.length;
                    }
                }
            });
        },
    };
}


/* =========================================================================
   HTMX Configuration
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    // Configure HTMX defaults
    if (typeof htmx !== "undefined") {
        htmx.config.defaultSwapStyle = "innerHTML";
        htmx.config.historyCacheSize = 0;

        // Log HTMX errors for debugging
        document.addEventListener("htmx:responseError", function (event) {
            console.error("[EXPOSE] HTMX error:", event.detail.xhr.status, event.detail.pathInfo.requestPath);
        });

        // SSE extension configuration for real-time updates.
        // The SSE endpoint will be at /v1/tenants/{tenant_id}/events
        // when wired to the NATS broker (future implementation).
        htmx.config.wsReconnectDelay = "full-jitter";
    }
});


/* =========================================================================
   D3.js Observation Graph — placeholder
   ========================================================================= */

/**
 * Initialize the observation graph within the given container element.
 * This is a placeholder that draws the empty SVG canvas with grid lines;
 * the full force-directed graph renderer is handled by a separate agent.
 *
 * @param {string} containerId - DOM id of the graph container
 */
function initObservationGraph(containerId) {
    var container = document.getElementById(containerId);
    if (!container || typeof d3 === "undefined") {
        return;
    }

    var rect = container.getBoundingClientRect();
    var width = rect.width;
    var height = rect.height;

    // Clear any existing SVG
    d3.select("#" + containerId).select("svg").remove();

    var svg = d3
        .select("#" + containerId)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height])
        .style("background", "transparent");

    // Subtle grid pattern
    var defs = svg.append("defs");

    var gridPattern = defs
        .append("pattern")
        .attr("id", "grid")
        .attr("width", 40)
        .attr("height", 40)
        .attr("patternUnits", "userSpaceOnUse");

    gridPattern
        .append("path")
        .attr("d", "M 40 0 L 0 0 0 40")
        .attr("fill", "none")
        .attr("stroke", "rgba(30, 32, 53, 0.5)")
        .attr("stroke-width", "0.5");

    svg.append("rect").attr("width", width).attr("height", height).attr("fill", "url(#grid)");

    // Center crosshair — faint reference point
    var centerGroup = svg
        .append("g")
        .attr("transform", "translate(" + width / 2 + "," + height / 2 + ")")
        .attr("opacity", 0.15);

    centerGroup
        .append("circle")
        .attr("r", 60)
        .attr("fill", "none")
        .attr("stroke", "#6366f1")
        .attr("stroke-width", 0.5)
        .attr("stroke-dasharray", "4,4");

    centerGroup
        .append("circle")
        .attr("r", 3)
        .attr("fill", "#6366f1");

    // Store svg reference for the full graph renderer to use
    container._exposeSvg = svg;
    container._exposeWidth = width;
    container._exposeHeight = height;
}


/* =========================================================================
   Resize observer — keeps the graph SVG in sync with container size
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    var graphContainer = document.getElementById("observation-graph");
    if (graphContainer && typeof ResizeObserver !== "undefined") {
        var resizeTimer = null;
        var observer = new ResizeObserver(function () {
            // Debounce to avoid excessive redraws
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                initObservationGraph("observation-graph");
            }, 200);
        });
        observer.observe(graphContainer);
    }
});
