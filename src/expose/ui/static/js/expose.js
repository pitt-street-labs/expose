/**
 * EXPOSE Dashboard — client-side initialization.
 *
 * Alpine.js data store for UI state, HTMX SSE configuration,
 * D3.js observation graph wiring, and scan trigger form.
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
 * graph layout state, and graph data polling.
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

        // Graph polling interval handle
        _graphPollHandle: null,

        // Graph initialization flag
        _graphInitialized: false,

        /**
         * Handle tenant selection change.
         * Updates HTMX polling targets, resets graph state, and starts
         * graph data polling for the selected tenant.
         */
        onTenantChange() {
            // Stop any existing graph poll
            if (this._graphPollHandle) {
                clearInterval(this._graphPollHandle);
                this._graphPollHandle = null;
            }

            if (!this.selectedTenantId) {
                this.entityCount = 0;
                this.activeRunId = null;
                // Destroy graph when no tenant is selected
                if (typeof ExposeGraph !== "undefined" && this._graphInitialized) {
                    ExposeGraph.destroy();
                    this._graphInitialized = false;
                }
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

            // Initialize graph and start polling
            this._initGraphAndPoll();
        },

        /**
         * Initialize the D3 graph renderer and start polling the graph
         * API endpoint every 5 seconds.
         */
        _initGraphAndPoll() {
            var self = this;
            var containerId = "observation-graph";
            var container = document.getElementById(containerId);

            if (!container || typeof ExposeGraph === "undefined" || typeof d3 === "undefined") {
                return;
            }

            // Initialize graph if not yet done (or re-init on tenant switch)
            if (this._graphInitialized) {
                ExposeGraph.destroy();
            }

            var rect = container.getBoundingClientRect();
            ExposeGraph.init("#" + containerId, {
                width: Math.max(rect.width, 400),
                height: Math.max(rect.height, 300),
            });
            this._graphInitialized = true;

            // Fetch immediately, then poll every 5 seconds
            fetchGraphData(self.selectedTenantId);
            this._graphPollHandle = setInterval(function () {
                if (self.selectedTenantId) {
                    fetchGraphData(self.selectedTenantId);
                }
            }, 5000);
        },

        /**
         * Initialize on mount — read any pre-set values from the DOM.
         */
        init() {
            var self = this;

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

            // If a tenant is already selected (e.g. page reload), kick off graph
            if (this.selectedTenantId) {
                // Defer to allow DOM to settle
                setTimeout(function () {
                    self._initGraphAndPoll();
                }, 100);
            }
        },
    };
}


/* =========================================================================
   Scan Form — Alpine.js component
   ========================================================================= */

/**
 * Alpine component for the scan trigger form.
 * Posts to the runs API to start a new pipeline run.
 */
function scanForm() {
    return {
        seed: "",
        scanning: false,
        statusMessage: "",

        /**
         * Submit the scan request to the runs API.
         * Reads the selected tenant ID from the parent exposeApp component.
         */
        async submitScan() {
            if (!this.seed.trim()) {
                this.statusMessage = "Enter a seed value (domain, IP, or CIDR).";
                return;
            }

            // Read tenant ID from the tenant selector
            var tenantSelect = document.getElementById("tenant-select");
            var tenantId = tenantSelect ? tenantSelect.value : "";
            if (!tenantId) {
                this.statusMessage = "Select a tenant first.";
                return;
            }

            this.scanning = true;
            this.statusMessage = "Starting scan...";

            try {
                var resp = await fetch("/v1/tenants/" + tenantId + "/runs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        seeds: [this.seed.trim()],
                        collector_ids: null,
                    }),
                });

                if (!resp.ok) {
                    var errBody = await resp.text();
                    this.statusMessage = "Error " + resp.status + ": " + errBody;
                    this.scanning = false;
                    return;
                }

                var data = await resp.json();
                this.statusMessage = "Run " + data.run_id + " started (" + data.state + ")";

                // Set activeRunId on the parent app component
                var appEl = document.querySelector("[x-data]");
                if (appEl && appEl.__x) {
                    appEl.__x.$data.activeRunId = data.run_id;
                }
            } catch (e) {
                this.statusMessage = "Error: " + e.message;
            }

            this.scanning = false;
        },
    };
}


/* =========================================================================
   Graph Data Fetching
   ========================================================================= */

/**
 * Fetch observation graph data from the API and feed it to the D3 renderer.
 * Marks the node with the highest lead_score with a data attribute for
 * downstream risk highlighting (Wave 3 Agent F1 hook).
 *
 * @param {string} tenantId - UUID of the tenant
 */
function fetchGraphData(tenantId) {
    if (!tenantId || typeof ExposeGraph === "undefined") {
        return;
    }

    fetch("/v1/tenants/" + tenantId + "/graph")
        .then(function (r) {
            if (!r.ok) {
                console.warn("[EXPOSE] Graph fetch failed:", r.status);
                return null;
            }
            return r.json();
        })
        .then(function (data) {
            if (!data) {
                return;
            }

            var nodes = data.nodes || [];
            var edges = data.edges || [];

            // --- Highest-risk node marking ---
            // Find the node with the highest lead_score (or attribution_confidence
            // as fallback). Mark it with a data attribute so Wave 3 Agent F1 can
            // apply red highlighting via CSS [data-highest-risk="true"].
            var highestIdx = -1;
            var highestScore = -1;

            for (var i = 0; i < nodes.length; i++) {
                var score = nodes[i].lead_score != null
                    ? nodes[i].lead_score
                    : (nodes[i].attribution_confidence || 0);
                if (score > highestScore) {
                    highestScore = score;
                    highestIdx = i;
                }
            }

            // Reset all, then mark the winner
            for (var j = 0; j < nodes.length; j++) {
                nodes[j].highest_risk = false;
            }
            if (highestIdx >= 0 && nodes.length > 0) {
                nodes[highestIdx].highest_risk = true;
            }

            // Feed data to D3 renderer
            try {
                ExposeGraph.updateData({ nodes: nodes, edges: edges });
            } catch (e) {
                console.error("[EXPOSE] Graph update error:", e.message);
            }

            // Apply data-highest-risk attribute to the corresponding SVG circle
            // after a short delay to let D3 render the enter selection.
            setTimeout(function () {
                var graphContainer = document.getElementById("observation-graph");
                if (!graphContainer) return;
                var circles = graphContainer.querySelectorAll("circle");
                circles.forEach(function (circle) {
                    circle.removeAttribute("data-highest-risk");
                });
                if (highestIdx >= 0 && nodes[highestIdx]) {
                    // D3 keyed by id — find the circle whose __data__.id matches
                    circles.forEach(function (circle) {
                        if (circle.__data__ && circle.__data__.id === nodes[highestIdx].id) {
                            circle.setAttribute("data-highest-risk", "true");
                        }
                    });
                }
            }, 100);
        })
        .catch(function (err) {
            console.error("[EXPOSE] Graph fetch error:", err.message);
        });
}

// Store reference globally so graph.js and other scripts can call it
window.fetchGraphData = fetchGraphData;


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
   Resize observer — reinitializes graph on container resize
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    var graphContainer = document.getElementById("observation-graph");
    if (graphContainer && typeof ResizeObserver !== "undefined") {
        var resizeTimer = null;
        var observer = new ResizeObserver(function () {
            // Debounce to avoid excessive redraws
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                // Only reinitialize if ExposeGraph is active; the old
                // placeholder initObservationGraph is no longer needed
                // since ExposeGraph.init handles the full renderer.
                var appEl = document.querySelector("[x-data]");
                if (appEl && appEl.__x && appEl.__x.$data._graphInitialized) {
                    appEl.__x.$data._initGraphAndPoll();
                }
            }, 200);
        });
        observer.observe(graphContainer);
    }
});
