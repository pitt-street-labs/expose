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

        // SSE connection — EventSource instance for live run events
        _eventSource: null,

        // SSE connection status for UI display
        sseConnected: false,

        // Tenant config panel
        showConfigPanel: false,
        tenantConfig: null,
        configSaving: false,
        configMessage: "",

        // CSV export state
        exportFilter: { entityType: "", tier: "", collector: "", environment: "" },
        exporting: false,

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

            // Disconnect SSE from previous tenant/run
            this.disconnectSSE();

            // Reset config panel
            this.showConfigPanel = false;
            this.tenantConfig = null;
            this.configMessage = "";

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

        /* ==================================================================
           SSE Live Updates — EventSource management
           ================================================================== */

        /**
         * Connect to the SSE endpoint for the active run.
         * Receives typed events (entities_discovered, collector_completed,
         * run_completed) and refreshes the relevant UI sections in real-time
         * instead of relying solely on polling.
         *
         * Auto-disconnects on run_completed or on error after 3 retries.
         */
        connectSSE() {
            var self = this;

            if (!this.selectedTenantId || !this.activeRunId) {
                return;
            }

            // Tear down any existing connection first
            this.disconnectSSE();

            var url = "/v1/tenants/" + this.selectedTenantId +
                      "/runs/" + this.activeRunId + "/events";

            var es = new EventSource(url);
            this._eventSource = es;
            this._sseRetryCount = 0;

            es.onopen = function () {
                self.sseConnected = true;
                self._sseRetryCount = 0;
                console.info("[EXPOSE] SSE connected:", url);
            };

            // --- Typed event handlers ---

            // entities_discovered: refresh entity table + graph immediately
            es.addEventListener("entities_discovered", function (evt) {
                self._onEntitiesDiscovered(evt);
            });

            // collector_completed: refresh run status bar
            es.addEventListener("collector_completed", function (evt) {
                self._onCollectorCompleted(evt);
            });

            // collector_started: informational log
            es.addEventListener("collector_started", function (evt) {
                console.info("[EXPOSE] SSE: collector_started", evt.data);
            });

            // collector_failed: log warning, refresh status
            es.addEventListener("collector_failed", function (evt) {
                console.warn("[EXPOSE] SSE: collector_failed", evt.data);
                self._refreshRunStatus();
            });

            // attribution_updated: refresh entity table + graph
            es.addEventListener("attribution_updated", function (evt) {
                self._refreshEntityTable();
                fetchGraphData(self.selectedTenantId);
            });

            // run_completed: final refresh, disconnect
            es.addEventListener("run_completed", function (evt) {
                self._onRunCompleted(evt);
            });

            // Generic error handler — reconnect up to 3 times
            es.onerror = function () {
                self.sseConnected = false;
                self._sseRetryCount = (self._sseRetryCount || 0) + 1;
                if (self._sseRetryCount >= 3) {
                    console.warn("[EXPOSE] SSE: max retries reached, falling back to polling");
                    self.disconnectSSE();
                } else {
                    console.warn("[EXPOSE] SSE: connection error, retry " + self._sseRetryCount + "/3");
                }
            };
        },

        /**
         * Disconnect the SSE EventSource cleanly.
         * Idempotent — safe to call even if no connection exists.
         */
        disconnectSSE() {
            if (this._eventSource) {
                this._eventSource.close();
                this._eventSource = null;
            }
            this.sseConnected = false;
            this._sseRetryCount = 0;
        },

        /**
         * Handle entities_discovered SSE event.
         * Triggers an immediate refresh of the entity table and graph.
         */
        _onEntitiesDiscovered: function (evt) {
            try {
                var payload = JSON.parse(evt.data);
                var count = (payload.data && payload.data.entities)
                    ? payload.data.entities.length
                    : 0;
                console.info("[EXPOSE] SSE: entities_discovered (" + count + " new)");
            } catch (_e) {
                // Non-critical — refresh regardless
            }
            this._refreshEntityTable();
            fetchGraphData(this.selectedTenantId);
        },

        /**
         * Handle collector_completed SSE event.
         * Refreshes the run status bar to show updated stage progress.
         */
        _onCollectorCompleted: function (evt) {
            try {
                var payload = JSON.parse(evt.data);
                var cid = (payload.data && payload.data.collector_id) || "unknown";
                console.info("[EXPOSE] SSE: collector_completed — " + cid);
            } catch (_e) {
                // Non-critical
            }
            this._refreshRunStatus();
            this._refreshEntityTable();
            fetchGraphData(this.selectedTenantId);
        },

        /**
         * Handle run_completed SSE event.
         * Performs a final refresh of all data, disconnects SSE, and clears
         * the active run ID.
         */
        _onRunCompleted: function (evt) {
            console.info("[EXPOSE] SSE: run_completed — final refresh");

            // Final data refresh
            this._refreshEntityTable();
            this._refreshRunStatus();
            fetchGraphData(this.selectedTenantId);

            // Refresh AI insights if the component exists
            var aiPanel = document.querySelector("[x-data='aiInsights()']");
            if (aiPanel && aiPanel.__x) {
                aiPanel.__x.$data.fetchInsights(this.selectedTenantId);
            }

            // Clean disconnect
            this.disconnectSSE();

            // Clear active run (with a short delay so the final status renders)
            var self = this;
            setTimeout(function () {
                self.activeRunId = null;
            }, 2000);
        },

        /**
         * Trigger an HTMX refresh of the entity table partial.
         */
        _refreshEntityTable: function () {
            var entityList = document.getElementById("entity-list");
            if (entityList && typeof htmx !== "undefined" && this.selectedTenantId) {
                htmx.ajax("GET", "/partials/entities?tenant_id=" + this.selectedTenantId, {
                    target: "#entity-list",
                    swap: "innerHTML",
                });
            }
        },

        /**
         * Trigger an HTMX refresh of the run status bar partial.
         */
        _refreshRunStatus: function () {
            if (!this.activeRunId) return;
            var statusBar = document.querySelector(".status-bar");
            if (statusBar && typeof htmx !== "undefined") {
                htmx.ajax("GET", "/partials/run-status/" + this.activeRunId, {
                    target: ".status-bar",
                    swap: "innerHTML",
                });
            }
        },

        /* ==================================================================
           Tenant Configuration Management
           ================================================================== */

        /**
         * Fetch the tenant configuration from the API.
         * Populates this.tenantConfig for the config panel form.
         */
        async loadTenantConfig() {
            if (!this.selectedTenantId) return;
            this.configMessage = "";
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/config/"
                );
                if (!resp.ok) {
                    this.configMessage = "Failed to load config (HTTP " + resp.status + ")";
                    return;
                }
                var data = await resp.json();
                // Convert the frozen API response to a mutable form-state object
                this.tenantConfig = {
                    scope_rules: (data.scope_rules || []).map(function (r) {
                        return { rule_type: r.rule_type, value: r.value, is_exclusion: r.is_exclusion || false };
                    }),
                    enabled_collectors: data.enabled_collectors || [],
                    schedule_cron: data.schedule_cron || "",
                    egress_profile: data.egress_profile || "direct",
                    llm_enabled: data.llm_enabled || false,
                    llm_provider: data.llm_provider || "",
                    llm_cost_ceiling_per_run: data.llm_cost_ceiling_per_run || 0,
                };
            } catch (e) {
                this.configMessage = "Error loading config: " + e.message;
                console.error("[EXPOSE] Config load error:", e);
            }
        },

        /**
         * PATCH the tenant configuration to the API.
         * Only sends fields that differ from defaults (PATCH semantics).
         */
        async saveTenantConfig() {
            if (!this.selectedTenantId || !this.tenantConfig) return;
            this.configSaving = true;
            this.configMessage = "";

            try {
                var body = {
                    scope_rules: this.tenantConfig.scope_rules,
                    enabled_collectors: this.tenantConfig.enabled_collectors,
                    schedule_cron: this.tenantConfig.schedule_cron || null,
                    egress_profile: this.tenantConfig.egress_profile,
                    llm_enabled: this.tenantConfig.llm_enabled,
                    llm_provider: this.tenantConfig.llm_provider || null,
                    llm_cost_ceiling_per_run: this.tenantConfig.llm_cost_ceiling_per_run,
                };

                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/config/",
                    {
                        method: "PATCH",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(body),
                    }
                );

                if (!resp.ok) {
                    var errText = await resp.text();
                    this.configMessage = "Save failed (" + resp.status + "): " + errText;
                } else {
                    this.configMessage = "Configuration saved.";
                    // Refresh to pick up server-side changes (e.g. updated_at)
                    await this.loadTenantConfig();
                }
            } catch (e) {
                this.configMessage = "Error saving config: " + e.message;
                console.error("[EXPOSE] Config save error:", e);
            }
            this.configSaving = false;
        },

        /**
         * Add a new empty scope rule to the config form.
         */
        addScopeRule() {
            if (!this.tenantConfig) return;
            this.tenantConfig.scope_rules.push({
                rule_type: "apex_domain",
                value: "",
                is_exclusion: false,
            });
        },

        /**
         * Remove a scope rule by index.
         */
        removeScopeRule(index) {
            if (!this.tenantConfig) return;
            this.tenantConfig.scope_rules.splice(index, 1);
        },

        /**
         * Toggle a collector ID in the enabled_collectors list.
         */
        toggleCollector(collectorId) {
            if (!this.tenantConfig) return;
            var idx = this.tenantConfig.enabled_collectors.indexOf(collectorId);
            if (idx >= 0) {
                this.tenantConfig.enabled_collectors.splice(idx, 1);
            } else {
                this.tenantConfig.enabled_collectors.push(collectorId);
            }
        },

        /* ==================================================================
           CSV Export
           ================================================================== */

        /**
         * Download filtered entities as a CSV file.
         * Builds query params from exportFilter state, fetches from the
         * export API, and triggers a browser download via a temporary
         * object URL.
         */
        downloadCsv() {
            this.exporting = true;
            var self = this;
            var params = new URLSearchParams();
            if (this.exportFilter.entityType) {
                params.set("entity_type", this.exportFilter.entityType);
            }
            if (this.exportFilter.tier) {
                params.set("attribution_tier", this.exportFilter.tier);
            }
            if (this.exportFilter.collector) {
                params.set("collector_id", this.exportFilter.collector);
            }
            if (this.exportFilter.environment) {
                params.set("environment", this.exportFilter.environment);
            }

            var url = "/v1/tenants/" + this.selectedTenantId + "/export/csv?" + params.toString();

            fetch(url)
                .then(function (r) {
                    if (!r.ok) {
                        console.error("[EXPOSE] CSV export failed:", r.status);
                        return null;
                    }
                    return r.blob();
                })
                .then(function (blob) {
                    if (!blob) return;
                    var a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "expose-export-" + new Date().toISOString().slice(0, 10) + ".csv";
                    a.click();
                    URL.revokeObjectURL(a.href);
                })
                .catch(function (err) {
                    console.error("[EXPOSE] CSV export error:", err.message);
                })
                .finally(function () {
                    self.exporting = false;
                });
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

                // Set activeRunId on the parent app component and connect SSE
                var appEl = document.querySelector("[x-data]");
                if (appEl && appEl.__x) {
                    appEl.__x.$data.activeRunId = data.run_id;
                    // Connect SSE for real-time event streaming
                    appEl.__x.$data.connectSSE();
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
