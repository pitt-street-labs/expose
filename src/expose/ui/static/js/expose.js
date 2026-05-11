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
        tenants: [],
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
        _configLoaded: false,
        tenantConfig: {
            scope_rules: [],
            enabled_collectors: [],
            schedule_cron: "",
            egress_profile: "direct",
            egress_fallbacks: [],
            socks5_proxy: "",
            llm_enabled: false,
            llm_provider: "",
            llm_model: "",
            llm_cost_ceiling_per_run: 10.0,
        },
        configSaving: false,
        configMessage: "",

        // CSV export state
        exportFilter: { entityType: "", tier: "", collector: "", environment: "" },
        exporting: false,

        // Credential management panel
        showCredentialsPanel: false,
        _credentialsLoaded: false,
        credentialSlots: [],
        credentialConfiguredCount: 0,
        credentialTotalCount: 0,
        credentialMessage: "",
        showSfImportModal: false,
        showBundleImportModal: false,
        sfImportText: "",
        bundleImportText: "",

        // Scan elapsed timer
        _scanStartTime: null,
        _scanElapsedHandle: null,
        scanElapsed: 0,

        // Scan log panel
        showScanLog: true,
        scanLogEntries: [],
        scanLogPolling: false,
        _scanLogPollHandle: null,
        _scanLogSince: 0,

        // Priority findings from lead scoring
        showFindingsPanel: true,
        findings: [],

        // Supply chain providers
        showProvidersPanel: false,
        providers: [],

        // Provenance chain data for the selected entity
        provenanceData: null,

        // Summary stats for at-a-glance risk posture
        stats: {
            totalEntities: 0,
            confirmedThreats: 0,
            highRisk: 0,
            collectors: 0,
            lastScan: '--',
            nonProduction: 0,
        },

        /**
         * Fetch the list of tenants from the API and populate the
         * tenant selector dropdown.  Called once during init().
         */
        async loadTenants() {
            try {
                var resp = await fetch("/v1/tenants/");
                if (!resp.ok) {
                    console.error("[EXPOSE] Failed to load tenants:", resp.status);
                    return;
                }
                var data = await resp.json();
                this.tenants = data.tenants || [];
            } catch (e) {
                console.error("[EXPOSE] Error loading tenants:", e);
            }
        },

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

            // Stop scan log polling and clear entries
            this.stopScanLogPolling();
            this.stopScanTimer();
            this.scanLogEntries = [];
            this._scanLogSince = 0;

            // Reset config panel
            this.showConfigPanel = false;
            this._configLoaded = false;
            this.tenantConfig = {
                scope_rules: [],
                enabled_collectors: [],
                schedule_cron: "",
                egress_profile: "direct",
                egress_fallbacks: [],
                socks5_proxy: "",
                llm_enabled: false,
                llm_provider: "",
                llm_model: "",
                llm_cost_ceiling_per_run: 10.0,
            };
            this.configMessage = "";

            // Reset credentials panel
            this.showCredentialsPanel = false;
            this._credentialsLoaded = false;
            this.credentialSlots = [];
            this.credentialMessage = "";
            this.showSfImportModal = false;
            this.showBundleImportModal = false;

            // Reset provenance panel
            this.provenanceData = null;

            if (!this.selectedTenantId) {
                this.entityCount = 0;
                this.activeRunId = null;
                // Reset findings and providers
                this.findings = [];
                this.providers = [];
                this.showProvidersPanel = false;
                // Reset summary stats
                this.stats = {
                    totalEntities: 0,
                    confirmedThreats: 0,
                    highRisk: 0,
                    collectors: 0,
                    lastScan: '--',
                    nonProduction: 0,
                };
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

            // Load summary stats for the at-a-glance panel
            this.loadStats();

            // Load priority findings
            this.loadFindings();

            // Load supply chain providers
            this.loadProviders();
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
                // Start scan log polling if not already active
                if (!self.scanLogPolling) {
                    self.startScanLogPolling();
                }
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

            // Final scan log fetch before stopping polling
            this._pollScanLog();
            this.stopScanLogPolling();

            // Stop elapsed timer
            this.stopScanTimer();

            // Final data refresh
            this._refreshEntityTable();
            this._refreshRunStatus();
            fetchGraphData(this.selectedTenantId);

            // Refresh summary stats after run completion
            this.loadStats();

            // Refresh priority findings after run completion
            this.loadFindings();

            // Refresh supply chain providers after run completion
            this.loadProviders();

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

            // Auto-collapse the scan log panel after 8 seconds of idle.
            // The panel stays visible (scanLogEntries.length > 0) but
            // collapsed so stale log output doesn't dominate the view.
            setTimeout(function () {
                if (!self.activeRunId) {
                    self.showScanLog = false;
                }
            }, 8000);
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
                    egress_fallbacks: data.egress_fallbacks || [],
                    socks5_proxy: data.socks5_proxy || "",
                    llm_enabled: data.llm_enabled || false,
                    llm_provider: data.llm_provider || "",
                    llm_model: data.llm_model || "",
                    llm_cost_ceiling_per_run: data.llm_cost_ceiling_per_run || 0,
                };
                this._configLoaded = true;
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
                    egress_fallbacks: this.tenantConfig.egress_fallbacks,
                    socks5_proxy: this.tenantConfig.socks5_proxy || null,
                    llm_enabled: this.tenantConfig.llm_enabled,
                    llm_provider: this.tenantConfig.llm_provider || null,
                    llm_model: this.tenantConfig.llm_model || null,
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

        /**
         * Toggle an egress profile in the egress_fallbacks list.
         */
        toggleEgressFallback(profileId) {
            if (!this.tenantConfig) return;
            var idx = this.tenantConfig.egress_fallbacks.indexOf(profileId);
            if (idx >= 0) {
                this.tenantConfig.egress_fallbacks.splice(idx, 1);
            } else {
                this.tenantConfig.egress_fallbacks.push(profileId);
            }
        },

        /**
         * Apply sensible defaults when LLM enrichment is first enabled.
         * Sets provider to "gemini" if empty, cost ceiling to 1.00 if zero,
         * and clears model to use the provider default.
         */
        applyLlmDefaults() {
            if (!this.tenantConfig) return;
            if (!this.tenantConfig.llm_provider) {
                this.tenantConfig.llm_provider = "gemini";
            }
            if (!this.tenantConfig.llm_cost_ceiling_per_run || this.tenantConfig.llm_cost_ceiling_per_run <= 0) {
                this.tenantConfig.llm_cost_ceiling_per_run = 1.00;
            }
            // Leave llm_model empty to use provider default
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

        /* ==================================================================
           Credential Management
           ================================================================== */

        /**
         * Fetch credential slot statuses from the API.
         */
        async loadCredentials() {
            if (!this.selectedTenantId) return;
            this.credentialMessage = "";
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/credentials/"
                );
                if (!resp.ok) {
                    this.credentialMessage = "Failed to load credentials (HTTP " + resp.status + ")";
                    return;
                }
                var data = await resp.json();
                this.credentialSlots = data.slots || [];
                this.credentialConfiguredCount = data.configured_count || 0;
                this.credentialTotalCount = data.total_count || 0;
                this._credentialsLoaded = true;
            } catch (e) {
                this.credentialMessage = "Error loading credentials: " + e.message;
                console.error("[EXPOSE] Credentials load error:", e);
            }
        },

        /**
         * Test a credential by calling the test endpoint.
         */
        async testCredential(credentialId) {
            if (!this.selectedTenantId) return;
            this.credentialMessage = "Testing " + credentialId + "...";
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/credentials/" + credentialId + "/test",
                    { method: "POST" }
                );
                if (!resp.ok) {
                    this.credentialMessage = "Test failed (HTTP " + resp.status + ")";
                    return;
                }
                var result = await resp.json();
                this.credentialMessage = credentialId + ": " + result.status + " — " + result.message;
            } catch (e) {
                this.credentialMessage = "Test error: " + e.message;
                console.error("[EXPOSE] Credential test error:", e);
            }
        },

        /**
         * Import SpiderFoot credentials from the modal textarea.
         */
        async importSpiderFoot() {
            if (!this.selectedTenantId || !this.sfImportText.trim()) {
                this.credentialMessage = "Paste SpiderFoot credentials JSON first.";
                return;
            }
            this.credentialMessage = "Importing SpiderFoot credentials...";
            try {
                var creds = JSON.parse(this.sfImportText);
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/credentials/import/spiderfoot",
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ credentials: creds }),
                    }
                );
                if (!resp.ok) {
                    var errText = await resp.text();
                    this.credentialMessage = "Import failed (" + resp.status + "): " + errText;
                    return;
                }
                var result = await resp.json();
                this.credentialMessage = "Imported " + result.imported_count + " credentials" +
                    (result.skipped_count > 0 ? ", skipped " + result.skipped_count : "") + ".";
                this.showSfImportModal = false;
                this.sfImportText = "";
                await this.loadCredentials();
            } catch (e) {
                this.credentialMessage = "Import error: " + e.message;
                console.error("[EXPOSE] SpiderFoot import error:", e);
            }
        },

        /**
         * Import a native JSON bundle from the modal textarea.
         */
        async importBundle() {
            if (!this.selectedTenantId || !this.bundleImportText.trim()) {
                this.credentialMessage = "Paste credential bundle JSON first.";
                return;
            }
            this.credentialMessage = "Importing credential bundle...";
            try {
                var parsed = JSON.parse(this.bundleImportText);
                // Accept either the full bundle format or just a flat dict
                var creds = parsed.credentials || parsed;
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/credentials/import/bundle",
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            format_version: parsed.format_version || "1.0",
                            credentials: creds,
                        }),
                    }
                );
                if (!resp.ok) {
                    var errText = await resp.text();
                    this.credentialMessage = "Import failed (" + resp.status + "): " + errText;
                    return;
                }
                var result = await resp.json();
                this.credentialMessage = "Imported " + result.imported_count + " credentials" +
                    (result.skipped_count > 0 ? ", skipped " + result.skipped_count : "") + ".";
                if (result.errors && result.errors.length > 0) {
                    this.credentialMessage += " Errors: " + result.errors.join("; ");
                }
                this.showBundleImportModal = false;
                this.bundleImportText = "";
                await this.loadCredentials();
            } catch (e) {
                this.credentialMessage = "Import error: " + e.message;
                console.error("[EXPOSE] Bundle import error:", e);
            }
        },

        /**
         * Export credentials as a JSON bundle and trigger a download.
         */
        async exportCredentialBundle() {
            if (!this.selectedTenantId) return;
            this.credentialMessage = "Exporting credentials...";
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/credentials/export/bundle"
                );
                if (!resp.ok) {
                    this.credentialMessage = "Export failed (HTTP " + resp.status + ")";
                    return;
                }
                var data = await resp.json();
                var blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                var a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = "expose-credentials-" + new Date().toISOString().slice(0, 10) + ".json";
                a.click();
                URL.revokeObjectURL(a.href);
                this.credentialMessage = "Credentials exported (values masked).";
            } catch (e) {
                this.credentialMessage = "Export error: " + e.message;
                console.error("[EXPOSE] Credential export error:", e);
            }
        },

        /* ==================================================================
           Summary Stats
           ================================================================== */

        /**
         * Fetch summary statistics for the at-a-glance risk posture panel.
         * Computes entity counts, attribution tier breakdowns, collector
         * count, last scan timestamp, and non-production exposure from the
         * entities and runs API endpoints.
         */
        async loadStats() {
            if (!this.selectedTenantId) return;

            try {
                // Fetch entities and runs in parallel
                var tenantUrl = "/v1/tenants/" + this.selectedTenantId;
                var [entitiesResp, runsResp, configResp] = await Promise.all([
                    fetch(tenantUrl + "/entities"),
                    fetch(tenantUrl + "/runs"),
                    fetch(tenantUrl + "/config/"),
                ]);

                // --- Entity stats ---
                if (entitiesResp.ok) {
                    var entData = await entitiesResp.json();
                    var entities = entData.entities || entData.items || [];
                    this.stats.totalEntities = entities.length;

                    var confirmed = 0;
                    var high = 0;
                    var nonProd = 0;

                    for (var i = 0; i < entities.length; i++) {
                        var e = entities[i];
                        var tier = (e.attribution_tier || "").toLowerCase();
                        if (tier === "confirmed") confirmed++;
                        if (tier === "high") high++;

                        // Non-production: check environment or properties
                        var env = "";
                        if (e.properties && e.properties.environment) {
                            env = e.properties.environment.toLowerCase();
                        } else if (e.environment) {
                            env = e.environment.toLowerCase();
                        }
                        if (env === "dev" || env === "development" ||
                            env === "test" || env === "testing" ||
                            env === "staging" || env === "stage" ||
                            env === "sandbox" || env === "qa") {
                            nonProd++;
                        }
                    }

                    this.stats.confirmedThreats = confirmed;
                    this.stats.highRisk = high;
                    this.stats.nonProduction = nonProd;
                }

                // --- Last scan timestamp ---
                if (runsResp.ok) {
                    var runsData = await runsResp.json();
                    var runs = runsData.runs || runsData.items || [];
                    if (runs.length > 0) {
                        // Find the most recent completed run
                        var latest = null;
                        for (var j = 0; j < runs.length; j++) {
                            var run = runs[j];
                            var ts = run.completed_at || run.started_at || run.created_at;
                            if (ts && (!latest || ts > latest)) {
                                latest = ts;
                            }
                        }
                        if (latest) {
                            // Format as relative or short absolute time
                            var d = new Date(latest);
                            var now = new Date();
                            var diffMs = now - d;
                            var diffMin = Math.floor(diffMs / 60000);
                            if (diffMin < 1) {
                                this.stats.lastScan = "just now";
                            } else if (diffMin < 60) {
                                this.stats.lastScan = diffMin + "m ago";
                            } else if (diffMin < 1440) {
                                this.stats.lastScan = Math.floor(diffMin / 60) + "h ago";
                            } else {
                                this.stats.lastScan = Math.floor(diffMin / 1440) + "d ago";
                            }
                        } else {
                            this.stats.lastScan = "--";
                        }
                    } else {
                        this.stats.lastScan = "--";
                    }
                }

                // --- Collector count from tenant config ---
                if (configResp.ok) {
                    var cfgData = await configResp.json();
                    var enabledCollectors = cfgData.enabled_collectors || [];
                    this.stats.collectors = enabledCollectors.length;
                }
            } catch (e) {
                console.warn("[EXPOSE] Stats fetch failed:", e);
            }
        },

        /* ==================================================================
           Priority Findings
           ================================================================== */

        /**
         * Fetch prioritized findings from the lead scoring API.
         * Populates this.findings for the Priority Findings table.
         */
        async loadFindings() {
            if (!this.selectedTenantId) return;
            try {
                var res = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/findings/?limit=20"
                );
                if (res.ok) {
                    var data = await res.json();
                    // Only show findings when they contain real scored entities
                    // (takeover risks, real scan data), not placeholder/demo data.
                    if (data.is_placeholder) {
                        this.findings = [];
                    } else {
                        this.findings = data.findings;
                    }
                }
            } catch (e) {
                console.error("[EXPOSE] Failed to load findings:", e);
            }
        },

        /* ==================================================================
           Supply Chain Providers
           ================================================================== */

        /**
         * Category color mapping for supply chain provider badges.
         * Returns a CSS color string for the provider category.
         * @param {string} category - Provider category slug
         * @returns {string} CSS color value
         */
        providerCategoryColor(category) {
            var colors = {
                "cdn_waf": "#f59e0b",
                "cdn": "#f59e0b",
                "waf": "#f59e0b",
                "email": "#6366f1",
                "email_delivery": "#818cf8",
                "email_deliv": "#818cf8",
                "dns": "#22d3ee",
                "hosting": "#10b981",
                "analytics": "#a78bfa",
                "support": "#f472b6",
                "marketing": "#fb923c",
                "payment": "#ef4444",
                "auth": "#ec4899",
                "ci_cd": "#14b8a6",
                "monitoring": "#84cc16",
                "cloud": "#3b82f6",
                "storage": "#0ea5e9",
            };
            return colors[(category || "").toLowerCase()] || "var(--text-muted)";
        },

        /**
         * Fetch supply chain providers from the entities API.
         * Filters for entities with entity_type="provider" and populates
         * this.providers for the Supply Chain Dependencies panel.
         */
        async loadProviders() {
            if (!this.selectedTenantId) return;
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId + "/entities"
                );
                if (!resp.ok) return;
                var data = await resp.json();
                var entities = data.entities || data.items || [];
                this.providers = entities
                    .filter(function (e) {
                        return e.entity_type === "provider";
                    })
                    .map(function (e) {
                        var props = e.properties || {};
                        return {
                            name: e.canonical_identifier || e.name || "Unknown",
                            category: props.category || props.provider_category || "unknown",
                            evidence: props.evidence || props.detection_evidence || "--",
                            risk_notes: props.risk_notes || props.risk_note || "--",
                        };
                    });
            } catch (e) {
                console.warn("[EXPOSE] Failed to load providers:", e);
            }
        },

        /* ==================================================================
           Provenance Chain
           ================================================================== */

        /**
         * Fetch the provenance chain for a given entity from the API.
         * Populates this.provenanceData for the Provenance Chain panel.
         *
         * @param {string} entityId - UUID of the entity
         */
        async loadProvenance(entityId) {
            if (!this.selectedTenantId || !entityId) return;
            try {
                var resp = await fetch(
                    "/v1/tenants/" + this.selectedTenantId +
                    "/entities/" + entityId + "/provenance"
                );
                if (!resp.ok) {
                    console.warn("[EXPOSE] Provenance fetch failed:", resp.status);
                    this.provenanceData = null;
                    return;
                }
                this.provenanceData = await resp.json();
            } catch (e) {
                console.warn("[EXPOSE] Provenance fetch error:", e);
                this.provenanceData = null;
            }
        },

        /**
         * Return the CSS color for a correlation evidence dimension.
         * Each dimension in the 12-predicate vocabulary has a distinct color
         * for visual distinction in the evidence tree.
         *
         * @param {string} dimension - Dimension slug (cert, dns, whois, etc.)
         * @returns {string} CSS color value
         */
        dimensionColor(dimension) {
            var colors = {
                cert:        "#00BCD4",
                dns:         "#2196F3",
                whois:       "#9C27B0",
                asn:         "#FF9800",
                nameserver:  "#795548",
                subdomain:   "#4CAF50",
                cloud:       "#bc8cff",
                observation: "#607D8B",
                exposure:    "#f85149",
                naming:      "#d29922",
                explicit:    "#3fb950",
                recency:     "#58a6ff",
            };
            return colors[(dimension || "").toLowerCase()] || "var(--text-muted)";
        },

        /**
         * Format a confidence delta as a signed string with appropriate
         * color class for display in the evidence tree.
         *
         * @param {number} delta - Confidence delta value
         * @returns {string} Formatted string like "+0.30" or "-0.10"
         */
        formatDelta(delta) {
            if (delta === 0) return "0.00";
            var sign = delta > 0 ? "+" : "";
            return sign + delta.toFixed(2);
        },

        /**
         * Check whether a pivot dimension was matched in the correlation summary.
         *
         * @param {string} dimension - Dimension slug
         * @returns {boolean} True if any evidence item uses this dimension
         */
        isDimensionMatched(dimension) {
            if (!this.provenanceData || !this.provenanceData.correlation) return false;
            var evidence = this.provenanceData.correlation.evidence || [];
            for (var i = 0; i < evidence.length; i++) {
                if (evidence[i].dimension === dimension) return true;
            }
            return false;
        },

        /**
         * Navigate to a related entity's provenance by finding and clicking it
         * in the entity table, or by loading its provenance directly if we can
         * resolve its UUID.
         *
         * @param {string} identifier - The source_entity canonical identifier
         */
        navigateToEntityProvenance(identifier) {
            if (!identifier) return;
            // Try to find the entity row in the table and click it
            var rows = document.querySelectorAll("#entity-list .entity-row");
            for (var i = 0; i < rows.length; i++) {
                var text = rows[i].getAttribute("data-search-text") || "";
                if (text.indexOf(identifier.toLowerCase()) >= 0) {
                    rows[i].click();
                    rows[i].scrollIntoView({ behavior: "smooth", block: "center" });
                    return;
                }
            }
            // Also highlight on the graph
            this.highlightEntity(identifier);
        },

        /**
         * Map a lead score (0-100) to a CSS color variable.
         * Used by the findings table score bar to indicate severity.
         *
         * @param {number} score - Lead score value
         * @returns {string} CSS variable reference
         */
        scoreColor(score) {
            if (score >= 70) return "var(--error)";
            if (score >= 40) return "var(--warning)";
            if (score >= 20) return "var(--accent)";
            return "var(--text-dim)";
        },

        /**
         * Dispatch a custom event to highlight an entity on the graph.
         * The D3 renderer listens for 'expose:node-selected' events.
         *
         * @param {string} identifier - Entity canonical identifier
         */
        highlightEntity(identifier) {
            window.dispatchEvent(
                new CustomEvent("expose:node-selected", {
                    detail: { id: identifier },
                })
            );
        },

        /* ==================================================================
           Scan Elapsed Timer
           ================================================================== */

        /**
         * Start the elapsed-time timer.  Records the current timestamp and
         * updates ``scanElapsed`` (in whole seconds) every second.
         * Called when a run begins (alongside scan-log polling).
         */
        startScanTimer() {
            this.stopScanTimer();
            this._scanStartTime = Date.now();
            this.scanElapsed = 0;
            var self = this;
            this._scanElapsedHandle = setInterval(function () {
                self.scanElapsed = Math.floor((Date.now() - self._scanStartTime) / 1000);
            }, 1000);
        },

        /**
         * Stop the elapsed-time timer.  Idempotent.
         */
        stopScanTimer() {
            if (this._scanElapsedHandle) {
                clearInterval(this._scanElapsedHandle);
                this._scanElapsedHandle = null;
            }
        },

        /**
         * Format elapsed seconds as a compact human-readable string.
         * Examples: "12s", "1m 05s", "3m 20s".
         * @param {number} seconds - Elapsed seconds
         * @returns {string}
         */
        formatElapsed(seconds) {
            if (seconds < 60) return seconds + "s";
            var m = Math.floor(seconds / 60);
            var s = seconds % 60;
            return m + "m " + String(s).padStart(2, "0") + "s";
        },

        /* ==================================================================
           Scan Log Polling
           ================================================================== */

        /**
         * Start polling the scan log endpoint for new entries.
         * Called when a run starts (from scanForm.submitScan or connectSSE).
         */
        startScanLogPolling() {
            this.stopScanLogPolling();
            this.scanLogEntries = [];
            this._scanLogSince = 0;
            this.scanLogPolling = true;
            this.showScanLog = true;

            var self = this;
            this._pollScanLog();
            this._scanLogPollHandle = setInterval(function () {
                self._pollScanLog();
            }, 2000);
        },

        /**
         * Stop scan log polling.
         */
        stopScanLogPolling() {
            if (this._scanLogPollHandle) {
                clearInterval(this._scanLogPollHandle);
                this._scanLogPollHandle = null;
            }
            this.scanLogPolling = false;
        },

        /**
         * Fetch new log entries from the API since the last known offset.
         * Appends new entries to scanLogEntries and auto-scrolls the terminal.
         */
        async _pollScanLog() {
            if (!this.selectedTenantId || !this.activeRunId) return;
            try {
                var url = "/v1/tenants/" + this.selectedTenantId +
                          "/runs/" + this.activeRunId +
                          "/log?since=" + this._scanLogSince;
                var resp = await fetch(url);
                if (!resp.ok) return;
                var data = await resp.json();
                if (data.entries && data.entries.length > 0) {
                    for (var i = 0; i < data.entries.length; i++) {
                        this.scanLogEntries.push(data.entries[i]);
                    }
                    this._scanLogSince = data.total;

                    // Auto-scroll to bottom
                    var self = this;
                    this.$nextTick(function () {
                        var terminal = self.$refs.scanLogTerminal;
                        if (terminal) {
                            terminal.scrollTop = terminal.scrollHeight;
                        }
                    });
                }
            } catch (e) {
                console.warn("[EXPOSE] Scan log poll failed:", e);
            }
        },

        /**
         * Format a scan-log message with highlighted observation counts
         * and actionable error guidance.
         * HTML-escapes the message first (XSS safety), then wraps non-zero
         * observation counts in a green-highlighted span. For warn/error-level
         * entries matching known error patterns, appends actionable guidance
         * in a dimmer color.
         * @param {string} msg - Raw log message string
         * @param {string} [level] - Log level (info, warn, error)
         * @returns {string} HTML-safe string with optional highlight markup
         */
        formatLogMsg(msg, level) {
            if (!msg) return "";
            // HTML-escape to prevent XSS
            var escaped = msg
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#x27;");
            // Highlight non-zero observation counts:
            // Pattern: "completed: N observation(s)" where N > 0
            var result = escaped.replace(
                /completed: (\d+) observation/,
                function (_match, n) {
                    if (parseInt(n, 10) > 0) {
                        return 'completed: <span style="color: var(--success); font-weight: 600;">' + n + '</span> observation';
                    }
                    return _match;
                }
            );

            // Actionable error guidance for warn/error-level log entries.
            // When a known error pattern is detected, append guidance text
            // in a dimmer color to help the user take corrective action.
            if (level === "warn" || level === "error") {
                var ERROR_GUIDANCE = {
                    "HTTP 302": "credentials may be invalid — check API Keys panel",
                    "HTTP 401": "API key rejected — verify key in API Keys panel",
                    "HTTP 403": "access denied — check API key permissions",
                    "HTTP 429": "rate limited — scan will retry on next run",
                    "HTTP 502": "upstream service down — will use fallback if configured",
                    "HTTP 503": "service unavailable — temporary outage",
                    "not configured": "API key missing — import via API Keys panel",
                    "credentials not configured": "API key not loaded — check credential import",
                    "unreachable": "service not responding — check network or try later",
                };
                var lowerMsg = msg.toLowerCase();
                for (var pattern in ERROR_GUIDANCE) {
                    if (lowerMsg.indexOf(pattern.toLowerCase()) >= 0) {
                        result += ' <span style="color: var(--text-dim); font-style: italic; font-size: 0.9em;">— ' +
                            ERROR_GUIDANCE[pattern] + '</span>';
                        break;
                    }
                }
            }

            return result;
        },

        /**
         * Check whether a log entry message reports observations found (count > 0).
         * Used for conditional CSS class binding.
         * @param {string} msg - Raw log message string
         * @returns {boolean}
         */
        logHasObservations(msg) {
            if (!msg) return false;
            var m = msg.match(/completed: (\d+) observation/);
            return m !== null && parseInt(m[1], 10) > 0;
        },

        /**
         * Format an ISO timestamp to HH:MM:SS for the scan log.
         * @param {string} ts - ISO 8601 timestamp string
         * @returns {string} Formatted time string
         */
        formatLogTs(ts) {
            if (!ts) return "";
            try {
                var d = new Date(ts);
                var h = String(d.getHours()).padStart(2, "0");
                var m = String(d.getMinutes()).padStart(2, "0");
                var s = String(d.getSeconds()).padStart(2, "0");
                return h + ":" + m + ":" + s;
            } catch (_e) {
                return ts.substring(11, 19) || "";
            }
        },

        /**
         * Initialize on mount — read any pre-set values from the DOM.
         */
        applyEntityFilter() {
            var filter = (this.entityFilter || "").toLowerCase().trim();
            var rows = document.querySelectorAll("#entity-list .entity-row");
            var visible = 0;
            for (var i = 0; i < rows.length; i++) {
                var text = rows[i].getAttribute("data-search-text") || "";
                var match = !filter || text.indexOf(filter) >= 0;
                rows[i].style.display = match ? "" : "none";
                if (match) visible++;
            }
            this.entityCount = visible;
        },

        init() {
            var self = this;

            // Populate tenant selector from API
            this.loadTenants();

            document.addEventListener("htmx:afterSwap", function (event) {
                if (event.detail.target && event.detail.target.id === "entity-list") {
                    var rows = event.detail.target.querySelectorAll(".entity-row");
                    self.entityCount = rows.length;
                    self.applyEntityFilter();
                }
            });

            document.addEventListener("scan-started", function (event) {
                var runId = event.detail && event.detail.run_id;
                if (runId) {
                    self.activeRunId = runId;
                    self.startScanLogPolling();
                    self.startScanTimer();
                    self.connectSSE();
                }
            });

            if (this.selectedTenantId) {
                setTimeout(function () {
                    self._initGraphAndPoll();
                    self.loadStats();
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
        orgName: "",
        scanning: false,
        statusMessage: "",
        estimateText: "",
        orgSuggestions: [],
        _orgSuggestTimer: null,

        /**
         * Compute and display a scan duration estimate.
         * Uses seed/org field state plus the tenant's enabled collector
         * count to call the backend estimate endpoint.
         *
         * Heuristics for seed count estimation:
         *  - 1 for a non-empty domain/IP/CIDR seed
         *  - +1 if an organization name is provided
         *  - x3 TLD expansion factor (multi-TLD DNS pre-check)
         */
        async updateEstimate() {
            var hasSeed = this.seed.trim().length > 0;
            var hasOrg = this.orgName.trim().length > 0;

            if (!hasSeed && !hasOrg) {
                this.estimateText = "";
                return;
            }

            // Estimate seed count: base seeds x TLD expansion factor
            var baseSeedCount = (hasSeed ? 1 : 0) + (hasOrg ? 1 : 0);
            var tldExpansion = 3;  // multi-TLD pre-check factor
            var seedCount = baseSeedCount * tldExpansion;

            // Get the enabled collector count from the parent app's tenant config.
            // If config hasn't been loaded yet, trigger a load so subsequent
            // estimates use the real value instead of the fallback default.
            var collectorCount = 0;
            var appEl = document.querySelector("[x-data]");
            if (appEl && appEl._x_dataStack) {
                var appData = appEl._x_dataStack[0];
                if (appData && appData.tenantConfig &&
                    appData.tenantConfig.enabled_collectors &&
                    appData.tenantConfig.enabled_collectors.length > 0) {
                    collectorCount = appData.tenantConfig.enabled_collectors.length;
                } else if (appData && appData.stats && appData.stats.collectors > 0) {
                    collectorCount = appData.stats.collectors;
                }
                // If config not loaded yet and we have a tenant, trigger async load
                if (collectorCount === 0 && appData && !appData._configLoaded && appData.selectedTenantId) {
                    appData.loadTenantConfig();
                }
            }
            // Fallback only when no tenant config data is available at all
            if (collectorCount === 0) {
                collectorCount = 29;  // total builtin collectors
            }

            try {
                var resp = await fetch(
                    "/v1/admin/scan-estimate?seed_count=" + seedCount +
                    "&collector_count=" + collectorCount
                );
                if (resp.ok) {
                    var data = await resp.json();
                    var secs = Math.round(data.estimated_seconds);
                    var label = secs < 60
                        ? "~" + secs + "s"
                        : "~" + Math.ceil(secs / 60) + "m";
                    this.estimateText = "Estimated: " + label +
                        " (" + data.total_dispatches + " dispatches)";
                }
            } catch (_e) {
                // Silently ignore — estimate is best-effort
                this.estimateText = "";
            }
        },

        /**
         * Fetch organization name suggestions from the fuzzy-match API.
         * Called on org input changes with a 500ms debounce.
         * Populates orgSuggestions[] for display as clickable chips.
         */
        async fetchOrgSuggestions() {
            var query = (this.orgName || "").trim();
            if (query.length < 2) {
                this.orgSuggestions = [];
                return;
            }

            try {
                var resp = await fetch(
                    "/v1/admin/org-suggest?q=" + encodeURIComponent(query)
                );
                if (!resp.ok) {
                    this.orgSuggestions = [];
                    return;
                }
                var data = await resp.json();
                // Filter out exact matches -- no point suggesting what they already typed
                this.orgSuggestions = (data.suggestions || []).filter(function (s) {
                    return s.name.toLowerCase() !== query.toLowerCase();
                });
            } catch (_e) {
                this.orgSuggestions = [];
            }
        },

        /**
         * Handle org input changes with debounced suggestion fetch.
         * Also triggers the existing updateEstimate() call.
         */
        onOrgInput() {
            var self = this;
            this.updateEstimate();
            if (this._orgSuggestTimer) {
                clearTimeout(this._orgSuggestTimer);
            }
            this._orgSuggestTimer = setTimeout(function () {
                self.fetchOrgSuggestions();
            }, 500);
        },

        /**
         * Select an organization suggestion, replacing the input value.
         * Clears the suggestion list after selection.
         *
         * @param {string} name - The suggested organization name
         */
        selectOrgSuggestion(name) {
            this.orgName = name;
            this.orgSuggestions = [];
            this.updateEstimate();
        },

        /**
         * Submit the scan request to the runs API.
         * Reads the selected tenant ID from the parent exposeApp component.
         * Sends both domain/IP/CIDR seeds and optional organization seeds.
         */
        async submitScan() {
            var hasSeed = this.seed.trim().length > 0;
            var hasOrg = this.orgName.trim().length > 0;

            if (!hasSeed && !hasOrg) {
                this.statusMessage = "Enter a seed value (domain, IP, or CIDR) and/or an organization name.";
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
                var payload = {
                    seeds: hasSeed ? [this.seed.trim()] : [],
                    organization_seeds: hasOrg ? [this.orgName.trim()] : [],
                    collector_ids: null,
                };

                var resp = await fetch("/v1/tenants/" + tenantId + "/runs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                });

                if (!resp.ok) {
                    var errBody = await resp.text();
                    this.statusMessage = "Error " + resp.status + ": " + errBody;
                    this.scanning = false;
                    return;
                }

                var data = await resp.json();
                var seedSummary = [];
                if (data.seeds && data.seeds.length > 0) {
                    seedSummary.push(data.seeds.length + " seed(s)");
                }
                if (data.organization_seeds && data.organization_seeds.length > 0) {
                    seedSummary.push(data.organization_seeds.length + " org(s)");
                }
                this.statusMessage = "Run " + data.run_id + " started — " +
                    seedSummary.join(", ") + " (" + data.state + ")";

                // Notify parent exposeApp via custom event
                var scanEl = document.querySelector(".scan-form-card");
                if (scanEl) {
                    scanEl.dispatchEvent(new CustomEvent("scan-started", {
                        bubbles: true,
                        detail: { run_id: data.run_id },
                    }));
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
   Entity Detail Panel — click-to-expand properties
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    /**
     * Property category definitions.
     * Keys shown to the user are mapped into groups for organized display.
     * Properties starting with _ are hidden except for whitelisted source keys.
     */
    var PROPERTY_CATEGORIES = {
        "Source": ["_collector_id", "_observation_type", "_observed_at"],
        "Registration": ["registrant_org", "registrar", "nameservers", "creation_date", "expiration_date", "updated_date"],
        "Cloud": ["bucket_name", "cloud_provider", "region", "account_id", "resource_type"],
        "DNS": ["resolved_ips", "record_type", "spf_ip4_addresses", "spf_ip6_addresses", "dmarc_policy", "dkim_selector", "mx_records"],
        "Network": ["open_ports", "asn", "as_name", "cidr_block", "reverse_dns"],
        "Security": ["waf_detected", "waf_provider", "tls_issuer", "tls_expiry", "security_contact", "vulnerability_disclosure"],
    };

    /** Human-readable labels for property keys. */
    var PROPERTY_LABELS = {
        "_collector_id": "Collector",
        "_observation_type": "Observation Type",
        "_observed_at": "Observed At",
        "registrant_org": "Registrant Org",
        "registrar": "Registrar",
        "nameservers": "Nameservers",
        "creation_date": "Created",
        "expiration_date": "Expires",
        "updated_date": "Updated",
        "bucket_name": "Bucket",
        "cloud_provider": "Cloud Provider",
        "region": "Region",
        "account_id": "Account ID",
        "resource_type": "Resource Type",
        "resolved_ips": "Resolved IPs",
        "record_type": "Record Type",
        "spf_ip4_addresses": "SPF IPv4",
        "spf_ip6_addresses": "SPF IPv6",
        "dmarc_policy": "DMARC Policy",
        "dkim_selector": "DKIM Selector",
        "mx_records": "MX Records",
        "open_ports": "Open Ports",
        "asn": "ASN",
        "as_name": "AS Name",
        "cidr_block": "CIDR Block",
        "reverse_dns": "Reverse DNS",
        "waf_detected": "WAF Detected",
        "waf_provider": "WAF Provider",
        "tls_issuer": "TLS Issuer",
        "tls_expiry": "TLS Expiry",
        "security_contact": "Security Contact",
        "vulnerability_disclosure": "Vuln Disclosure",
    };

    /** Set of all categorized keys for quick lookup. */
    var categorizedKeys = {};
    for (var cat in PROPERTY_CATEGORIES) {
        for (var k = 0; k < PROPERTY_CATEGORIES[cat].length; k++) {
            categorizedKeys[PROPERTY_CATEGORIES[cat][k]] = cat;
        }
    }

    /**
     * Format a property value for display.
     * Arrays are joined with commas; objects are JSON-stringified;
     * booleans get yes/no; everything else is toString'd.
     */
    function formatValue(val) {
        if (val === null || val === undefined) return "--";
        if (Array.isArray(val)) return val.join(", ");
        if (typeof val === "object") return JSON.stringify(val);
        if (typeof val === "boolean") return val ? "yes" : "no";
        return String(val);
    }

    /**
     * Create a single property row DOM element (label + value).
     * Uses textContent exclusively to prevent XSS.
     *
     * @param {string} label - Display label
     * @param {string} value - Formatted value string
     * @returns {HTMLElement}
     */
    function createPropElement(label, value) {
        var prop = document.createElement("div");
        prop.className = "entity-detail-prop";

        var labelEl = document.createElement("span");
        labelEl.className = "entity-detail-label";
        labelEl.textContent = label;

        var valueEl = document.createElement("span");
        valueEl.className = "entity-detail-value";
        valueEl.textContent = value;

        prop.appendChild(labelEl);
        prop.appendChild(valueEl);
        return prop;
    }

    /**
     * Create a property group DOM element with a title and property rows.
     *
     * @param {string} title - Group title (e.g. "Source", "DNS")
     * @param {Array<{label: string, value: string}>} items - Property items
     * @returns {HTMLElement}
     */
    function createGroupElement(title, items) {
        var group = document.createElement("div");
        group.className = "entity-detail-group";

        var titleEl = document.createElement("div");
        titleEl.className = "entity-detail-group-title";
        titleEl.textContent = title;
        group.appendChild(titleEl);

        var propsContainer = document.createElement("div");
        propsContainer.className = "entity-detail-properties";

        for (var i = 0; i < items.length; i++) {
            propsContainer.appendChild(
                createPropElement(items[i].label, items[i].value)
            );
        }

        group.appendChild(propsContainer);
        return group;
    }

    /**
     * Build the detail panel DOM from a properties object.
     * Groups properties by category and renders a two-column layout.
     * All text content is set via textContent (XSS-safe).
     *
     * @param {Object} props - Entity properties dict
     * @returns {HTMLElement}
     */
    function buildDetailDOM(props) {
        if (!props || Object.keys(props).length === 0) {
            var empty = document.createElement("div");
            empty.className = "entity-detail-empty";
            empty.textContent = "No properties available.";
            return empty;
        }

        // Collect properties into categories
        var grouped = {};
        var uncategorized = [];

        for (var key in props) {
            if (!props.hasOwnProperty(key)) continue;

            // Skip internal keys not in whitelist
            if (key.charAt(0) === "_" && !categorizedKeys[key]) continue;

            if (categorizedKeys[key]) {
                var catName = categorizedKeys[key];
                if (!grouped[catName]) grouped[catName] = [];
                grouped[catName].push(key);
            } else {
                uncategorized.push(key);
            }
        }

        var content = document.createElement("div");
        content.className = "entity-detail-content";

        // Render categorized groups
        var categoryOrder = ["Source", "Registration", "Cloud", "DNS", "Network", "Security"];
        for (var i = 0; i < categoryOrder.length; i++) {
            var category = categoryOrder[i];
            if (!grouped[category] || grouped[category].length === 0) continue;

            var items = [];
            for (var j = 0; j < grouped[category].length; j++) {
                var propKey = grouped[category][j];
                items.push({
                    label: PROPERTY_LABELS[propKey] || propKey,
                    value: formatValue(props[propKey]),
                });
            }
            content.appendChild(createGroupElement(category, items));
        }

        // Render uncategorized properties under "Other"
        if (uncategorized.length > 0) {
            var otherItems = [];
            for (var u = 0; u < uncategorized.length; u++) {
                var uKey = uncategorized[u];
                otherItems.push({
                    label: PROPERTY_LABELS[uKey] || uKey.replace(/_/g, " "),
                    value: formatValue(props[uKey]),
                });
            }
            content.appendChild(createGroupElement("Other", otherItems));
        }

        return content;
    }

    /**
     * Event delegation handler on #entity-list.
     * Toggles a detail row below the clicked entity row.
     */
    function handleEntityClick(event) {
        var row = event.target.closest(".entity-row");
        if (!row) return;

        var entityId = row.getAttribute("data-entity-id");
        if (!entityId) return;

        // Check if detail row already exists
        var existingDetail = row.nextElementSibling;
        if (existingDetail && existingDetail.classList.contains("entity-detail")) {
            // Toggle off — collapse with animation
            existingDetail.classList.add("entity-detail-collapsing");
            row.classList.remove("entity-row-expanded");
            setTimeout(function () {
                if (existingDetail.parentNode) {
                    existingDetail.parentNode.removeChild(existingDetail);
                }
            }, 200);
            // Clear provenance panel when collapsing
            var appElCollapse = document.querySelector("[x-data]");
            if (appElCollapse && appElCollapse._x_dataStack) {
                var appDataCollapse = appElCollapse._x_dataStack[0];
                if (appDataCollapse) appDataCollapse.provenanceData = null;
            }
            return;
        }

        // Close any other open detail rows
        var openDetails = document.querySelectorAll("#entity-list .entity-detail");
        var expandedRows = document.querySelectorAll("#entity-list .entity-row-expanded");
        for (var i = 0; i < openDetails.length; i++) {
            openDetails[i].parentNode.removeChild(openDetails[i]);
        }
        for (var j = 0; j < expandedRows.length; j++) {
            expandedRows[j].classList.remove("entity-row-expanded");
        }

        // Parse properties from the data attribute
        var propsJSON = row.getAttribute("data-properties") || "{}";
        var props;
        try {
            props = JSON.parse(propsJSON);
        } catch (e) {
            console.warn("[EXPOSE] Failed to parse entity properties:", e);
            props = {};
        }

        // Determine column count from the header row
        var table = row.closest("table");
        var colCount = 4;
        if (table) {
            var headerCells = table.querySelectorAll("thead th");
            if (headerCells.length > 0) colCount = headerCells.length;
        }

        // Create detail row using safe DOM methods (no innerHTML)
        var detailRow = document.createElement("tr");
        detailRow.className = "entity-detail";
        detailRow.setAttribute("data-detail-for", entityId);

        var detailCell = document.createElement("td");
        detailCell.setAttribute("colspan", String(colCount));
        detailCell.className = "entity-detail-cell";
        detailCell.appendChild(buildDetailDOM(props));

        detailRow.appendChild(detailCell);
        row.classList.add("entity-row-expanded");

        // Insert after the clicked row
        if (row.nextSibling) {
            row.parentNode.insertBefore(detailRow, row.nextSibling);
        } else {
            row.parentNode.appendChild(detailRow);
        }

        // Trigger provenance chain load via the Alpine app scope
        var appEl = document.querySelector("[x-data]");
        if (appEl && appEl._x_dataStack) {
            var appData = appEl._x_dataStack[0];
            if (appData && typeof appData.loadProvenance === "function") {
                appData.loadProvenance(entityId);
            }
        }
    }

    // Attach click listener via delegation on #entity-list
    var entityList = document.getElementById("entity-list");
    if (entityList) {
        entityList.addEventListener("click", handleEntityClick);
    }

    // Re-attach after HTMX swaps (entity list is HTMX-loaded)
    document.addEventListener("htmx:afterSwap", function (event) {
        if (event.detail.target && event.detail.target.id === "entity-list") {
            // Listener is on the container, no re-attach needed for delegation.
            // Detail rows are cleared on table refresh (new HTML replaces old).
        }
    });
});


/* =========================================================================
   Resize observer — reinitializes graph on container resize
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    var graphContainer = document.getElementById("observation-graph");
    if (graphContainer && typeof ResizeObserver !== "undefined") {
        var resizeTimer = null;
        var observer = new ResizeObserver(function () {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                var appEl = document.querySelector("[x-data]");
                if (appEl && appEl.__x && appEl.__x.$data._graphInitialized) {
                    appEl.__x.$data._initGraphAndPoll();
                }
            }, 200);
        });
        observer.observe(graphContainer);
    }
});


/* =========================================================================
   Split-pane drag handle
   ========================================================================= */

document.addEventListener("DOMContentLoaded", function () {
    var handle = document.getElementById("split-handle");
    var paneLeft = document.querySelector(".pane-left");
    var splitPane = document.querySelector(".split-pane");
    if (!handle || !paneLeft || !splitPane) return;

    var dragging = false;

    handle.addEventListener("mousedown", function (e) {
        e.preventDefault();
        dragging = true;
        handle.classList.add("dragging");
        document.body.style.cursor = "col-resize";
        document.body.style.userSelect = "none";
    });

    document.addEventListener("mousemove", function (e) {
        if (!dragging) return;
        var rect = splitPane.getBoundingClientRect();
        var offset = e.clientX - rect.left;
        var pct = (offset / rect.width) * 100;
        pct = Math.max(25, Math.min(pct, 75));
        paneLeft.style.flex = "0 0 " + pct + "%";
        paneLeft.style.maxWidth = pct + "%";
    });

    document.addEventListener("mouseup", function () {
        if (!dragging) return;
        dragging = false;
        handle.classList.remove("dragging");
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
    });
});
