# EXPOSE Darkroom Dashboard -- Manual QA Browser Tests

**Version:** Phase 1 (in-memory, no persistent DB)
**Application URL:** `http://localhost:8090`
**Dashboard URL:** `http://localhost:8090/dashboard`
**Status:** Current

---

## Setup

These steps must be completed before running any test.

1. **Start the application:**
   ```bash
   cd ~/projects/ff6k
   docker-compose up -d
   ```

2. **Wait for the health check to pass:**
   ```bash
   curl http://localhost:8090/healthz
   ```
   You should receive `{"status":"ok"}`. If the curl fails, wait 15 seconds and retry. If it still fails, check container logs with `docker-compose logs api`.

3. **Create a test tenant via the API** (the dashboard needs at least one tenant in the database):
   ```bash
   curl -s -X POST http://localhost:8090/v1/tenants/ \
     -H "Content-Type: application/json" \
     -d '{"name": "qa-test-tenant"}' | python3 -m json.tool
   ```
   Record the returned `id` value (a UUID). You will use this as the tenant ID throughout all tests. Example: `3f8a1b2c-...`.

4. **Open a browser** (Chrome or Firefox recommended) and navigate to `http://localhost:8090/dashboard`.

5. **Open browser DevTools** (F12) and keep the Console tab visible. Several tests require verifying console output.

**Phase 1 note:** This is an in-memory Phase 1 deployment. Tenant configuration does not persist across process restarts. Some API endpoints return placeholder/demo data when no database session factory is wired. The scan pipeline executes real collector logic against live targets -- use safe seed domains you own or `example.com` (which returns placeholder data in dev mode).

---

## Test 1: Dashboard Loads with Darkroom Theme

**Objective:** Verify the dashboard page loads, the Darkroom visual theme renders correctly, and all major layout panels are present.

**Prerequisites:** Setup steps 1-4 complete. Browser open to `http://localhost:8090/dashboard`.

**Steps:**

1. Navigate to `http://localhost:8090/dashboard` in your browser.
2. Wait for the page to fully load (no more than 3 seconds on localhost).
3. Inspect the top bar area at the very top of the viewport.
4. Inspect the main split-pane area occupying the center of the page.
5. Inspect the bottom status bar.
6. Open DevTools (F12) and check the Console tab for JavaScript errors.

**Expected Results:**

- The page background is near-black (`#0a0a0f`, CSS variable `--void`). The overall impression is a dark "darkroom" aesthetic -- no white backgrounds, no bright unstyled elements.
- **Top bar** (`.top-bar`): Visible at the top. Contains:
  - Left: A diamond logo mark with "EXPOSE" text and "Attack Surface Intelligence" tagline.
  - Center: A tenant selector dropdown (`#tenant-select`) with at least the option "Select tenant..." and a "default" entry.
  - Right: No run indicator visible yet (it is hidden when no run is active).
- **Left pane** (`.pane-left`): Labeled "Observation Graph" in the pane header. Shows an empty-state placeholder reading "No tenant selected" with a diamond icon and the message "Select a tenant above to begin mapping the attack surface."
- **Right pane** (`.pane-right`): Labeled "Entities" in the pane header. Contains a "Filter..." search input. Shows an empty-state message: "Waiting for data" / "Entities will appear here as the pipeline discovers and attributes assets on your external surface."
- **Status bar** (`.status-bar`): At the bottom. Displays "No active run" and "EXPOSE v0.1.0-dev".
- The Start Scan form card, Tenant Config panel, and API Keys panel are all **hidden** (they only appear after a tenant is selected).
- The browser Console shows **zero JavaScript errors**. Informational HTMX messages are acceptable.
- The page title in the browser tab reads "Dashboard -- Attack Surface Intelligence".

**Pass Criteria:** All six layout elements (top bar with logo/selector, left pane with graph placeholder, right pane with entity placeholder, status bar with version, no JS errors, correct page title) are present and correctly themed.

**Notes:**
- If the background appears white or elements are unstyled, verify that `/static/css/expose.css` loaded (check Network tab in DevTools for a 200 response).
- If the tenant dropdown is empty, the `default` tenant option is hardcoded in the HTML template and should always appear. The API-created tenant from setup step 3 may need a page refresh to appear if dynamic population is wired.
- If you see "JS disabled -- static view" in the top bar, JavaScript is not executing. Check that Alpine.js, HTMX, and D3.js loaded from the CDN (Network tab).

---

## Test 2: Start a Scan

**Objective:** Verify that selecting a tenant reveals the scan form, and submitting a seed domain starts a pipeline run with correct status indicators.

**Prerequisites:** Setup complete. At least one tenant exists (created in setup step 3). You have the tenant UUID.

**Steps:**

1. Navigate to `http://localhost:8090/dashboard`.
2. Click the tenant selector dropdown (`#tenant-select`) in the top bar center.
3. Select the tenant you created (e.g., "qa-test-tenant"). If it does not appear in the dropdown, select the hardcoded "default" option.
4. Wait 1-2 seconds. Observe the page layout changes.
5. Locate the "Start Scan" card (`.scan-form-card`) that should now be visible below the top bar.
6. Click in the seed input field (`#seed-input`, placeholder text "example.com").
7. Type `example.com` into the input field.
8. Click the "Scan" button (`.btn-primary`).
9. Observe the button state and status message area below the form.
10. Check the top-right corner of the top bar for the run indicator.
11. Check the Console tab in DevTools for SSE connection messages.

**Expected Results:**

- After selecting a tenant (step 3):
  - The "Start Scan" card appears with a text input and a "Scan" button.
  - The "Tenant Config" and "API Keys" collapsible panels appear (collapsed by default).
  - The left pane's "No tenant selected" placeholder disappears.
  - The right pane begins loading entities (spinner may briefly appear).
- After clicking "Scan" (step 8):
  - The button text changes from "Scan" to "Scanning..." and becomes disabled (`:disabled` state, non-clickable).
  - A status message appears below the form reading something like: "Run [uuid] started (pending)".
  - The button reverts to "Scan" once the request completes (within 2 seconds).
- **Run indicator** (`.run-indicator`): A green-bordered badge appears in the top-right of the top bar. It contains a pulsing green dot (`.run-indicator-dot`) and the text "SSE Live" (if SSE connected) or "Run active".
- **Console output:** Messages like `[EXPOSE] SSE connected: /v1/tenants/.../runs/.../events` appear, confirming the SSE EventSource connected.
- **Status bar:** Changes from "No active run" to "Streaming live events..." or "Run in progress (polling)".

**Pass Criteria:** The scan form accepts input and submits successfully (status message shows a run UUID), the run indicator appears in the top bar, and the status bar reflects an active run.

**Notes:**
- If the scan returns an error like "Tenant not found" (404), the tenant UUID in the dropdown does not match a tenant in the database. Create a tenant via the API (setup step 3) and reload the page.
- If the button never changes to "Scanning...", check the Console for fetch errors. The API endpoint is `POST /v1/tenants/{tenant_id}/runs`.
- In Phase 1 dev mode, the scan may complete almost instantly if collectors hit timeouts or return no data for `example.com`. This is expected behavior.

---

## Test 3: Entity Table Populates

**Objective:** Verify that after a scan starts (or with placeholder data), the entity table in the right pane populates with correctly formatted rows showing type, identifier, attribution, and timestamp columns.

**Prerequisites:** Test 2 completed (a scan has been started for the selected tenant), OR the tenant has placeholder data returned by the dev-mode API.

**Steps:**

1. With a tenant selected and a scan started (from Test 2), observe the right pane labeled "Entities".
2. Wait up to 10 seconds for the entity list to populate. The HTMX polling interval is 5 seconds (`hx-trigger="load, every 5s"`).
3. Examine the table structure: look for column headers and data rows.
4. Count the number of rows.
5. Examine the entity count badge next to the "Entities" title.
6. Type a filter term (e.g., `example`) into the "Filter..." input in the pane header.
7. Clear the filter input.

**Expected Results:**

- The entity table (`.entity-table`) appears inside the `#entity-list` container with four columns:
  - **Type** (`.col-type`): Each cell contains a colored badge (`.entity-type-badge`) with text like "domain", "subdomain", or "ip". Badge colors vary by type:
    - `domain`: indigo/purple tint
    - `subdomain`: blue-gray tint
    - `ip`: amber tint
  - **Identifier** (`.col-identifier`): The entity's canonical identifier (e.g., `example.com`, `api.example.com`, `203.0.113.42`). Text is white/light colored (`.identifier-text`).
  - **Attribution** (`.col-attribution`): A pill-shaped badge (`.attribution-badge`) showing status:
    - `confirmed`: wheat/gold color with a subtle glow animation
    - `high`: amber-gold color
    - `requires review`: amber with pulsing animation
    - `medium`: blue-gray color
  - **Last Observed** (`.col-observed`): An ISO-8601 timestamp in muted gray text.
- In dev mode (no DB session factory), 5 placeholder entities appear: `example.com`, `api.example.com`, `203.0.113.42`, `mail.example.com`, `198.51.100.7`.
- The entity count badge (`.entity-count`) next to the "Entities" header shows the number of rows (e.g., "5").
- Each row has a subtle hover effect (background shifts to `--surface`).
- New rows animate in with the `reveal` animation (fade-in from blur).
- The Filter input is present but filtering is client-side via Alpine.js -- note that the `entityFilter` model is bound but the actual table is HTMX-rendered, so filtering may not visually hide rows in Phase 1 unless wired.

**Pass Criteria:** The entity table renders with at least one row, all four columns (Type, Identifier, Attribution, Last Observed) display correctly with appropriate color-coded badges, and the entity count badge updates.

**Notes:**
- If the table shows "No entities discovered for this tenant yet." (the empty state from `entity_table.html`), the scan has not produced entities yet or the tenant has no data. Wait for the 5-second poll cycle or check the API directly: `curl http://localhost:8090/v1/tenants/{tenant_id}/entities`.
- If data appears but badges are unstyled (plain text), verify that `expose.css` loaded and CSS classes like `.entity-type-domain` and `.attribution-confirmed` are present.
- The HTMX indicator (`.spinner` with three pulsing dots) may flash briefly during each poll -- this is expected.

---

## Test 4: Observation Graph Renders

**Objective:** Verify the D3.js force-directed observation graph initializes, renders nodes and edges, and supports hover tooltips and interactive features.

**Prerequisites:** A tenant is selected. The scan has produced entities (or placeholder data is available). The graph container is visible in the left pane.

**Steps:**

1. Select a tenant from the dropdown (if not already selected).
2. Observe the left pane ("Observation Graph"). Wait up to 5 seconds for the graph to initialize.
3. Look for circular nodes appearing in the dark graph area.
4. Look for thin lines (edges) connecting some of the nodes.
5. Hover your mouse over a node. Observe the tooltip that appears.
6. Hover over a different node and observe how edge highlighting changes.
7. Click and drag a node to reposition it. Release the mouse button.
8. Use the mouse scroll wheel (or trackpad pinch) to zoom in and out on the graph.
9. Click the layout toggle button in the pane header (labeled "Radial" or "Force").
10. Look at the graph legend strip below the graph area.

**Expected Results:**

- The graph renders inside the `#observation-graph` container as an SVG element with a near-black background (`#0a0a0f`).
- **Nodes** appear as circles with colors corresponding to attribution status:
  - Seed nodes: dim amber (`#b8860b`)
  - Unattributed: cool gray (`#4a5568`)
  - Medium/corroborated: blue (`#5b7ca3`)
  - High: amber-gold (`#d4a020`)
  - Confirmed: wheat-gold (`#f5deb3`) with a glow filter
  - Requires review: alert amber (`#e6a817`) with a pulsing animation
- **Node size** varies based on the number of collector signals (more signals = larger circle, base 6px + 2px per signal).
- **If a highest-risk node exists** (deru-kui feature): One node appears in red (`#ef4444`) with a red pulsing drop-shadow, noticeably larger than other nodes (2x radius).
- **Edges**: Thin blue-gray lines (`#5b7ca3`) connect related nodes at 25% opacity.
- **Hover tooltip** (`.expose-tooltip`): A dark popup with amber border appears near the cursor showing:
  - Entity label (bold)
  - Type (e.g., "domain")
  - Attribution status
  - Confidence percentage
  - Signal count
  - First seen timestamp (if available)
- **Hover edge highlighting**: When hovering a node, edges connected to that node brighten (90% opacity); unrelated edges dim (8% opacity).
- **Deru-kui tooltip** (for highest-risk node): A larger red-bordered tooltip appears with Japanese text, the entity label, and a lead score.
- **Drag**: Nodes can be dragged; the force simulation adjusts positions of connected nodes. Releasing the node lets it settle back via the force layout.
- **Zoom**: Scroll wheel zooms in/out. The entire graph scales (min 0.2x to max 5x).
- **Layout toggle**: The button in the pane header toggles its label between "Radial" and "Force". The graph layout may reorganize.
- **Legend** (`.graph-legend`): Below the graph, a horizontal strip shows colored dots with labels: Seed, Discovered, Corroborated, High, Confirmed (with glow animation), Review (with pulse animation).

**Pass Criteria:** The SVG graph renders with at least one node, hover produces a tooltip with entity details, and the graph responds to drag/zoom interactions.

**Notes:**
- If the graph area is blank (no SVG), check that D3.js loaded (Network tab: `d3.min.js` should return 200) and that the Console shows no errors from `ExposeGraph.init()`.
- If no nodes appear but the SVG is present, the graph data endpoint may be returning empty arrays. Check: `curl http://localhost:8090/v1/tenants/{tenant_id}/graph`. An empty `{"nodes":[],"edges":[]}` response means no entities/relationships exist yet.
- The graph polls for new data every 5 seconds (`setInterval` in `expose.js`). New entities from a running scan will appear progressively with an emerge animation (800ms fade-in from zero radius).
- Lower-confidence nodes appear blurred (Gaussian blur filter). This is the "darkroom reveal" visual metaphor -- they sharpen as confidence increases.

---

## Test 5: Tenant Config Panel

**Objective:** Verify the tenant configuration panel expands, displays all configuration sections, accepts edits, saves successfully, and persists changes across a reload.

**Prerequisites:** A tenant is selected in the dropdown.

**Steps:**

1. With a tenant selected, locate the "Tenant Config" card below the scan form.
2. Click anywhere on the "Tenant Config" header bar (the row with the expand/collapse arrow). The panel should expand.
3. Wait for the "Loading configuration..." text to be replaced by the config form.
4. **Scope Rules section:** Click the "+ Add Rule" button.
5. In the new rule row that appears, leave the type dropdown on "apex_domain" and type `testdomain.com` in the value text field.
6. Click "+ Add Rule" again. Change the type dropdown to "cidr" and type `10.0.0.0/24` in the value field. Check the "Exclude" checkbox.
7. **Enabled Collectors section:** Check the checkbox next to `ct-crtsh`. Check the checkbox next to `rdap-whois`. Uncheck any others that may be checked.
8. **Schedule (Cron) section:** Type `0 2 * * *` in the cron input field.
9. **Egress Profile section:** Click the egress dropdown and select "socks5".
10. **LLM Enrichment section:** Check the "Enable LLM" checkbox. Select "Anthropic" from the Provider dropdown. Type `5.00` in the "Cost Ceiling ($/run)" field.
11. Click the "Save Configuration" button.
12. Observe the save status message.
13. Click the "Tenant Config" header to collapse the panel.
14. Click it again to re-expand.
15. Verify that all your changes are still present.

**Expected Results:**

- Clicking the header toggles between expanded (arrow up, "Collapse") and collapsed (arrow down, "Expand") states with a smooth transition.
- Initially shows "Loading configuration..." briefly, then the form appears.
- **Scope Rules** (`<fieldset>` with legend "Scope Rules"):
  - "+ Add Rule" creates a new row with a type dropdown (defaulting to "apex_domain"), a value text input, an "Exclude" checkbox, and a red X remove button.
  - The type dropdown offers: apex_domain, exact_domain, ip_address, cidr, asn, cloud_account, registrant_org.
- **Enabled Collectors**: 13 checkboxes are listed, each labeled with a collector ID (e.g., `active-dns-resolve`, `ct-crtsh`, `rdap-whois`).
- **Schedule**: A text input accepting cron syntax.
- **Egress Profile**: A dropdown with options: direct, socks5, wireguard, http_connect.
- **LLM Enrichment** (labeled "Stage 4b"):
  - "Enable LLM" checkbox. When checked, Provider dropdown and Cost Ceiling input become visible.
  - Provider dropdown: None, OpenAI, Anthropic, Ollama (local), Azure OpenAI.
- After clicking "Save Configuration":
  - The button text changes to "Saving..." briefly.
  - A status message appears: "Configuration saved."
  - The button reverts to "Save Configuration".
- After collapsing and re-expanding, the configuration reloads from the API and shows the same values you entered (scope rules, enabled collectors, cron, egress, LLM settings).

**Pass Criteria:** All five configuration sections (scope rules, collectors, schedule, egress, LLM) accept input, the save operation succeeds with a confirmation message, and re-expanding the panel shows the saved values.

**Notes:**
- Phase 1 config is stored in-memory (`_configs` dict in `tenant_config.py`). If you restart the Docker containers, all saved configuration is lost. This is expected.
- If "Save failed (422)" appears, one of the inputs may be invalid. The cron expression is validated by `CronExpression` -- malformed expressions like `* * *` (too few fields) will be rejected.
- The remove button (red X) on scope rules should remove that rule from the form immediately. The removal is only persisted when you click "Save Configuration".

---

## Test 6: API Key Management

**Objective:** Verify the API Keys panel expands, shows credential slots with status indicators, and supports the JSON bundle import flow.

**Prerequisites:** A tenant is selected. No credentials have been imported yet (fresh state).

**Steps:**

1. Locate the "API Keys" card below the Tenant Config panel.
2. Click the "API Keys" header bar to expand the panel.
3. Wait for the credentials table to load (replaces "Loading credentials..." text).
4. Examine the table structure and status indicators.
5. Count the number of credential rows.
6. Locate a row with status "missing" and try clicking its "Test" button.
7. Click the "Import JSON" button below the credentials table.
8. In the import modal that appears, paste the following JSON into the textarea:
   ```json
   {"shodan_api_key": "test-key-abc123", "github_token": "ghp_test1234567890"}
   ```
9. Click the "Import" button.
10. Observe the status message and table changes.
11. Locate the "Shodan API Key" row and click its "Test" button.
12. Click the "Export" button.

**Expected Results:**

- The "API Keys" header shows a counter like "0/10 configured" initially.
- The credentials table has five columns: **Credential**, **Status**, **Value**, **Collectors**, **Actions**.
- 10 credential rows appear (the known slots): Shodan API Key, SecurityTrails API Key, VirusTotal API Key, Censys API ID, Censys API Secret, BinaryEdge API Key, GitHub Token, PassiveTotal API Key, GreyNoise API Key, urlscan.io API Key.
- Each row initially shows:
  - Status: a gray "missing" badge.
  - Value: `---` (no value stored).
  - Collectors: the associated collector ID(s) or "none".
  - Actions: a "Test" button, which is disabled (grayed out) when status is "missing".
- After importing (step 9):
  - Status message: "Imported 2 credentials."
  - The counter in the header updates to "2/10 configured".
  - "Shodan API Key" row now shows a green "configured" badge, a masked value like `****c123`, and its Test button is now enabled.
  - "GitHub Token" row similarly shows "configured" with a masked value.
- After clicking "Test" on the Shodan row (step 11):
  - Status message: "shodan_api_key: ok -- Shodan API Key is configured (health check not yet implemented)."
- After clicking "Export" (step 12):
  - A JSON file downloads with a name like `expose-credentials-YYYY-MM-DD.json`.
  - The status message reads "Credentials exported (values masked)."

**Pass Criteria:** The credentials table displays all 10 slots, import updates status from "missing" to "configured" with masked values, the Test button returns a success response for configured credentials, and Export triggers a file download.

**Notes:**
- The "Import SpiderFoot" button opens a separate modal for SpiderFoot-format credentials (`sfp_module.api_key` keys). Test that flow separately if desired.
- The "Cancel" button in import modals should close the modal and clear the textarea without importing.
- If import returns "Import failed (422)", check that the JSON is valid and keys match known slot IDs. Unknown slot IDs will be skipped with an error in the response.
- Phase 1 stores credentials in-memory (`InMemoryBackend`). They are lost on container restart.

---

## Test 7: CSV Export

**Objective:** Verify the export panel appears when entities exist, filter dropdowns work, and clicking "Download CSV" triggers a file download with correctly formatted data.

**Prerequisites:** A tenant is selected and has entities (either from a completed scan or placeholder data). The entity table in the right pane shows at least one row.

**Steps:**

1. With entities visible in the right pane, scroll down below the main split pane area to find the "Export" card.
2. Verify the Export panel is visible (it is hidden when no entities exist).
3. Examine the two filter dropdowns and the "Download CSV" button.
4. Leave both filter dropdowns on their defaults ("All Types" and "All Tiers").
5. Click the "Download CSV" button.
6. Observe the button state change and verify a file downloads.
7. Open the downloaded CSV file in a text editor or spreadsheet application.
8. Examine the CSV contents.
9. Go back to the Export panel. Change the entity type filter to "Domain".
10. Click "Download CSV" again.
11. Open this second CSV file and compare it to the first.
12. Change the attribution tier filter to "Confirmed" (with type still on "Domain").
13. Click "Download CSV" a third time and verify the filtered results.

**Expected Results:**

- The Export panel appears below the split pane when entities exist. It shows:
  - A type filter dropdown with options: All Types, Domain, IP Address, Certificate, Organization.
  - A tier filter dropdown with options: All Tiers, Confirmed, High, Medium, Requires Review.
  - A "Download CSV" button.
- When "Download CSV" is clicked:
  - The button text changes to "Exporting..." briefly.
  - A file downloads with a name like `expose-export-YYYY-MM-DD.csv`.
  - The button reverts to "Download CSV".
- **CSV file contents** (unfiltered, placeholder data):
  - Header row: `entity_identifier,entity_type,attribution_tier,confidence,collectors,first_seen,last_seen,environment,risk_summary`
  - 8 data rows (the full placeholder set): example.com, api.example.com, 203.0.113.42, mail.example.com, 198.51.100.7, *.example.com, Example Corp, staging.example.com.
  - Each row has all 9 columns populated.
- When filtered by type "Domain" (step 9): The CSV contains only rows where `entity_type` is `domain` (example.com, api.example.com, mail.example.com, staging.example.com).
- When filtered by type "Domain" AND tier "Confirmed": Only `example.com` appears (the only domain with `confirmed` attribution).

**Pass Criteria:** CSV downloads with the correct filename, contains a valid header row and data rows, and filters correctly reduce the row count.

**Notes:**
- The API route maps the UI's "IP Address" option to the query param `entity_type=ip_address`. If filtering does not work, check the network request in DevTools to verify the query parameters.
- The CSV filename includes the tenant UUID and a UTC timestamp for traceability.
- If the Export panel is not visible, the `x-show="entities.length > 0 || entityCount > 0"` condition is not met. Ensure the entity table has rows.
- If the download does not trigger, check for browser popup blockers or look for errors in the Console related to `URL.createObjectURL`.

---

## Test 8: SSE Live Updates

**Objective:** Verify that Server-Sent Events (SSE) deliver real-time updates to the dashboard when a scan is running, including the "SSE Live" indicator, entity table refreshes, and graph data updates.

**Prerequisites:** A tenant is selected. No scan is currently running.

**Steps:**

1. Open browser DevTools (F12) to the Console tab. Clear existing messages.
2. Also open the Network tab and filter by "EventStream" or "eventsource" (varies by browser -- in Chrome, filter the Fetch/XHR list for the `/events` URL).
3. Type `example.com` in the scan seed input and click "Scan".
4. Immediately observe the top-right corner of the top bar for the run indicator.
5. Watch the Console for SSE-related log messages.
6. Watch the status bar at the bottom of the page.
7. Watch the entity table in the right pane for automatic updates.
8. Watch the observation graph in the left pane for new nodes appearing.
9. Wait for the scan to complete (monitor the Console for `run_completed` events).
10. After completion, observe the run indicator and status bar.

**Expected Results:**

- **Run indicator**: A green-bordered badge appears in the top bar with a pulsing green dot and text "SSE Live" (confirming the EventSource connected successfully).
- **Console messages** (in order):
  - `[EXPOSE] SSE connected: /v1/tenants/.../runs/.../events`
  - `[EXPOSE] SSE: collector_started ...` (one per collector that begins execution)
  - `[EXPOSE] SSE: entities_discovered (N new)` (as entities are found)
  - `[EXPOSE] SSE: collector_completed -- <collector_id>` (as each collector finishes)
  - `[EXPOSE] SSE: run_completed -- final refresh`
- **Network tab**: An EventStream connection to `/v1/tenants/{tenant_id}/runs/{run_id}/events` with `text/event-stream` content type. Messages stream in as `event: <type>\ndata: <json>`.
- **Status bar**: Shows "Streaming live events..." while SSE is connected.
- **Entity table**: Rows appear or update without a full page reload. The HTMX partial is re-fetched on each `entities_discovered` event.
- **Observation graph**: New nodes emerge with a fade-in animation (800ms). Edges draw in with a stroke-dasharray animation (600ms).
- **On run completion**:
  - The Console shows `run_completed -- final refresh`.
  - The SSE connection closes (Console shows no more SSE messages).
  - The run indicator disappears from the top bar (after a 2-second delay).
  - The status bar returns to "No active run | EXPOSE v0.1.0-dev".

**Pass Criteria:** The "SSE Live" indicator appears, the Console shows a sequence of SSE events, the entity table and graph update automatically during the scan, and the indicator clears after the run completes.

**Notes:**
- If the indicator shows "Run active" instead of "SSE Live", the SSE connection failed. Check the Console for error messages. The SSE endpoint is `GET /v1/tenants/{tenant_id}/runs/{run_id}/events`.
- SSE will auto-retry up to 3 times on connection error. After 3 failures, it falls back to HTMX polling (Console: "SSE: max retries reached, falling back to polling"). The status bar will show "Run in progress (polling)" instead.
- In Phase 1, some collectors may complete very quickly (especially if they timeout connecting to external services). The entire sequence might happen in under 5 seconds.
- If the EventSource fails immediately (no connection at all), the `RunEventBus` may not be initialized. Check that the API process started correctly.

---

## Test 9: Run Completion

**Objective:** Verify that when a scan completes, the run status bar shows the final "completed" state with all pipeline stages marked done, and all statistics are populated.

**Prerequisites:** A scan was started (Test 2). If it already completed, start a new scan for this test.

**Steps:**

1. If no scan is running, type `example.com` in the seed input and click "Scan".
2. Wait for the scan to complete. Monitor the Console for the `run_completed` message (this is the definitive signal). In Phase 1 dev mode, this typically takes 5-30 seconds.
3. Examine the status bar at the bottom of the page immediately when the run completes (before the 2-second clear delay).
4. If the status bar uses the HTMX-polled run status partial (from a page served with `active_run_id`), examine the pipeline stages and metrics displayed.
5. After the 2-second delay, observe the status bar return to idle.
6. Verify the entity count and entity table state.
7. Navigate to `http://localhost:8090/v1/tenants/{tenant_id}/runs` in a new tab to verify the run record via the API.

**Expected Results:**

- **During the run** -- the status bar (if using the run status partial at `/partials/run-status/{run_id}`) shows:
  - A pipeline stage progression: **Seed** -> **Collect** -> **Sanitize** -> **Attribute** -> **Done**.
  - Each stage is marked with an indicator:
    - Completed stages: green checkmark
    - Active stage: pulsing blue dot
    - Pending stages: hollow circle
  - Stage connectors: solid green between completed stages, gradient for active, gray for pending.
  - Metrics on the right side: `N discovered | M attributed | Xs elapsed | Run abcd1234...`
- **On completion**:
  - All five stages show green checkmarks (status `done`).
  - The "Done" stage is the final one marked complete.
  - The discovered count reflects the total number of entities found.
  - The attributed count shows how many entities reached "confirmed" attribution.
  - The elapsed time (seconds) stops incrementing.
- **After the 2-second delay**:
  - The status bar reverts to "No active run | EXPOSE v0.1.0-dev".
  - The run indicator in the top bar disappears.
- **API verification** (step 7): `GET /v1/tenants/{tenant_id}/runs` returns a JSON list including the completed run with `"state": "completed"` and a non-null `completed_at` timestamp.

**Pass Criteria:** The run transitions through all pipeline stages to "completed" state, all stages show green checkmarks, discovered/attributed counts are non-negative integers, elapsed time is accurate, and the run record shows `completed` state via the API.

**Notes:**
- If the status bar shows "Loading run status..." indefinitely, the run status partial endpoint may be failing. Check: `curl http://localhost:8090/partials/run-status/{run_id}`.
- In dev mode without a DB session factory, the partial returns placeholder data (`_PLACEHOLDER_RUN`) showing 47 discovered, 12 attributed, 134s elapsed, with the "collect" stage active. This is expected for verifying the template rendering.
- The `failed` state is a special case: all incomplete stages are marked as "failed" rather than "done". To test this, you would need to trigger a collector failure (e.g., by providing an unreachable seed).
- If the run seems stuck, check `docker-compose logs api` for errors in the background pipeline task.

---

## Test 10: Multi-Tenant Isolation

**Objective:** Verify that switching between tenants in the dropdown correctly resets the entity table, observation graph, and configuration panels, and that data from one tenant does not bleed into another.

**Prerequisites:** Setup complete. You need two tenants. Create a second tenant:
```bash
curl -s -X POST http://localhost:8090/v1/tenants/ \
  -H "Content-Type: application/json" \
  -d '{"name": "qa-test-tenant-2"}' | python3 -m json.tool
```
Record the second tenant's UUID.

**Steps:**

1. Navigate to `http://localhost:8090/dashboard`.
2. Select the first tenant ("qa-test-tenant") from the dropdown.
3. Wait for data to load. Note the entity count in the right pane.
4. Expand the "Tenant Config" panel. Add a scope rule: type `apex_domain`, value `first-tenant.com`. Click "Save Configuration". Note the confirmation message.
5. Collapse the Tenant Config panel.
6. Expand the "API Keys" panel. Note the configured count (e.g., "2/10 configured" if you ran Test 6).
7. Now switch to the second tenant ("qa-test-tenant-2") by selecting it from the dropdown.
8. Observe how each section of the dashboard resets.
9. Expand the "Tenant Config" panel for the second tenant.
10. Expand the "API Keys" panel for the second tenant.
11. Switch back to the first tenant.
12. Expand the "Tenant Config" panel again and verify your scope rule is still there.

**Expected Results:**

- **On tenant switch** (step 7), the following resets occur simultaneously:
  - **Entity table**: Clears and reloads for the new tenant. The entity count badge updates. If the new tenant has no entities, the empty state message appears.
  - **Observation graph**: The D3 graph is destroyed and re-initialized (`ExposeGraph.destroy()` called). Nodes from the previous tenant disappear. If the new tenant has no graph data, the SVG is empty.
  - **Run indicator**: If a run was active for the previous tenant, the SSE connection disconnects (Console: SSE connection should close). The run indicator disappears.
  - **Tenant Config panel**: Collapses automatically. The `tenantConfig` state resets to `null`.
  - **API Keys panel**: Collapses automatically. The `credentialSlots` state resets to `null`.
  - **Status bar**: Reverts to "No active run" (the previous tenant's run context is cleared).

- **Second tenant config** (step 9): When expanded, shows default/empty configuration (no scope rules, no enabled collectors, blank cron, "direct" egress profile, LLM disabled). This proves isolation -- the first tenant's scope rule (`first-tenant.com`) does NOT appear.

- **Second tenant credentials** (step 10): Shows "0/10 configured" (all slots "missing"). Even if you imported credentials for the first tenant, the second tenant's credential store is independent.

- **Switching back** (steps 11-12): The first tenant's configuration reloads from the API. The scope rule for `first-tenant.com` should still be present (it was saved in step 4). The credential count should show whatever was configured earlier.

**Pass Criteria:** Switching tenants clears entity data, resets the graph, disconnects SSE, and collapses config panels. Each tenant's configuration and credentials are independent -- no cross-tenant data leakage.

**Notes:**
- If data from the first tenant appears when the second tenant is selected, there may be a caching issue. Check that the HTMX requests include the correct `tenant_id` query parameter (visible in the Network tab).
- The graph polling interval (`_graphPollHandle`) is cleared on tenant switch. Verify in the Console that no stale graph fetches fire for the old tenant after switching.
- If SSE was connected for a run on tenant A, switching to tenant B should call `disconnectSSE()`. Verify in the Console that the EventSource closes cleanly.
- In Phase 1 dev mode (no DB session factory), the entity partial returns the same placeholder data for any tenant ID. This is a known limitation -- the entity table will show the same rows for both tenants. To verify true isolation, use the API directly: `curl http://localhost:8090/v1/tenants/{tenant_id}/entities` should return different data per tenant (when the DB is wired).
- Configuration isolation is fully testable even in Phase 1, since the in-memory `_configs` dict is keyed by tenant UUID.
