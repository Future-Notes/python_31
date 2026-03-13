// static/js/calendar.js (updated)
(function () {
  let calendar;
  let calendars = [];
  let notesCache = [];
  let userTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  let selectedEventDbId = null;
  // Recurrence state — set when an existing recurring event is opened/dragged
  let selectedEventRRule = null;
  let selectedEventOriginalStart = null;
  let selectedEventOriginalEnd = null;

  function formatISOLocalInput(dtIso) {
    if (!dtIso) return "";
    const d = new Date(dtIso);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  let currentCalendarId = localStorage.getItem("active_calendar_id") || null;

  async function api(path, opts = {}) {
    opts.headers = opts.headers || {};
    const paramName = path.includes('/google') ? 'local_calendar_id' : 'calendar_id';
    const skipInjection = path.startsWith('/api/calendars') && !path.includes('/api/calendars/');

    if (currentCalendarId && !skipInjection) {
      const method = (opts.method || 'GET').toUpperCase();
      if (method === 'GET' || method === 'DELETE') {
        const separator = path.includes('?') ? '&' : '?';
        path = `${path}${separator}${paramName}=${currentCalendarId}`;
      } else {
        opts.body = opts.body || {};
        if (typeof opts.body === "object" && !opts.body[paramName]) {
          opts.body[paramName] = parseInt(currentCalendarId, 10);
        }
      }
    }

    if (opts.body && typeof opts.body === "object") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    opts.credentials = opts.credentials || "include";

    const r = await fetch(path, opts);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw j;
    return j;
  }

  // -----------------------------------------------------------------------
  // Recurrence helpers
  // -----------------------------------------------------------------------

  const RRULE_DAY_ABBR = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'];

  /**
   * Parse an RRULE string into a plain key/value object.
   * Accepts both "RRULE:FREQ=WEEKLY;..." and "FREQ=WEEKLY;..." forms.
   */
  function parseRRule(rruleString) {
    if (!rruleString) return {};
    const s = rruleString.startsWith("RRULE:") ? rruleString.slice(6) : rruleString;
    const parts = {};
    s.split(";").forEach(p => {
      const eq = p.indexOf("=");
      if (eq !== -1) parts[p.slice(0, eq)] = p.slice(eq + 1);
    });
    return parts;
  }

  /** Serialise a parsed RRULE parts object back to "RRULE:..." string. */
  function serializeRRule(parts) {
    return "RRULE:" + Object.entries(parts).map(([k, v]) => `${k}=${v}`).join(";");
  }

  /**
   * Given the occurrence start date and the series RRULE, compute the Date
   * of the *next* occurrence after startDate.
   */
  function computeNextOccurrence(startDate, rruleString) {
    if (!startDate || !rruleString) return null;
    const parts = parseRRule(rruleString);
    const freq = parts.FREQ || "WEEKLY";
    const interval = parseInt(parts.INTERVAL || "1", 10);
    const next = new Date(startDate);
    switch (freq) {
      case "DAILY": next.setDate(next.getDate() + interval); break;
      case "WEEKLY": next.setDate(next.getDate() + 7 * interval); break;
      case "MONTHLY": next.setMonth(next.getMonth() + interval); break;
      case "YEARLY": next.setFullYear(next.getFullYear() + interval); break;
      default: next.setDate(next.getDate() + 7);
    }
    return next;
  }

  /**
   * For WEEKLY recurrences: swap the BYDAY abbreviation that matches oldDate
   * with the one matching newDate (handles multi-day rules like BYDAY=FR,SA).
   * Returns the RRULE unchanged for other frequencies.
   */
  function updateRRuleForDayChange(rruleString, oldDate, newDate) {
    if (!rruleString) return rruleString;
    const parts = parseRRule(rruleString);
    if (parts.FREQ === "WEEKLY" && parts.BYDAY) {
      const oldAbbr = RRULE_DAY_ABBR[oldDate.getDay()];
      const newAbbr = RRULE_DAY_ABBR[newDate.getDay()];
      if (oldAbbr !== newAbbr) {
        const days = parts.BYDAY.split(",").map(d => d.trim());
        const idx = days.indexOf(oldAbbr);
        if (idx !== -1) days[idx] = newAbbr;
        else days.push(newAbbr);
        parts.BYDAY = [...new Set(days)].join(",");
      }
    }
    return serializeRRule(parts);
  }

  /**
   * Build the { start, end } strings for an API payload.
   *   isAllDay → date-only "YYYY-MM-DD" strings (no UTC shift)
   *   timed    → full UTC ISO strings
   */
  function buildDatePayload(startDate, endDate, isAllDay) {
    const pad = n => String(n).padStart(2, '0');
    const toDateStr = d => d
      ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
      : null;

    let payloadStart, payloadEnd;
    if (isAllDay) {
      payloadStart = startDate ? toDateStr(startDate) : null;
      if (endDate) {
        payloadEnd = toDateStr(endDate);
      } else if (payloadStart) {
        const tmp = new Date(payloadStart + "T00:00:00");
        tmp.setDate(tmp.getDate() + 1);
        payloadEnd = toDateStr(tmp);
      } else {
        payloadEnd = null;
      }
    } else {
      payloadStart = startDate ? startDate.toISOString() : null;
      if (endDate) {
        payloadEnd = endDate.toISOString();
      } else if (payloadStart) {
        const tmp = new Date(payloadStart);
        tmp.setHours(tmp.getHours() + 1);
        payloadEnd = tmp.toISOString();
      } else {
        payloadEnd = null;
      }
    }
    return { start: payloadStart, end: payloadEnd };
  }

  /**
   * Show a polished in-page dialog asking the user how to handle a recurring
   * event edit/drag. Resolves with 'all', 'one', or 'cancel'.
   */
  function showRecurrenceChoiceDialog() {
    return new Promise(resolve => {
      const overlay = document.createElement('div');
      overlay.style.cssText = [
        'position:fixed', 'inset:0', 'background:rgba(0,0,0,0.72)',
        'z-index:10000', 'display:flex', 'align-items:center', 'justify-content:center',
        'backdrop-filter:blur(4px)', '-webkit-backdrop-filter:blur(4px)'
      ].join(';');

      const box = document.createElement('div');
      box.style.cssText = [
        'background:#16162a', 'border:1px solid rgba(255,255,255,0.09)',
        'border-radius:16px', 'padding:28px 24px 22px', 'max-width:350px',
        'width:90%', 'box-shadow:0 24px 64px rgba(0,0,0,0.7)',
        'animation:rcdFadeIn 0.18s ease'
      ].join(';');

      if (!document.getElementById('rcd-style')) {
        const style = document.createElement('style');
        style.id = 'rcd-style';
        style.textContent = `
          @keyframes rcdFadeIn {
            from { opacity:0; transform:translateY(10px) scale(0.97); }
            to   { opacity:1; transform:none; }
          }
          .rcd-btn {
            display:block; width:100%; padding:11px 16px; border-radius:9px;
            font-size:14px; cursor:pointer; text-align:left;
            transition:background 0.15s, border-color 0.15s;
          }
          .rcd-btn-primary {
            border:none; background:#4f46e5; color:#fff;
            font-weight:500; margin-bottom:8px;
          }
          .rcd-btn-primary:hover { background:#4338ca; }
          .rcd-btn-secondary {
            border:1px solid rgba(255,255,255,0.13); background:transparent;
            color:#d4d4e8; margin-bottom:8px;
          }
          .rcd-btn-secondary:hover {
            border-color:rgba(255,255,255,0.25);
            background:rgba(255,255,255,0.04);
          }
          .rcd-btn-ghost {
            border:none; background:transparent;
            color:#6060a0; font-size:13px; text-align:center;
          }
          .rcd-btn-ghost:hover { color:#9090c0; }
        `;
        document.head.appendChild(style);
      }

      box.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <span style="font-size:22px">🔁</span>
          <h3 style="margin:0;color:#e8e8f8;font-size:16px;font-weight:600">Recurring event</h3>
        </div>
        <p style="margin:0 0 20px;color:#8888b0;font-size:13.5px;line-height:1.6">
          This event is part of a series. Which events do you want to update?
        </p>
        <button class="rcd-btn rcd-btn-primary"   data-result="all">All events in the series</button>
        <button class="rcd-btn rcd-btn-secondary" data-result="one">Only this event</button>
        <button class="rcd-btn rcd-btn-ghost"     data-result="cancel">Cancel</button>
      `;

      overlay.appendChild(box);
      document.body.appendChild(overlay);

      function cleanup(result) {
        document.body.removeChild(overlay);
        resolve(result);
      }

      box.querySelectorAll('.rcd-btn').forEach(btn => {
        btn.addEventListener('click', () => cleanup(btn.dataset.result));
      });
      overlay.addEventListener('click', e => { if (e.target === overlay) cleanup('cancel'); });
    });
  }

  // -----------------------------------------------------------------------
  // Sidebar / calendar management
  // -----------------------------------------------------------------------

  async function loadSidebarCalendars() {
    try {
      const fetched = await api("/api/calendars", { method: "GET" });
      calendars = Array.isArray(fetched) ? fetched : [];
      const container = document.getElementById("calendar-list");
      container.innerHTML = "";
      let foundCurrent = false;

      calendars.forEach(cal => {
        if (cal.id == currentCalendarId) foundCurrent = true;
        if (!currentCalendarId && cal.is_default) setCalendar(cal.id);

        const el = document.createElement("div");
        el.className = "sidebar-calendar-item";
        el.innerText = cal.name;
        if (cal.id == currentCalendarId) el.classList.add("active-calendar");
        el.onclick = () => switchCalendar(cal.id);
        container.appendChild(el);
      });

      if (!foundCurrent && calendars.length > 0) {
        setCalendar(calendars[0].id);
        loadSidebarCalendars();
        return;
      }
      updateGoogleSyncUI();
    } catch (e) {
      console.error("Fout bij ophalen kalenders:", e);
    }
  }

  function switchCalendar(id) {
    setCalendar(id);
    loadSidebarCalendars();
    if (window.fcInstance) window.fcInstance.refetchEvents();
    updateGoogleSyncUI();
  }

  function setCalendar(id) {
    currentCalendarId = id;
    localStorage.setItem("active_calendar_id", id);
  }

  async function updateGoogleSyncUI() {
    const btnConnect = document.getElementById("connect-google-btn");
    const syncControls = document.getElementById("google-sync-controls");
    const googleNameEl = document.getElementById("google-calendar-name");
    if (!btnConnect || !syncControls || !googleNameEl) return;

    try {
      const response = await api("/api/google/status", { method: "GET" });
      const res = await response.json?.() ?? response;

      if (res.error === "not allowed") {
        btnConnect.style.display = "none";
        syncControls.style.display = "none";
        googleNameEl.textContent = "—";
        return;
      }
      if (!res.connected) {
        btnConnect.style.display = "block";
        syncControls.style.display = "none";
        googleNameEl.textContent = "—";
        return;
      }
      if (res.linked) {
        btnConnect.style.display = "none";
        syncControls.style.display = "block";
        googleNameEl.textContent = res.google_calendar_name || res.google_calendar_id || "primary";
      } else {
        btnConnect.style.display = "block";
        syncControls.style.display = "none";
        googleNameEl.textContent = "—";
      }
    } catch (e) {
      console.error("Error fetching Google status:", e);
      btnConnect.style.display = "block";
      syncControls.style.display = "none";
      googleNameEl.textContent = "—";
    }
  }

  async function connectGoogle() {
    try {
      const res = await api(`/api/google/connect`);
      if (res?.auth_url) {
        window.location.href = res.auth_url;
      } else if (res?.already_connected) {
        await fetchGoogleStatus();
      } else {
        throw new Error("No auth_url returned and calendar not marked connected");
      }
    } catch (err) {
      console.error("Could not start Google flow", err);
      alert("Failed to start Google connect flow. See console.");
    }
  }

  async function fetchGoogleStatus() {
    try {
      const statusRes = await api(`/api/google/status`);
      if (statusRes.connected) console.log("Calendar connection status refreshed:", statusRes);
    } catch (err) {
      console.error("Failed to fetch Google status", err);
    }
  }

  async function syncGoogle() {
    const localCalId = localStorage.getItem("active_calendar_id");
    if (!localCalId) return alert("No local calendar selected");

    const btn = document.getElementById("sync-google-btn");
    btn.textContent = "Syncing...";
    btn.disabled = true;
    try {
      const res = await api("/api/google/sync", {
        method: "POST",
        body: { local_calendar_id: parseInt(localCalId, 10), direction: "both" }
      });
      if (res) {
        calendar.refetchEvents();
        alert(`Sync complete — pulled ${res.pulled}, pushed ${res.pushed}`);
      } else {
        alert("Sync finished with no result object");
      }
    } catch (err) {
      console.error("Sync failed", err);
      alert("Google sync failed — see console for details");
    } finally {
      btn.disabled = false;
      btn.textContent = "Sync \u2194 Local";
    }
  }

  async function disconnectGoogle() {
    if (!confirm("Disconnect Google calendar for this local calendar? This will stop syncing but will not delete any events.")) return;
    try {
      await api("/api/google/disconnect", { method: "POST", body: {} });
      await loadSidebarCalendars();
      await updateGoogleSyncUI();
    } catch (err) {
      console.error("Failed to disconnect Google", err);
      alert("Failed to disconnect Google. See console.");
    }
  }

  // -----------------------------------------------------------------------
  // Notes
  // -----------------------------------------------------------------------

  async function loadNotes() {
    try {
      const res = await api("/api/notes");
      notesCache = res;
      renderNotesPicker();
    } catch (err) {
      console.error("Failed to load notes:", err);
      notesCache = [];
      renderNotesPicker();
    }
  }

  function renderNotesPicker(selectedIds = []) {
    const container = document.getElementById("notes-picker");
    container.innerHTML = "";
    if (!notesCache || notesCache.length === 0) {
      container.innerHTML = '<div style="opacity:0.6">No notes</div>';
      return;
    }
    for (const n of notesCache) {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:6px;border-bottom:1px solid rgba(255,255,255,0.02)";
      const label = document.createElement("label");
      label.style.cssText = "flex:1;cursor:pointer";
      label.innerHTML = `
        <input type="checkbox" value="${n.id}" class="note-checkbox" style="margin-right:8px;">
        <strong style="font-size:13px">${n.title || ''}</strong>
        <div style="opacity:0.6;font-size:12px">${n.snippet || ''}</div>
      `;
      row.appendChild(label);
      container.appendChild(row);
    }
    for (const cb of container.querySelectorAll(".note-checkbox")) {
      if (selectedIds.includes(parseInt(cb.value))) cb.checked = true;
    }
  }

  function selectedNoteIds() {
    const arr = [];
    for (const cb of document.querySelectorAll("#notes-picker .note-checkbox")) {
      if (cb.checked) arr.push(parseInt(cb.value));
    }
    return arr;
  }

  function escapeHtml(s) {
    if (!s) return "";
    return s.replace(/[&<>"'`]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', "`": '&#96;' })[ch]);
  }

  // -----------------------------------------------------------------------
  // Recurrence UI
  // -----------------------------------------------------------------------

  function updateRRulePreview() {
    const freq = document.getElementById("recurrence-freq").value;
    if (!freq) {
      document.getElementById("rrule-preview").textContent = "No recurrence";
      return;
    }
    const interval = parseInt(document.getElementById("recurrence-interval").value) || 1;
    let parts = [`FREQ=${freq}`, `INTERVAL=${interval}`];

    if (freq === "WEEKLY") {
      const days = Array.from(document.querySelectorAll("#weekly-weekdays .weekday:checked")).map(i => i.value);
      if (days.length) parts.push(`BYDAY=${days.join(",")}`);
    }

    const endType = document.getElementById("recurrence-end-type").value;
    if (endType === "until") {
      const until = document.getElementById("recurrence-until").value;
      if (until) parts.push(`UNTIL=${until.replace(/-/g, "")}T000000Z`);
    } else if (endType === "count") {
      const cnt = parseInt(document.getElementById("recurrence-count").value) || 1;
      parts.push(`COUNT=${cnt}`);
    }

    const rrule = `RRULE:${parts.join(";")}`;
    document.getElementById("rrule-preview").textContent = rrule;
    return rrule;
  }

  function buildRRuleFromUI() {
    const freq = document.getElementById("recurrence-freq").value;
    if (!freq) return null;
    const interval = parseInt(document.getElementById("recurrence-interval").value) || 1;
    let parts = [`FREQ=${freq}`, `INTERVAL=${interval}`];
    if (freq === "WEEKLY") {
      const days = Array.from(document.querySelectorAll("#weekly-weekdays .weekday:checked")).map(i => i.value);
      if (days.length) parts.push(`BYDAY=${days.join(",")}`);
    }
    const endType = document.getElementById("recurrence-end-type").value;
    if (endType === "until") {
      const until = document.getElementById("recurrence-until").value;
      if (until) parts.push(`UNTIL=${until.replace(/-/g, "")}T000000Z`);
    } else if (endType === "count") {
      const cnt = parseInt(document.getElementById("recurrence-count").value) || 1;
      parts.push(`COUNT=${cnt}`);
    }
    return `RRULE:${parts.join(";")}`;
  }

  function clearRecurrenceUI() {
    document.getElementById("recurrence-freq").value = "";
    document.getElementById("recurrence-interval").value = 1;
    document.getElementById("recurrence-end-type").value = "never";
    document.getElementById("recurrence-until").style.display = "none";
    document.getElementById("recurrence-count").style.display = "none";
    document.getElementById("weekly-weekdays").style.display = "none";
    for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) cb.checked = false;
    document.getElementById("rrule-preview").textContent = "No recurrence";
  }

  function prefillRecurrenceFromRRule(rruleString) {
    if (!rruleString) return;
    const parts = parseRRule(rruleString);

    document.getElementById("recurrence-freq").value = parts.FREQ || "";
    document.getElementById("recurrence-interval").value = parts.INTERVAL || 1;

    if (parts.BYDAY) {
      document.getElementById("weekly-weekdays").style.display = "block";
      const activeDays = parts.BYDAY.split(",").map(d => d.trim());
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) {
        cb.checked = activeDays.includes(cb.value);
      }
    } else {
      document.getElementById("weekly-weekdays").style.display = "none";
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) cb.checked = false;
    }

    if (parts.UNTIL) {
      document.getElementById("recurrence-end-type").value = "until";
      document.getElementById("recurrence-until").style.display = "inline-block";
      const d = parts.UNTIL.slice(0, 8);
      document.getElementById("recurrence-until").value = `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}`;
      document.getElementById("recurrence-count").style.display = "none";
    } else if (parts.COUNT) {
      document.getElementById("recurrence-end-type").value = "count";
      document.getElementById("recurrence-count").style.display = "inline-block";
      document.getElementById("recurrence-count").value = parts.COUNT;
      document.getElementById("recurrence-until").style.display = "none";
    } else {
      document.getElementById("recurrence-end-type").value = "never";
      document.getElementById("recurrence-until").style.display = "none";
      document.getElementById("recurrence-count").style.display = "none";
    }
    updateRRulePreview();
  }

  // FIX: use recurrence_rule (eventsLoader field) not rrule (FC internal field)
  function showRecurrenceForEdit(rruleString) {
    if (!rruleString) {
      document.getElementById("recurrence-simple").value = "";
      document.getElementById("recurrence-advanced").style.display = "none";
      return;
    }
    const parts = parseRRule(rruleString);
    document.getElementById("recurrence-simple").value = parts.FREQ || "";
    document.getElementById("recurrence-advanced").style.display = "block";
    prefillRecurrenceFromRRule(rruleString);
  }

  async function createCalendar(name) {
    if (!name) return;
    const res = await api("/api/calendars", { method: "POST", body: { name } });
    await loadSidebarCalendars();
    return res;
  }

  // -----------------------------------------------------------------------
  // Modal open / close
  // -----------------------------------------------------------------------

  function openApptModal(isEditing) {
    document.getElementById("appt-modal").style.display = "flex";
    document.getElementById("delete-appt-btn").style.display = isEditing ? "inline-block" : "none";
  }

  function closeApptModal() {
    document.getElementById("appt-modal").style.display = "none";
    selectedEventDbId = null;
    selectedEventRRule = null;
    selectedEventOriginalStart = null;
    selectedEventOriginalEnd = null;
    clearRecurrenceUI();
    renderNotesPicker([]);
  }

  // -----------------------------------------------------------------------
  // Event click → open edit modal
  // -----------------------------------------------------------------------

  async function onEventClick(info) {
    const dbid = info.event.extendedProps.db_id;
    selectedEventDbId = dbid;

    // FIX: eventsLoader stores recurrence as `recurrence_rule`, not `rrule`
    selectedEventRRule = info.event.extendedProps.recurrence_rule || null;
    selectedEventOriginalStart = info.event.start;
    selectedEventOriginalEnd = info.event.end;

    document.getElementById("modal-title").textContent = "Edit appointment";
    document.getElementById("appt-title").value = info.event.title || "";
    document.getElementById("appt-desc").value = info.event.extendedProps.description || "";
    document.getElementById("appt-color").value = info.event.backgroundColor || "";
    updateColorSwatchFromInput();
    document.getElementById("appt-all-day").checked = !!info.event.allDay;
    document.getElementById("appt-start").value = formatISOLocalInput(info.event.start);

    let endValue = info.event.end;
    if (info.event.allDay && !endValue && info.event.start) {
      const tmp = new Date(info.event.start);
      tmp.setDate(tmp.getDate() + 1);
      endValue = tmp.toISOString();
    }
    document.getElementById("appt-end").value = formatISOLocalInput(endValue);

    // Populate recurrence UI from the stored recurrence_rule
    showRecurrenceForEdit(selectedEventRRule);

    const noteIds = info.event.extendedProps.notes || [];
    renderNotesPicker(noteIds);

    openApptModal(true);
  }

  // -----------------------------------------------------------------------
  // Date-select → open new appointment modal
  // -----------------------------------------------------------------------

  async function onDateSelect(selectionInfo) {
    selectedEventDbId = null;
    selectedEventRRule = null;
    selectedEventOriginalStart = null;
    selectedEventOriginalEnd = null;

    document.getElementById("modal-title").textContent = "New appointment";
    document.getElementById("appt-title").value = "";
    document.getElementById("appt-desc").value = "";
    document.getElementById("appt-color").value = "";
    document.getElementById("recurrence-simple").value = "";
    document.getElementById("recurrence-advanced").style.display = "none";
    updateColorSwatchFromInput();

    const startStr = selectionInfo.startStr || "";
    const endStr = selectionInfo.endStr || "";

    // Explicit allDay flag (set by handleDateClick) takes priority; fall back
    // to detecting a date-only "YYYY-MM-DD" string from drag-select.
    const isAllDay = (selectionInfo.allDay === true) ||
      /^\d{4}-\d{2}-\d{2}$/.test(startStr);

    document.getElementById("appt-all-day").checked = isAllDay;

    if (isAllDay) {
      const s = new Date(startStr + "T00:00:00");
      let e;
      if (endStr && /^\d{4}-\d{2}-\d{2}$/.test(endStr)) {
        e = new Date(endStr + "T00:00:00");
      } else {
        e = new Date(s.getTime() + 24 * 3600 * 1000);
      }
      document.getElementById("appt-start").value = formatISOLocalInput(s.toISOString());
      document.getElementById("appt-end").value = formatISOLocalInput(e.toISOString());
    } else {
      document.getElementById("appt-start").value = formatISOLocalInput(selectionInfo.startStr);
      document.getElementById("appt-end").value = formatISOLocalInput(selectionInfo.endStr);
    }

    clearRecurrenceUI();
    renderNotesPicker([]);
    openApptModal(false);
  }

  // -----------------------------------------------------------------------
  // Save appointment (create or update), with recurrence handling
  // -----------------------------------------------------------------------

  async function saveAppointment() {
    const title = document.getElementById("appt-title").value;
    const desc = document.getElementById("appt-desc").value;
    const colorVal = document.getElementById("appt-color").value;
    const startLocal = document.getElementById("appt-start").value;
    const endLocal = document.getElementById("appt-end").value;
    const allDay = document.getElementById("appt-all-day").checked;
    const calendarId = document.getElementById("appt-calendar").value;
    const notes = selectedNoteIds();
    const rrule = buildRRuleFromUI();
    const color = colorVal || null;

    // For all-day: send date-only strings to avoid UTC shifting
    function toPayloadDate(localStr, isAllDayEvent) {
      if (!localStr) return null;
      return isAllDayEvent ? localStr.slice(0, 10) : new Date(localStr).toISOString();
    }

    const newStart = toPayloadDate(startLocal, allDay);
    const newEnd = toPayloadDate(endLocal, allDay);

    const recurrenceEndDate = (() => {
      if (document.getElementById("recurrence-end-type").value !== "until") return null;
      const v = document.getElementById("recurrence-until").value;
      return v ? new Date(v).toISOString() : null;
    })();

    const basePayload = {
      title, description: desc,
      start: newStart, end: newEnd,
      is_all_day: allDay, color,
      recurrence_rule: rrule,
      recurrence_end_date: recurrenceEndDate,
      calendar_id: parseInt(calendarId),
      notes
    };

    try {
      if (!selectedEventDbId) {
        // ── New appointment ──────────────────────────────────────────────
        await api("/api/appointments", { method: "POST", body: basePayload });

      } else if (selectedEventRRule) {
        // ── Editing a recurring event → ask the user ─────────────────────
        const choice = await showRecurrenceChoiceDialog();
        if (choice === 'cancel') return; // leave modal open

        if (choice === 'all') {
          // Update the entire series with all modal values
          await api(`/api/appointments/${selectedEventDbId}`, {
            method: "PUT", body: basePayload
          });

        } else {
          // 'one': detach just this occurrence
          // 1) POST a one-off copy with modal values (no recurrence)
          await api("/api/appointments", {
            method: "POST",
            body: { ...basePayload, recurrence_rule: null, recurrence_end_date: null }
          });

          // 2) Advance the original series past this occurrence
          const nextStart = computeNextOccurrence(selectedEventOriginalStart, selectedEventRRule);
          if (nextStart) {
            const origDuration = (selectedEventOriginalEnd && selectedEventOriginalStart)
              ? selectedEventOriginalEnd - selectedEventOriginalStart
              : (allDay ? 24 * 3600 * 1000 : 3600 * 1000);
            const nextEnd = new Date(nextStart.getTime() + origDuration);
            const { start: advStart, end: advEnd } = buildDatePayload(nextStart, nextEnd, allDay);

            await api(`/api/appointments/${selectedEventDbId}`, {
              method: "PUT",
              body: { start: advStart, end: advEnd, is_all_day: allDay }
            });
          }
        }

      } else {
        // ── Editing a regular (non-recurring) appointment ─────────────────
        await api(`/api/appointments/${selectedEventDbId}`, {
          method: "PUT", body: basePayload
        });
      }

      calendar.refetchEvents();
      closeApptModal();
    } catch (err) {
      console.error(err);
      alert("Failed to save appointment");
    }
  }

  // -----------------------------------------------------------------------
  // Delete appointment
  // -----------------------------------------------------------------------

  async function deleteAppointment() {
    if (!selectedEventDbId) return;
    if (!confirm("Delete this appointment?")) return;
    await api(`/api/appointments/${selectedEventDbId}`, { method: "DELETE" });
    calendar.refetchEvents();
    closeApptModal();
  }

  // -----------------------------------------------------------------------
  // FullCalendar bootstrap
  // -----------------------------------------------------------------------

  function initFullCalendar() {
    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    const VIEW_BREAKPOINTS = { small: 480, medium: 768 };
    function getResponsiveView(width = window.innerWidth) {
      if (width <= VIEW_BREAKPOINTS.small) return 'timeGridDay';
      if (width <= VIEW_BREAKPOINTS.medium) return 'listWeek';
      return 'timeGridWeek';
    }
    const initialResponsiveView = getResponsiveView();

    calendars = Array.isArray(calendars) ? calendars.filter(Boolean) : [];

    // ── Events loader ──────────────────────────────────────────────────

    async function eventsLoader(fetchInfo, successCallback, failureCallback) {
      try {
        const start = encodeURIComponent(fetchInfo.startStr);
        const end = encodeURIComponent(fetchInfo.endStr);
        const res = await api(`/api/appointments?start=${start}&end=${end}`);

        const evts = (res || []).map(a => {
          const startVal = a.start || a.start_datetime;
          const endVal = a.end || a.end_datetime;
          const isAllDay = !!a.allDay || !!a.is_all_day ||
            (/^\d{4}-\d{2}-\d{2}$/.test(a.start) || /^\d{4}-\d{2}-\d{2}$/.test(a.start_datetime));

          let startField, endField;
          if (isAllDay) {
            startField = a.start || (a.start_datetime ? a.start_datetime.split('T')[0] : null);
            if (a.end) { endField = a.end; }
            else if (a.end_datetime) { endField = a.end_datetime.split('T')[0]; }
            else if (startField) {
              const tmp = new Date(startField + "T00:00:00");
              tmp.setDate(tmp.getDate() + 1);
              endField = tmp.toISOString().slice(0, 10);
            } else { endField = null; }
          } else {
            startField = startVal ? new Date(startVal) : null;
            endField = endVal ? new Date(endVal) : null;
          }

          return {
            id: a.id, title: a.title,
            start: startField, end: endField,
            allDay: isAllDay,
            backgroundColor: a.color || (window.userColors && window.userColors.btn),
            extendedProps: {
              db_id: a.db_id != null ? a.db_id : a.id,
              description: a.description,
              notes: a.notes || [],
              calendar_id: a.calendar_id,
              recurrence_rule: a.recurrence_rule || null,  // ← canonical field name
              google_event_id: a.google_event_id
            },
            rrule: a.rrule || undefined
          };
        });

        successCallback(evts);
      } catch (err) {
        console.error("events loader failed", err);
        failureCallback(err);
      }
    }

    // ── Drag / resize with recurrence handling ─────────────────────────

    async function handleEventDropOrResize(info) {
      const event = info.event;
      const oldEvent = info.oldEvent;
      const isAllDay = !!event.allDay;
      const rrule = event.extendedProps.recurrence_rule;

      // Build {start, end} payload strings from FullCalendar Date / string values
      function payloadFromFC(fcStart, fcEnd, allDay) {
        const pad = n => String(n).padStart(2, '0');
        const toDate = d => d ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : null;

        if (allDay) {
          const s = fcStart instanceof Date ? toDate(fcStart) : (typeof fcStart === 'string' ? fcStart : null);
          let e = fcEnd instanceof Date ? toDate(fcEnd) : (typeof fcEnd === 'string' ? fcEnd : null);
          if (!e && s) {
            const tmp = new Date(s + "T00:00:00");
            tmp.setDate(tmp.getDate() + 1);
            e = toDate(tmp);
          }
          if (!s || !e) return null;
          return { start: s, end: e };
        } else {
          const startDt = fcStart ? new Date(fcStart) : null;
          const endDt = fcEnd ? new Date(fcEnd) : null;
          const s = startDt ? startDt.toISOString() : null;
          let e = endDt ? endDt.toISOString() : null;
          if (!e && s) { const tmp = new Date(s); tmp.setHours(tmp.getHours() + 1); e = tmp.toISOString(); }
          if (!s || !e) return null;
          return { start: s, end: e };
        }
      }

      if (rrule) {
        // ── Recurring event dropped/resized → ask the user ──────────────
        const choice = await showRecurrenceChoiceDialog();

        if (choice === 'cancel') { info.revert(); return; }

        if (choice === 'all') {
          // Update entire series: new dates + smart RRULE mutation
          const dates = payloadFromFC(event.start, event.end, isAllDay);
          if (!dates) { info.revert(); return; }

          const updatedRRule = updateRRuleForDayChange(rrule, oldEvent.start, event.start);

          try {
            const r = await fetch(`/api/appointments/${event.extendedProps.db_id}`, {
              method: "PUT", credentials: "include",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                start: dates.start, end: dates.end,
                is_all_day: isAllDay, recurrence_rule: updatedRRule
              })
            });
            if (!r.ok) throw new Error("Update failed");
            calendar.refetchEvents();
          } catch (err) {
            console.error("Failed to update recurring series", err);
            info.revert();
          }

        } else {
          // 'one': detach this occurrence
          const dates = payloadFromFC(event.start, event.end, isAllDay);
          if (!dates) { info.revert(); return; }

          // POST one-off copy at new position
          const newEventPayload = {
            title: event.title,
            description: event.extendedProps.description,
            start: dates.start,
            end: dates.end,
            is_all_day: isAllDay,
            color: event.backgroundColor || null,
            recurrence_rule: null,
            calendar_id: parseInt(currentCalendarId, 10),
            notes: event.extendedProps.notes || []
          };

          // Advance original series past this occurrence
          const nextStart = computeNextOccurrence(oldEvent.start, rrule);
          if (!nextStart) { info.revert(); return; }

          const origDuration = (oldEvent.end && oldEvent.start)
            ? oldEvent.end - oldEvent.start
            : (isAllDay ? 24 * 3600 * 1000 : 3600 * 1000);
          const nextEnd = new Date(nextStart.getTime() + origDuration);
          const { start: advStart, end: advEnd } = buildDatePayload(nextStart, nextEnd, isAllDay);

          try {
            await Promise.all([
              fetch("/api/appointments", {
                method: "POST", credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(newEventPayload)
              }).then(r => { if (!r.ok) throw new Error("Create one-off failed"); }),

              fetch(`/api/appointments/${event.extendedProps.db_id}`, {
                method: "PUT", credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ start: advStart, end: advEnd, is_all_day: isAllDay })
              }).then(r => { if (!r.ok) throw new Error("Advance series failed"); })
            ]);
            calendar.refetchEvents();
          } catch (err) {
            console.error("Failed to detach occurrence", err);
            info.revert();
          }
        }

      } else {
        // ── Non-recurring: existing behaviour ───────────────────────────
        const dates = payloadFromFC(event.start, event.end, isAllDay);
        if (!dates) { console.warn("Drop/resize: could not build date payload."); info.revert(); return; }

        console.warn("Drag/resize -> payload:", dates, "db_id:", event.extendedProps.db_id);

        fetch(`/api/appointments/${event.extendedProps.db_id}`, {
          method: "PUT", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ start: dates.start, end: dates.end, is_all_day: isAllDay })
        })
          .then(r => { if (!r.ok) throw new Error("Update failed"); return r.json(); })
          .then(() => calendar.refetchEvents())
          .catch(err => { console.error("Failed to update via drag/resize", err); info.revert(); });
      }
    }

    // ── dateClick: single slot click ─────────────────────────────────────

    function handleDateClick(info) {
      if (info.allDay) {
        const startStr = info.dateStr;
        const tmp = new Date(startStr + "T00:00:00");
        tmp.setDate(tmp.getDate() + 1);
        const pad = n => String(n).padStart(2, '0');
        const endStr = `${tmp.getFullYear()}-${pad(tmp.getMonth() + 1)}-${pad(tmp.getDate())}`;
        onDateSelect({ startStr, endStr, allDay: true });
      } else {
        const start = info.date;
        const end = new Date(start.getTime() + 60 * 60 * 1000);
        onDateSelect({ startStr: start.toISOString(), endStr: end.toISOString(), allDay: false });
      }
    }

    // ── select: drag-select a range ──────────────────────────────────────

    function handleSelect(selectionInfo) {
      onDateSelect(selectionInfo);
      calendar.unselect();
    }

    // ── Build and render ─────────────────────────────────────────────────

    const options = {
      initialView: initialResponsiveView,
      timeZone: 'local',
      headerToolbar: {
        left: 'prev,next today', center: 'title',
        right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek'
      },
      selectable: true, selectMirror: true, editable: true,
      events: eventsLoader,
      select: handleSelect,
      dateClick: handleDateClick,
      eventClick: info => onEventClick(info),
      eventDrop: handleEventDropOrResize,
      eventResize: handleEventDropOrResize
    };

    try {
      calendar = new FullCalendar.Calendar(calendarEl, options);
      calendar.render();
      window.fcInstance = calendar;
    } catch (err) {
      console.error("FullCalendar init failed:", err);
      try {
        const fallback = new FullCalendar.Calendar(calendarEl, { initialView: 'dayGridMonth' });
        fallback.render();
        window.fcInstance = calendar = fallback;
      } catch (err2) {
        console.error("Fallback FullCalendar init also failed:", err2);
      }
    }

    // ── Responsive view switching ─────────────────────────────────────────

    let resizeTimer = null;
    let lastAppliedView = initialResponsiveView;

    function onResize() {
      const newView = getResponsiveView();
      if (newView === lastAppliedView) return;
      lastAppliedView = newView;
      try { calendar.changeView(newView, calendar.getDate()); }
      catch (e) { console.warn("Failed to change view on resize:", e); }
    }

    window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(onResize, 160); });
    window.addEventListener('orientationchange', () => setTimeout(onResize, 200));
  }

  // -----------------------------------------------------------------------
  // Color swatch
  // -----------------------------------------------------------------------

  function updateColorSwatchFromInput() {
    const inp = document.getElementById("appt-color");
    const label = document.getElementById("color-swatch-label");
    if (!inp) return;
    const v = inp.value;
    if (!v) {
      label.textContent = "No color";
      inp.style.boxShadow = "inset 0 0 0 1px rgba(255,255,255,0.03)";
      inp.style.background = "";
    } else {
      label.textContent = v.toUpperCase();
      inp.style.background = v;
    }
  }

  // -----------------------------------------------------------------------
  // Bootstrap entry point (called by auth flow after login)
  // -----------------------------------------------------------------------

  window.calendarBootstrap = async function () {
    try {
      await loadSidebarCalendars();
      await loadNotes();

      document.addEventListener("click", function (e) {
        if (e.target && e.target.id === "clear-color-btn") {
          const inp = document.getElementById("appt-color");
          if (inp) { inp.value = ""; updateColorSwatchFromInput(); }
        }
      });
      document.addEventListener("input", function (e) {
        if (e.target && e.target.id === "appt-color") updateColorSwatchFromInput();
      });

      document.getElementById("recurrence-simple").addEventListener("change", (e) => {
        const val = e.target.value;
        const adv = document.getElementById("recurrence-advanced");
        if (!adv) return;
        if (!val) {
          adv.style.display = "none";
          document.getElementById("recurrence-freq").value = "";
          clearRecurrenceUI();
        } else {
          adv.style.display = "block";
          document.getElementById("recurrence-freq").value = val;
          document.getElementById("weekly-weekdays").style.display = val === "WEEKLY" ? "block" : "none";
          updateRRulePreview();
        }
      });

      initFullCalendar();

      document.getElementById("recurrence-freq").addEventListener("change", (e) => {
        document.getElementById("weekly-weekdays").style.display = e.target.value === "WEEKLY" ? "block" : "none";
        updateRRulePreview();
      });
      document.getElementById("recurrence-interval").addEventListener("input", updateRRulePreview);
      document.getElementById("recurrence-end-type").addEventListener("change", (e) => {
        const v = e.target.value;
        document.getElementById("recurrence-until").style.display = v === "until" ? "inline-block" : "none";
        document.getElementById("recurrence-count").style.display = v === "count" ? "inline-block" : "none";
        updateRRulePreview();
      });
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) {
        cb.addEventListener("change", updateRRulePreview);
      }
      document.getElementById("recurrence-until").addEventListener("change", updateRRulePreview);
      document.getElementById("recurrence-count").addEventListener("input", updateRRulePreview);
      document.getElementById("clear-recurrence").addEventListener("click", () => clearRecurrenceUI());

    } catch (err) {
      console.error("calendarBootstrap failed", err);
    }
  };

  // -----------------------------------------------------------------------
  // Global click wiring
  // -----------------------------------------------------------------------

  document.addEventListener("click", function (e) {
    if (!e.target) return;
    const id = e.target.id;
    if (id === "create-calendar-btn") { const name = document.getElementById("new-calendar-name").value.trim(); createCalendar(name).then(() => document.getElementById("new-calendar-name").value = ""); }
    else if (id === "close-appt-modal") { closeApptModal(); }
    else if (id === "save-appt-btn") { saveAppointment(); }
    else if (id === "delete-appt-btn") { deleteAppointment(); }
    else if (id === "connect-google-btn") { connectGoogle(); }
    else if (id === "sync-google-btn") { syncGoogle(); }
    else if (id === "disconnect-google-btn") { disconnectGoogle(); }
  });

})();

// -------------------------------------------------------------------------
// Sidebar toggle (mobile)
// -------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  (function setupSidebar() {
    const sidebar = document.getElementById("calendar-sidebar");
    const toggle = document.getElementById("calendar-sidebar-toggle");
    const closeBtn = document.getElementById("calendar-sidebar-close");
    const overlay = document.getElementById("calendar-sidebar-overlay");
    const MOBILE_BP = 768;

    if (!sidebar || !toggle || !overlay) return;

    const isMobile = () => window.innerWidth <= MOBILE_BP;

    function showToggleIfMobile() { toggle.style.display = isMobile() ? '' : 'none'; }

    function openSidebar() {
      sidebar.classList.add('open');
      sidebar.setAttribute('aria-hidden', 'false');
      toggle.setAttribute('aria-expanded', 'true');
      overlay.setAttribute('aria-hidden', 'false');
      document.documentElement.style.overflow = 'hidden';
      document.body.style.overflow = 'hidden';
      if (isMobile()) toggle.style.display = 'none';
      const focusable = sidebar.querySelector('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
      if (focusable) focusable.focus();
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      sidebar.setAttribute('aria-hidden', isMobile() ? 'true' : 'false');
      toggle.setAttribute('aria-expanded', 'false');
      overlay.setAttribute('aria-hidden', 'true');
      document.documentElement.style.overflow = '';
      document.body.style.overflow = '';
      if (isMobile()) { toggle.style.display = ''; toggle.focus(); }
      else { toggle.style.display = 'none'; }
    }

    function initState() {
      showToggleIfMobile();
      if (isMobile()) {
        sidebar.setAttribute('aria-hidden', 'true');
        toggle.setAttribute('aria-expanded', 'false');
        overlay.setAttribute('aria-hidden', 'true');
        sidebar.classList.remove('open');
      } else {
        sidebar.setAttribute('aria-hidden', 'false');
        toggle.setAttribute('aria-expanded', 'false');
        overlay.setAttribute('aria-hidden', 'true');
        sidebar.classList.remove('open');
        document.documentElement.style.overflow = '';
        document.body.style.overflow = '';
      }
    }

    toggle.addEventListener('click', e => { e.preventDefault(); openSidebar(); });
    closeBtn && closeBtn.addEventListener('click', e => { e.preventDefault(); closeSidebar(); });
    overlay.addEventListener('click', () => closeSidebar());
    document.addEventListener('keydown', ev => {
      if (ev.key === 'Escape' && sidebar.classList.contains('open')) closeSidebar();
    });

    let sbResizeTimer = null;
    window.addEventListener('resize', () => {
      clearTimeout(sbResizeTimer);
      sbResizeTimer = setTimeout(() => {
        if (!isMobile()) { closeSidebar(); sidebar.setAttribute('aria-hidden', 'false'); }
        else { sidebar.setAttribute('aria-hidden', 'true'); showToggleIfMobile(); }
      }, 180);
    });

    initState();
  })();
});