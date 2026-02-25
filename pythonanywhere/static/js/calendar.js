// static/js/calendar.js (updated)
(function() {
  let calendar;
  let calendars = [];
  let notesCache = [];
  let userTz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  let selectedEventDbId = null;

  function formatISOLocalInput(dtIso) {
      if (!dtIso) return "";
      const d = new Date(dtIso);

      const pad = n => String(n).padStart(2, '0');

      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  // Houdt het actieve ID bij (haal direct uit localStorage indien beschikbaar)
  let currentCalendarId = localStorage.getItem("active_calendar_id") || null;

  async function api(path, opts = {}) {
    opts.headers = opts.headers || {};

    const paramName = path.includes('/google') ? 'local_calendar_id' : 'calendar_id';

    // Only inject calendar_id for endpoints that actually want it
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
  // ... rest unchanged

    if (opts.body && typeof opts.body === "object") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }

    // before calling fetch, ensure cookies are included
    opts.credentials = opts.credentials || "include";

    const r = await fetch(path, opts);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw j;
    return j;
  }

  async function loadSidebarCalendars() {
    try {
      // after fetching:
      const fetched = await api("/api/calendars", { method: "GET" });
      calendars = Array.isArray(fetched) ? fetched : [];
      const container = document.getElementById("calendar-list");
      container.innerHTML = "";

      let foundCurrent = false;

      calendars.forEach(cal => {
        // If our stored ID exists among real calendars, keep it
        if (cal.id == currentCalendarId) foundCurrent = true;

        // Set default only if nothing is selected yet
        if (!currentCalendarId && cal.is_default) setCalendar(cal.id);

        const el = document.createElement("div");
        el.className = "sidebar-calendar-item";
        el.innerText = cal.name;
        if (cal.id == currentCalendarId) el.classList.add("active-calendar");
        el.onclick = () => switchCalendar(cal.id);
        container.appendChild(el);
      });

      // Stale ID (deleted calendar) — fall back to first available
      if (!foundCurrent && calendars.length > 0) {
        setCalendar(calendars[0].id);
        loadSidebarCalendars(); // re-render with correct active highlight
        return;
      }

      updateGoogleSyncUI();
    } catch (e) {
      console.error("Fout bij ophalen kalenders:", e);
    }
  }

  function switchCalendar(id) {
    setCalendar(id);
    loadSidebarCalendars(); // Refresh sidebar om de "active" class te updaten

    if (window.fcInstance) {
      window.fcInstance.refetchEvents(); // Trigger FullCalendar om opnieuw te laden met het nieuwe calendar_id
    }

    updateGoogleSyncUI(); // Zorg dat de Google knoppen kloppen bij de nieuwe kalender
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
      // Fetch status
      const response = await api("/api/google/status", { method: "GET" });

      // Ensure we have JSON
      const res = await response.json?.() ?? response;

      // Hide all Google options if not allowed
      if (res.error === "not allowed") {
        btnConnect.style.display = "none";
        syncControls.style.display = "none";
        googleNameEl.textContent = "—";
        return;
      }

      // No credentials -> show Connect
      if (!res.connected) {
        btnConnect.style.display = "block";
        syncControls.style.display = "none";
        googleNameEl.textContent = "—";
        return;
      }

      // Linked -> show sync controls
      if (res.linked) {
        btnConnect.style.display = "none";
        syncControls.style.display = "block";
        googleNameEl.textContent = res.google_calendar_name || res.google_calendar_id || "primary";
      } else {
        // Credentials exist but not linked
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

  // startGoogleConnectFlow still calls /api/google/connect through connectGoogle()
  async function connectGoogle() {
    try {
      const res = await api(`/api/google/connect`);

      if (res?.auth_url) {
        // Normal OAuth flow: redirect user to Google consent page
        window.location.href = res.auth_url;
      } else if (res?.already_connected) {
        // Credentials already exist for this calendar, no redirect needed
        console.log("Google calendar already connected for this local calendar.");
        // Optionally, update frontend state or refetch status
        await fetchGoogleStatus();
      } else {
        throw new Error("No auth_url returned and calendar not marked connected");
      }
    } catch (err) {
      console.error("Could not start Google flow", err);
      alert("Failed to start Google connect flow. See console.");
    }
  }

  // Example helper to refresh status for this local calendar
  async function fetchGoogleStatus() {
    try {
      const statusRes = await api(`/api/google/status`);
      if (statusRes.connected) {
        console.log("Calendar connection status refreshed:", statusRes);
        // Update your frontend UI accordingly
      }
    } catch (err) {
      console.error("Failed to fetch Google status", err);
    }
  }

  async function syncGoogle() {
    // No google_calendar_select anymore: we always sync to 'primary' on backend
    const localCalId = localStorage.getItem("active_calendar_id");
    if (!localCalId) return alert("No local calendar selected");

    const btn = document.getElementById("sync-google-btn");
    btn.textContent = "Syncing...";
    btn.disabled = true;
    try {
      // only send the local_calendar_id and direction — backend uses primary
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
      btn.textContent = "Sync ↔ Local";
    }
  }

  async function disconnectGoogle() {
    // This will ask server to disable mapping for THIS local calendar only
    if (!confirm("Disconnect Google calendar for this local calendar? This will stop syncing but will not delete any events.")) return;
    try {
      // backend will use injected local_calendar_id parameter
      await api("/api/google/disconnect", { method: "POST", body: {} });
      // Refresh UI
      await loadSidebarCalendars();
      await updateGoogleSyncUI();
    } catch (err) {
      console.error("Failed to disconnect Google", err);
      alert("Failed to disconnect Google. See console.");
    }
  }

  // ---------------- Notes loader & picker ----------------
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

  function renderNotesPicker(selectedIds=[]) {
    const container = document.getElementById("notes-picker");
    container.innerHTML = "";
    if (!notesCache || notesCache.length === 0) {
      container.innerHTML = '<div style="opacity:0.6">No notes</div>';
      return;
    }
    for (const n of notesCache) {
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.justifyContent = "space-between";
      row.style.alignItems = "center";
      row.style.padding = "6px";
      row.style.borderBottom = "1px solid rgba(255,255,255,0.02)";
      const label = document.createElement("label");
      label.style.flex = "1";
      label.style.cursor = "pointer";
      label.innerHTML = `<input type="checkbox" value="${n.id}" class="note-checkbox" style="margin-right:8px;"> <strong style="font-size:13px">${escapeHtml(n.title)}</strong><div style="opacity:0.6; font-size:12px">${escapeHtml(n.snippet || '')}</div>`;
      row.appendChild(label);
      container.appendChild(row);
    }
    // mark selected
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
    return s.replace(/[&<>"'`]/g, function(ch){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;',"`":'&#96;'})[ch]; });
  }

  // ---------------- Recurrence picker helpers ----------------
  function updateRRulePreview() {
    const freq = document.getElementById("recurrence-freq").value;
    if (!freq) {
      document.getElementById("rrule-preview").textContent = "No recurrence";
      return;
    }
    const interval = parseInt(document.getElementById("recurrence-interval").value) || 1;
    let parts = [`FREQ=${freq}`, `INTERVAL=${interval}`];

    if (freq === "WEEKLY") {
      const days = Array.from(document.querySelectorAll("#weekly-weekdays .weekday:checked")).map(i=>i.value);
      if (days.length) parts.push(`BYDAY=${days.join(",")}`);
    }

    const endType = document.getElementById("recurrence-end-type").value;
    if (endType === "until") {
      const until = document.getElementById("recurrence-until").value;
      if (until) parts.push(`UNTIL=${until.replace(/-/g,"")}T000000Z`);
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
      const days = Array.from(document.querySelectorAll("#weekly-weekdays .weekday:checked")).map(i=>i.value);
      if (days.length) parts.push(`BYDAY=${days.join(",")}`);
    }
    const endType = document.getElementById("recurrence-end-type").value;
    if (endType === "until") {
      const until = document.getElementById("recurrence-until").value;
      if (until) parts.push(`UNTIL=${until.replace(/-/g,"")}T000000Z`);
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

  async function createCalendar(name) {
    if (!name) return;
    const res = await api("/api/calendars", { method: "POST", body: { name } });
    await loadSidebarCalendars();
    return res;
  }

  function fcEventSourceFetch(info, successCallback, failureCallback) {
    const params = new URLSearchParams({
      start: info.startStr,
      end: info.endStr
    });
    const sel = document.getElementById("appt-calendar");
    const calendar_id = sel ? sel.value : null;
    if (calendar_id) params.append("calendar_id", calendar_id);

    fetch("/api/appointments?" + params.toString(), { credentials: "include" })
      .then(r => r.json())
      .then(events => {
        successCallback(events.map(e => {
            return {
            id: e.id,               // kept as the FC-visible id (e.g. "local-1")
            title: e.title,
            start: e.start,
            end: e.end,
            allDay: e.allDay,
            backgroundColor: e.color || undefined,
            extendedProps: {
                db_id: e.db_id,       // <-- use numeric DB id here (from server)
                description: e.description,
                google_event_id: e.google_event_id,
                notes: e.notes,
                rrule: e.rrule
            },
            rrule: e.rrule ? e.rrule : undefined
            };
        }));
        })
      .catch(failureCallback);
  }

  function openApptModal(ev) {
    document.getElementById("appt-modal").style.display = "flex";
    document.getElementById("delete-appt-btn").style.display = ev ? "inline-block" : "none";
  }
  function closeApptModal() {
    document.getElementById("appt-modal").style.display = "none";
    selectedEventDbId = null;
    clearRecurrenceUI();
    renderNotesPicker([]);
  }

  // ---------------- Event handlers ----------------
  async function onEventClick(info) {
    const dbid = info.event.extendedProps.db_id;
    selectedEventDbId = dbid;
    document.getElementById("modal-title").textContent = "Edit appointment";
    document.getElementById("appt-title").value = info.event.title || "";
    document.getElementById("appt-desc").value = info.event.extendedProps.description || "";
    document.getElementById("appt-color").value = info.event.backgroundColor || "";
    updateColorSwatchFromInput();
    document.getElementById("appt-all-day").checked = !!info.event.allDay;
    document.getElementById("appt-start").value = formatISOLocalInput(info.event.start);
    // handle possible missing end for all-day events
    let endValue = info.event.end;
    if (info.event.allDay && !endValue && info.event.start) {
      // if there is no end, set end to start + 1 day
      const tmp = new Date(info.event.start);
      tmp.setDate(tmp.getDate() + 1);
      endValue = tmp.toISOString();
    }
    document.getElementById("appt-end").value = formatISOLocalInput(endValue);

    // set calendar select if possible
    // We'll try to set the calendar select to the appointment's calendar id if available in event.extendedProps
    // (Backend currently sends calendar_id in event.extendedProps.db_id mapping; if not, let user select default)
    // For recurrence: if event has rrule string, prefill the recurrence UI
    const rrule = info.event.extendedProps.rrule || (info.event._def && info.event._def.recurringDef && info.event._def.recurringDef.type ? info.event._def.recurringDef : null);
    showRecurrenceForEdit(rrule);

    // notes
    const noteIds = info.event.extendedProps.notes || [];
    renderNotesPicker(noteIds);

    openApptModal(true);
  }

  function prefillRecurrenceFromRRule(rruleString) {
    // Accept both 'RRULE:...' and 'FREQ=...' style
    const s = rruleString.startsWith("RRULE:") ? rruleString.slice(6) : rruleString;
    const parts = {};
    s.split(";").forEach(p => {
      const [k,v] = p.split("=");
      parts[k] = v;
    });
    document.getElementById("recurrence-freq").value = parts.FREQ || "";
    document.getElementById("recurrence-interval").value = parts.INTERVAL || 1;
    if (parts.BYDAY) {
      document.getElementById("weekly-weekdays").style.display = "block";
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) cb.checked = (parts.BYDAY.split(",").indexOf(cb.value) !== -1);
    } else {
      document.getElementById("weekly-weekdays").style.display = "none";
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) cb.checked = false;
    }
    if (parts.UNTIL) {
      document.getElementById("recurrence-end-type").value = "until";
      document.getElementById("recurrence-until").style.display = "inline-block";
      // UNTIL may be like 20250220T000000Z -> take first 8 digits to form date
      const d = parts.UNTIL.slice(0,8);
      document.getElementById("recurrence-until").value = `${d.slice(0,4)}-${d.slice(4,6)}-${d.slice(6,8)}`;
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

  async function onDateSelect(selectionInfo) {
    selectedEventDbId = null;
    document.getElementById("modal-title").textContent = "New appointment";
    document.getElementById("appt-title").value = "";
    document.getElementById("appt-desc").value = "";
    document.getElementById("appt-color").value = "";
    document.getElementById("recurrence-simple").value = "";
    document.getElementById("recurrence-advanced").style.display = "none";
    updateColorSwatchFromInput();

    // detect all-day: FullCalendar selectionInfo.startStr may be date-only ("YYYY-MM-DD")
    const startStr = selectionInfo.startStr || "";
    const endStr = selectionInfo.endStr || "";

    const isAllDay = /^\d{4}-\d{2}-\d{2}$/.test(startStr);

    document.getElementById("appt-all-day").checked = !!isAllDay;

    if (isAllDay) {
      // If end is provided as date (FullCalendar uses exclusive end), set end to end-1 day for UI convenience
      // but the input expects a datetime-local; we'll show start at local midnight and end at local 00:00 of the following day
      const s = new Date(startStr + "T00:00:00");
      const e = endStr && /^\d{4}-\d{2}-\d{2}$/.test(endStr) ? new Date(endStr + "T00:00:00") : new Date(s.getTime() + 24*3600*1000);
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

  async function saveAppointment() {
    const title = document.getElementById("appt-title").value;
    const desc = document.getElementById("appt-desc").value;
    const colorVal = document.getElementById("appt-color").value;
    const startLocal = document.getElementById("appt-start").value;
    const endLocal = document.getElementById("appt-end").value;
    const allDay = document.getElementById("appt-all-day").checked;
    const calendarId = document.getElementById("appt-calendar").value;
    const notes = selectedNoteIds();

    // localToISOWithTZ: convert local datetime-local value to an ISO with timezone (UTC)
    function localToISOWithTZ(localStr) {
        if (!localStr) return null;
        return new Date(localStr).toISOString();
    }

    const rrule = buildRRuleFromUI();

    if (colorVal) color = colorVal;
    else color = null;

    const payload = {
      title,
      description: desc,
      start: localToISOWithTZ(startLocal),
      end: localToISOWithTZ(endLocal),
      is_all_day: allDay,
      color,
      recurrence_rule: rrule,
      recurrence_end_date: (document.getElementById("recurrence-end-type").value === "until") ? (document.getElementById("recurrence-until").value ? (new Date(document.getElementById("recurrence-until").value).toISOString()) : null) : null,
      calendar_id: parseInt(calendarId),
      notes: notes
    };

    try {
      if (selectedEventDbId) {
        await api(`/api/appointments/${selectedEventDbId}`, { method: "PUT", body: payload });
      } else {
        await api("/api/appointments", { method: "POST", body: payload });
      }
      calendar.refetchEvents();
      closeApptModal();
    } catch (err) {
      console.error(err);
      alert("Failed to save appointment");
    }
  }

  async function deleteAppointment() {
    if (!selectedEventDbId) return;
    if (!confirm("Delete this appointment?")) return;
    await api(`/api/appointments/${selectedEventDbId}`, { method: "DELETE" });
    calendar.refetchEvents();
    closeApptModal();
  }

  function initFullCalendar() {
    const calendarEl = document.getElementById("calendar");
    if (!calendarEl) return;

    // -----------------------
    // Responsive view helper
    // -----------------------
    // Choose views per width. Adjust breakpoints or views as you like.
    const VIEW_BREAKPOINTS = {
      small: 480,   // <=480px  -> timeGridDay (focus on single day)
      medium: 768   // <=768px  -> listWeek (compact week list)
      // >768px -> timeGridWeek (desktop)
    };

    function getResponsiveView(width = window.innerWidth) {
      if (width <= VIEW_BREAKPOINTS.small) return 'timeGridDay';
      if (width <= VIEW_BREAKPOINTS.medium) return 'listWeek';
      return 'timeGridWeek';
    }

    // initialView determined before creating calendar
    const initialResponsiveView = getResponsiveView();

    // (rest of your defensive setup for calendars and fcCals)
    calendars = Array.isArray(calendars) ? calendars.filter(Boolean) : [];
    const fcCals = calendars.map(c => ({
      id: String(c && c.id != null ? c.id : ''),
      title: (c && typeof c.name === 'string' && c.name.trim().length) ? c.name : (c && c.id ? `Calendar ${c.id}` : 'Default calendar'),
      color: (c && c.color) || ((window.userColors && window.userColors.hdr) || '#444'),
      googleCalendar: (c && c.google_event_id) || undefined
    }));
    console.log("initFullCalendar — sanitized fcCals:", fcCals, "userColors:", window.userColors);

    // Helper: convert fetchInfo start/end into event objects
    async function eventsLoader(fetchInfo, successCallback, failureCallback) {
      try {
        // encode to preserve "+" and other characters
        const start = encodeURIComponent(fetchInfo.startStr);
        const end = encodeURIComponent(fetchInfo.endStr);
        const res = await api(`/api/appointments?start=${start}&end=${end}`);

        const evts = (res || []).map(a => {
          // Backend sends:
          // - for timed events: "start_datetime": "2026-02-25T10:00:00+00:00"
          // - for all-day events: "start": "2026-02-25"  (or start_datetime may be present)
          const startVal = a.start || a.start_datetime;  // prefer date-only start if present
          const endVal   = a.end   || a.end_datetime;

          // Detect all-day robustly:
          // - explicit flag from backend (a.allDay or a.is_all_day), or
          // - ISO date-only string like "YYYY-MM-DD"
          const isAllDay = !!a.allDay || !!a.is_all_day ||
                          (/^\d{4}-\d{2}-\d{2}$/.test(a.start) ||
                            /^\d{4}-\d{2}-\d{2}$/.test(a.start_datetime));

          let startField = null;
          let endField = null;

          if (isAllDay) {
            // keep date-only strings for FullCalendar (YYYY-MM-DD)
            startField = a.start || (a.start_datetime ? a.start_datetime.split('T')[0] : null);

            // determine end:
            if (a.end) {
              endField = a.end;
            } else if (a.end_datetime) {
              endField = a.end_datetime.split('T')[0];
            } else if (startField) {
              // if server omitted end, compute exclusive end = start + 1 day
              const tmp = new Date(startField + "T00:00:00");
              tmp.setDate(tmp.getDate() + 1);
              endField = tmp.toISOString().slice(0,10);
            } else {
              endField = null;
            }
          } else {
            startField = startVal ? new Date(startVal) : null; // JS Date — FullCalendar expects Date object in 'local' tz
            endField   = endVal   ? new Date(endVal)   : null;
          }

          return {
            id: a.id,
            title: a.title,
            start: startField,
            end: endField,
            allDay: isAllDay,
            backgroundColor: a.color || (window.userColors && window.userColors.btn),
            extendedProps: {
              db_id: a.db_id != null ? a.db_id : a.id,
              description: a.description,
              notes: a.notes || [],
              calendar_id: a.calendar_id,
              recurrence_rule: a.recurrence_rule,
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

   function handleEventDropOrResize(info) {
    const event = info.event;

    // We'll build a payload that the backend can parse:
    // - all-day: send date-only strings "YYYY-MM-DD" for start/end (end must be exclusive)
    // - timed: send full ISO datetimes (UTC) like "2026-02-25T10:00:00.000Z"
    let payloadStart = null;
    let payloadEnd = null;
    const isAllDay = !!event.allDay;

    // Helper to format a Date object into YYYY-MM-DD (local date, no timezone conversions)
    const dateToLocalDateString = (d) => {
      if (!d) return null;
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    };

    if (isAllDay) {
      // derive local date strings (do NOT use toISOString() here)
      if (typeof event.start === "string") {
        // FullCalendar may already provide date-only string
        payloadStart = event.start;
      } else if (event.start instanceof Date) {
        payloadStart = dateToLocalDateString(event.start);
      }

      if (typeof event.end === "string") {
        payloadEnd = event.end;
      } else if (event.end instanceof Date) {
        payloadEnd = dateToLocalDateString(event.end);
      }

      // If end is missing, compute exclusive end = start + 1 day (date-only)
      if (!payloadEnd && payloadStart) {
        const tmp = new Date(payloadStart + "T00:00:00"); // local midnight
        tmp.setDate(tmp.getDate() + 1);
        payloadEnd = dateToLocalDateString(tmp);
      }

      // sanity: if we still don't have payloadStart/payloadEnd, revert to fail-safe (do nothing)
      if (!payloadStart || !payloadEnd) {
        console.warn("All-day update missing start/end, aborting update.", event);
        info.revert();
        return;
      }

      // We send date-only strings for all-day (backend should parse date-only as midnight UTC / exclusive end)
      // Option: you could send midnight UTC ISO instead, but that reintroduces timezone shifting issues.
    } else {
      // Timed event -> send full ISO (UTC) strings. FullCalendar's event.start is a Date in local tz.
      const startDt = event.start ? new Date(event.start) : null;
      const endDt   = event.end   ? new Date(event.end)   : null;

      if (startDt) payloadStart = startDt.toISOString();
      if (endDt)   payloadEnd   = endDt.toISOString();

      // Ensure end exists for timed events (db requires it)
      if (!payloadEnd && payloadStart) {
        const tmp = new Date(payloadStart);
        tmp.setHours(tmp.getHours() + 1); // default +1 hour
        payloadEnd = tmp.toISOString();
      }
    }

    const payload = {
      start: payloadStart,
      end: payloadEnd,
      is_all_day: isAllDay
    };

    // DEBUG logging — helps verify what we're sending
    try {
      console.warn("Dragging/resizing -> update payload:", payload, "db_id:", event.extendedProps.db_id);
    } catch (e) { /* ignore logging failures */ }

    // send update
    fetch(`/api/appointments/${event.extendedProps.db_id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
    .then(r => {
      if (!r.ok) throw new Error("Update failed");
      return r.json();
    })
    .then(updatedEvent => {
      calendar.refetchEvents();
    })
    .catch(err => {
      console.error("Failed to update appointment via drag/resize", err);
      info.revert();
    });
  }

    // dateClick: user clicked a single slot — open "new appointment" modal using a 1-hour default
    function handleDateClick(info) {
        // info.date is a JS Date object; build startStr and endStr as ISO strings
        const start = info.date;
        const end = new Date(start.getTime() + (60 * 60 * 1000)); // +1 hour default
        // Build the shape expected by onDateSelect: { startStr, endStr }
        const sel = { startStr: start.toISOString(), endStr: end.toISOString() };
        onDateSelect(sel);
    }

    // select: user dragged to select a range — use provided startStr/endStr
    function handleSelect(selectionInfo) {
        // FullCalendar's selectionInfo already has startStr and endStr
        onDateSelect(selectionInfo);
        // remove selection highlight
        calendar.unselect();
    }

    // eventClick: open edit modal for clicked event
    function handleEventClick(info) {
        onEventClick(info);
    }

    // Build calendar options
    const options = {
      initialView: initialResponsiveView,     // <-- responsive initial view
      timeZone: 'local',
      headerToolbar: {
        left: 'prev,next today',
        center: 'title',
        right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek'
      },
      selectable: true,
      selectMirror: true,
      editable: true,
      events: eventsLoader,
      select: handleSelect,
      dateClick: handleDateClick,
      eventClick: handleEventClick,
      eventDrop: handleEventDropOrResize,
      eventResize: handleEventDropOrResize
    };

    try {
        // Assign to outer-scope `calendar` so save/delete functions that call calendar.refetchEvents() work.
        calendar = new FullCalendar.Calendar(calendarEl, options);
        calendar.render();
        window.fcInstance = calendar;
    } catch (err) {
        console.error("FullCalendar initialization failed with options:", options, err);
        // fallback so page isn't blank
        try {
        const fallback = new FullCalendar.Calendar(calendarEl, { initialView: 'dayGridMonth' });
        fallback.render();
        window.fcInstance = fallback;
        calendar = fallback;
        console.warn("FullCalendar fallback instance created.");
        } catch (err2) {
        console.error("Fallback FullCalendar initialization also failed:", err2);
        }
    }

     // -----------------------
    // Watch for width changes and switch view when needed (debounced)
    // -----------------------
    let resizeTimer = null;
    let lastAppliedView = initialResponsiveView;

    function onResize() {
      const newView = getResponsiveView();
      if (newView === lastAppliedView) return;
      lastAppliedView = newView;
      try {
        // preserve current date / focus when changing view
        const currentDate = calendar.getDate(); // keeps displayed date
        calendar.changeView(newView, currentDate);
      } catch (e) {
        console.warn("Failed to change FullCalendar view on resize:", e);
      }
    }

    window.addEventListener('resize', () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(onResize, 160); // debounce: 160ms
    });

    // also listen to orientationchange for mobile
    window.addEventListener('orientationchange', () => {
      // slight delay to allow orientation/layout to settle
      setTimeout(onResize, 200);
    });

    // If you want immediate sync (e.g., when SPA route changes),
    // call onResize() where appropriate.
  }

  // Helper: update swatch UI when appt-color value changes
  function updateColorSwatchFromInput() {
    const inp = document.getElementById("appt-color");
    const label = document.getElementById("color-swatch-label");
    if (!inp) return;
    const v = inp.value;
    if (!v) {
      label.textContent = "No color";
      inp.style.boxShadow = "inset 0 0 0 1px rgba(255,255,255,0.03)";
      inp.style.background = ""; // browser default
    } else {
      label.textContent = v.toUpperCase();
      inp.style.background = v;
    }
  }

  // When opening modal for edit: if event has rrule, show advanced and set simple selector
  function showRecurrenceForEdit(rruleString) {
    if (!rruleString) {
      document.getElementById("recurrence-simple").value = "";
      document.getElementById("recurrence-advanced").style.display = "none";
      return;
    }
    // determine main freq from RRULE
    const s = rruleString.startsWith("RRULE:") ? rruleString.slice(6) : rruleString;
    const parts = {};
    s.split(";").forEach(p=>{ const [k,v]=p.split("="); parts[k]=v; });
    const freq = parts.FREQ || "";
    document.getElementById("recurrence-simple").value = freq;
    document.getElementById("recurrence-advanced").style.display = "block";
    prefillRecurrenceFromRRule(rruleString); // reuses your existing function
  }

  // Public bootstrap called by your auth flow after successful login check
  window.calendarBootstrap = async function() {
    try {
      await loadSidebarCalendars();
      await loadNotes();

      // Clear color button
      document.addEventListener("click", function(e) {
        if (e.target && e.target.id === "clear-color-btn") {
          const inp = document.getElementById("appt-color");
          if (inp) {
            inp.value = "";    // empty indicates "no color"
            updateColorSwatchFromInput();
          }
        }
      });

      // color input change -> update swatch label
      document.addEventListener("input", function(e){
        if (e.target && e.target.id === "appt-color") updateColorSwatchFromInput();
      });

      // show advanced when simple selection changes
      document.getElementById("recurrence-simple").addEventListener("change", (e) => {
        const val = e.target.value;
        const adv = document.getElementById("recurrence-advanced");
        if (!adv) return;
        if (!val) {
          // none: hide advanced and clear fields
          adv.style.display = "none";
          document.getElementById("recurrence-freq").value = "";
          clearRecurrenceUI();
        } else {
          // show advanced and set freq
          adv.style.display = "block";
          document.getElementById("recurrence-freq").value = val;
          document.getElementById("weekly-weekdays").style.display = val === "WEEKLY" ? "block" : "none";
          updateRRulePreview();
        }
      });
      initFullCalendar();

      // Wire up recurrence UI listeners
      document.getElementById("recurrence-freq").addEventListener("change", (e)=>{
        document.getElementById("weekly-weekdays").style.display = e.target.value === "WEEKLY" ? "block" : "none";
        updateRRulePreview();
      });
      document.getElementById("recurrence-interval").addEventListener("input", updateRRulePreview);
      document.getElementById("recurrence-end-type").addEventListener("change", (e)=>{
        const v = e.target.value;
        document.getElementById("recurrence-until").style.display = v==="until" ? "inline-block":"none";
        document.getElementById("recurrence-count").style.display = v==="count" ? "inline-block":"none";
        updateRRulePreview();
      });
      for (const cb of document.querySelectorAll("#weekly-weekdays .weekday")) cb.addEventListener("change", updateRRulePreview);
      document.getElementById("recurrence-until").addEventListener("change", updateRRulePreview);
      document.getElementById("recurrence-count").addEventListener("input", updateRRulePreview);
      document.getElementById("clear-recurrence").addEventListener("click", ()=>{ clearRecurrenceUI(); });

    } catch (err) {
      console.error("calendarBootstrap failed", err);
    }
  };

  // DOM wiring
  document.addEventListener("click", function(e) {
    if (e.target && e.target.id === "create-calendar-btn") {
      const name = document.getElementById("new-calendar-name").value.trim();
      createCalendar(name).then(()=>document.getElementById("new-calendar-name").value="");
    } else if (e.target && e.target.id === "close-appt-modal") {
      closeApptModal();
    } else if (e.target && e.target.id === "save-appt-btn") {
      saveAppointment();
    } else if (e.target && e.target.id === "delete-appt-btn") {
      deleteAppointment();
    } else if (e.target && e.target.id === "connect-google-btn") {
      connectGoogle();
    } else if (e.target && e.target.id === "sync-google-btn") {
      syncGoogle();
    } else if (e.target && e.target.id === "disconnect-google-btn") {
      disconnectGoogle();
    }
  });

})();

document.addEventListener("DOMContentLoaded", () => {
  (function setupSidebar() {
    const SIDEBAR_ID = "calendar-sidebar";
    const TOGGLE_ID = "calendar-sidebar-toggle";
    const CLOSE_ID  = "calendar-sidebar-close";
    const OVERLAY_ID = "calendar-sidebar-overlay";
    const MOBILE_BREAKPOINT = 768;

    const sidebar = document.getElementById(SIDEBAR_ID);
    const toggle  = document.getElementById(TOGGLE_ID);
    const closeBtn = document.getElementById(CLOSE_ID);
    const overlay = document.getElementById(OVERLAY_ID);

    if (!sidebar || !toggle || !overlay) return;

    function isMobile() {
      return window.innerWidth <= MOBILE_BREAKPOINT;
    }

    function showToggleIfMobile() {
      if (isMobile()) {
        // remove inline style to fall back to CSS display rules
        toggle.style.display = '';
      } else {
        toggle.style.display = 'none';
      }
    }

    function openSidebar() {
      sidebar.classList.add('open');
      sidebar.setAttribute('aria-hidden', 'false');
      toggle.setAttribute('aria-expanded', 'true');
      overlay.setAttribute('aria-hidden', 'false');
      // prevent page scrolling while open
      document.documentElement.style.overflow = 'hidden';
      document.body.style.overflow = 'hidden';
      // hide the attached toggle on mobile (we have close button inside)
      if (isMobile()) toggle.style.display = 'none';
      // focus first focusable in sidebar
      const focusable = sidebar.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (focusable) focusable.focus();
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      sidebar.setAttribute('aria-hidden', isMobile() ? 'true' : 'false');
      toggle.setAttribute('aria-expanded', 'false');
      overlay.setAttribute('aria-hidden', 'true');
      document.documentElement.style.overflow = '';
      document.body.style.overflow = '';
      // show the attached toggle again if mobile
      if (isMobile()) {
        toggle.style.display = ''; // let CSS make it visible
        // return focus to toggle
        toggle.focus();
      } else {
        toggle.style.display = 'none';
      }
    }

    // Initialize: on mobile show toggle; on desktop keep it hidden
    function initState() {
      showToggleIfMobile();
      if (isMobile()) {
        sidebar.setAttribute('aria-hidden', 'true');
        toggle.setAttribute('aria-expanded', 'false');
        overlay.setAttribute('aria-hidden', 'true');
        sidebar.classList.remove('open');
      } else {
        // desktop: ensure sidebar is visible as static element
        sidebar.setAttribute('aria-hidden', 'false');
        toggle.setAttribute('aria-expanded', 'false');
        overlay.setAttribute('aria-hidden', 'true');
        sidebar.classList.remove('open');
        document.documentElement.style.overflow = '';
        document.body.style.overflow = '';
      }
    }

    // events
    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      openSidebar();
    });

    closeBtn && closeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      closeSidebar();
    });

    // clicking overlay closes sidebar
    overlay.addEventListener('click', (e) => {
      closeSidebar();
    });

    // close on Escape
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && sidebar.classList.contains('open')) {
        closeSidebar();
      }
    });

    // respond to resizes: on desktop ensure toggle hidden and sidebar static; on mobile show toggle
    let sbResizeTimer = null;
    window.addEventListener('resize', () => {
      clearTimeout(sbResizeTimer);
      sbResizeTimer = setTimeout(() => {
        if (!isMobile()) {
          closeSidebar();
          sidebar.setAttribute('aria-hidden', 'false');
        } else {
          // on mobile keep sidebar closed by default and show attached toggle
          sidebar.setAttribute('aria-hidden', 'true');
          showToggleIfMobile();
        }
      }, 180);
    });

    // init
    initState();
  })();
});