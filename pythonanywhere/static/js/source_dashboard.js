document.addEventListener("DOMContentLoaded", async () => {
  // 1) Patch fetch so cookies are always sent
  if (!window.__fetchPatched) {
    const _origFetch = window.fetch;
    window.fetch = (url, opts = {}) => {
      opts.credentials = 'include';
      return _origFetch(url, opts);
    };
    window.__fetchPatched = true;
  }

  // 2) Helpers
  function showModal() {
    alert("Authentication required!");
    window.location.href = "/login_page";
  }
  function hideModal() {
    // no‐op if you have a real modal implementation
  }

  // 3) Try to re‑establish a session via the session_key cookie
  async function validateSession() {
    try {
      const res = await fetch("/test-session", { method: "GET" });
      if (res.status === 200) {
        hideModal();
        return true;
      }
      if (res.status === 403) {
        window.location.href = "/login_page?suspended=true";
        return false;
      }
      // 401 or other → not authenticated
      return false;
    } catch (err) {
      console.error("Session validation error:", err);
      return false;
    }
  }

  // 4) If no valid session, try auto‑login via lasting_key cookie
  async function attemptAutoLogin() {
    try {
      const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}) // backend reads lasting_key cookie
      });
      if (res.ok) {
        console.log("Auto-login successful!");
        hideModal();
        return true;
      }
      if (res.status === 403) {
        window.location.href = "/login_page?suspended=true";
        return false;
      }
      console.error("Auto-login failed");
      showModal();
      return false;
    } catch (err) {
      console.error("Error during auto-login:", err);
      showModal();
      return false;
    }
  }

  // 5) Combined auth flow
  let authenticated = await validateSession();
  if (!authenticated) {
    authenticated = await attemptAutoLogin();
    if (!authenticated) {
      return; // showModal has already run
    }
  }

  // 6) Wire up back button
  document.getElementById("back-button")
          .addEventListener("click", () => {
    window.location.href = "/admin_page";
  });

  // 7) Fetch and display source tracking
  async function fetchSourceTracking() {
    try {
      const res = await fetch("/api/source-tracking", { method: "GET" });
      if (!res.ok) {
        console.error("Failed to fetch tracking data");
        return;
      }
      const data = await res.json();
      populateTable(data);
    } catch (err) {
      console.error("Error fetching tracking data:", err);
    }
  }

  function populateTable(data) {
    const tbody = document.querySelector("#tracking-table tbody");
    tbody.innerHTML = "";
    data.forEach(item => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${item.id}</td>
        <td>${item.utm_source || ""}</td>
        <td>${item.utm_medium || ""}</td>
        <td>${item.utm_campaign || ""}</td>
        <td>${item.ip || ""}</td>
        <td>${item.timestamp || ""}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // 8) Kick off the data load
  fetchSourceTracking();
});
