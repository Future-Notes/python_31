document.addEventListener("DOMContentLoaded", async () => {
  const impId = sessionStorage.getItem("impersonated_user_id");
  if (!impId) return;

  // Fetch the impersonated user’s name
  let username = `User ${impId}`;
  try {
    const resp = await fetch(`/api/user/${impId}`, {
      credentials: "include"
    });
    if (resp.ok) {
      const d = await resp.json();
      username = d.username || username;
    }
  } catch(err) {
    console.error("Couldn’t fetch impersonated username", err);
  }

  // Build the bar & spacer
  const bar = document.createElement("div");
  bar.id = "admin-impersonation-bar";
  bar.style.cssText = `
    position:fixed; top:0; left:0; width:100%; background:#f44336; color:#fff;
    padding:10px; text-align:center; z-index:10000; font-weight:bold;
  `;
  bar.innerHTML = `You are logged in as <strong>${username}</strong>. `;

  const btn = document.createElement("button");
  btn.innerText = "Return to Admin";
  btn.style.cssText = `
    margin-left:10px; padding:5px 15px; cursor:pointer;
    background:#fff; color:#f44336; border:none; border-radius:5px;
    font-weight:bold;
  `;
  btn.onmouseover = ()=> btn.style.backgroundColor="#ddd";
  btn.onmouseout  = ()=> btn.style.backgroundColor="#fff";

  btn.onclick = async () => {
    // 1) restore admin session_key by re‑login via admin_lasting_key cookie
    await fetch("/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    // 2) clear impersonation flag
    sessionStorage.removeItem("impersonated_user_id");
    // 3) reload as admin
    window.location.reload();
  };

  bar.appendChild(btn);
  const spacer = document.createElement("div");
  spacer.style.cssText = "width:100%;height:40px;";
  document.body.insertBefore(spacer, document.body.firstChild);
  document.body.insertBefore(bar, spacer);
});

/*
  Subtle Testing Environment Bar for localhost
  Injects a fixed bar at the top of the page when running on localhost or 127.0.0.1
  Styles use !important on every property to override any default page CSS
*/

document.addEventListener('DOMContentLoaded', () => {
  const host = window.location.hostname;
  if (host === 'localhost' || host === '127.0.0.1') {
    // Create and append style element
    const style = document.createElement('style');
    style.id = 'env-testing-bar-style';
    style.textContent = `
      /* Bar container */
      #env-testing-bar { all: unset !important;
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 24px !important;
        background-color: rgba(104, 196, 43, 0.2) !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: sans-serif !important;
        font-size: 12px !important;
        z-index: 9999 !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1) !important;
      }
    `;
    document.head.appendChild(style);

    // Create the bar element
    const bar = document.createElement('div');
    bar.id = 'env-testing-bar';
    // Build the live server URL with the same path and query
    const liveHost = "bosbes.eu.pythonanywhere.com"; // Replace with your live domain
    const liveUrl = `${window.location.protocol}//${liveHost}${window.location.pathname}${window.location.search}${window.location.hash}`;
    bar.innerHTML = `Testing Environment.   <a href="${liveUrl}"> Click here to go to the live environment</a>`;
    document.body.insertBefore(bar, document.body.firstChild);
  }
});

function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
