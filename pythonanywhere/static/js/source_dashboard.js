document.addEventListener("DOMContentLoaded", async () => {
    const sessionKey = sessionStorage.getItem("session_key");
    const lastingKey = localStorage.getItem("lasting_key");

    async function attemptAutoLogin() {
        try {
            const response = await fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ lasting_key: lastingKey }),
            });
            const data = await response.json();
            if (response.ok) {
                sessionStorage.setItem("session_key", data.session_key);
                console.log("Auto-login successful!");
            } else if (response.status === 403) {
                window.location.href = '/login_page?suspended=true';
            } else {
                console.error("Auto-login failed:", data.error || "Unknown error");
                localStorage.removeItem("lasting_key");
                showModal();
            }
        } catch (error) {
            console.error("Error during auto-login:", error);
            showModal();
        }
    }

    function showModal() {
        // Placeholder for modal implementation; here we'll use a simple alert
        alert("Authentication required!");
        window.location.href = "/login_page";
    }

    function hideModal() {
        // Placeholder to hide modal if implemented
    }

    if (!sessionKey && lastingKey) {
        await attemptAutoLogin();
    } else if (!sessionKey && !lastingKey) {
        showModal();
    } else {
        try {
            const response = await fetch("/test-session", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${sessionStorage.getItem("session_key")}`,
                },
            });
            if (response.status === 401) {
                if (lastingKey) {
                    await attemptAutoLogin();
                } else {
                    showModal();
                }
            } else {
                hideModal();
            }
        } catch (error) {
            console.error("Error during session validation:", error);
            showModal();
        }
    }

    // Set up the back button to redirect to the admin page
    document.getElementById("back-button").addEventListener("click", () => {
        window.location.href = "/admin_page";
    });

    // Fetch source tracking data from the protected endpoint
    async function fetchSourceTracking() {
        try {
            const response = await fetch("/api/source-tracking", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${sessionStorage.getItem("session_key")}`,
                },
            });
            if (response.ok) {
                const data = await response.json();
                populateTable(data);
            } else {
                console.error("Failed to fetch tracking data");
            }
        } catch (error) {
            console.error("Error fetching tracking data:", error);
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

    // Initial fetch of the tracking data
    fetchSourceTracking();
});
