document.addEventListener("DOMContentLoaded", function() {
    (async function() {
        var adminSessionKey = localStorage.getItem("admin_session_key");
        var currentSessionKey = sessionStorage.getItem("session_key");
        var currentUserId = sessionStorage.getItem("current_user_id");

        console.log("Admin.js ran!")

        if (adminSessionKey && currentSessionKey && (currentSessionKey !== adminSessionKey) && currentUserId) {
            console.log("All required fields are present!")
            // Fetch the username of the currently impersonated user
            let username = "another user"; // Default fallback
            try {
                const response = await fetch(`/api/user/${currentUserId}`);
                if (response.ok) {
                    const data = await response.json();
                    username = data.username || `User ID ${currentUserId}`;
                }
            } catch (error) {
                console.error("Failed to fetch username:", error);
            }

            // Create the overlay bar element
            var bar = document.createElement("div");
            bar.id = "admin-impersonation-bar";

            // Apply styles with !important
            bar.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                background-color: #f44336 !important;
                color: #fff !important;
                padding: 10px !important;
                text-align: center !important;
                z-index: 10000 !important;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2) !important;
                font-family: Arial, sans-serif !important;
                font-size: 16px !important;
                font-weight: bold !important;
            `;

            // Create button for returning to admin
            var button = document.createElement("button");
            button.id = "return-to-admin";
            button.innerText = "Return to Admin";
            button.style.cssText = `
                margin-left: 10px !important;
                padding: 5px 15px !important;
                font-size: 14px !important;
                cursor: pointer !important;
                background-color: #fff !important;
                color: #f44336 !important;
                border: none !important;
                border-radius: 5px !important;
                font-weight: bold !important;
                transition: background 0.2s ease-in-out !important;
            `;

            // Hover effect for button
            button.addEventListener("mouseover", function() {
                button.style.backgroundColor = "#ddd";
            });
            button.addEventListener("mouseout", function() {
                button.style.backgroundColor = "#fff";
            });

            // Append message and button
            bar.innerHTML = `You are logged in as <strong>${username}</strong>. `;
            bar.appendChild(button);

            // Insert a spacer div to push content down instead of overlaying it
            var spacer = document.createElement("div");
            spacer.id = "admin-impersonation-spacer";
            spacer.style.cssText = `
                width: 100% !important;
                height: 40px !important; /* Adjust this to match the bar height */
            `;

            // Append elements to the document
            document.body.insertBefore(spacer, document.body.firstChild);
            document.body.insertBefore(bar, document.body.firstChild);

            // Button click event to restore admin session
            button.addEventListener("click", function() {
                var adminKey = localStorage.getItem("admin_session_key");
                var adminLastingKey = localStorage.getItem("admin_lasting_key");
            
                if (adminKey) {
                    sessionStorage.setItem("session_key", adminKey);
                }
                if (adminLastingKey) {
                    localStorage.setItem("lasting_key", adminLastingKey);
                }
            
                // Remove stored admin credentials
                localStorage.removeItem("admin_session_key");
                localStorage.removeItem("admin_lasting_key");
                sessionStorage.removeItem("current_user_id");
            
                // Reload page to apply admin session
                window.location.reload();
            });            
        }
    })();
});
