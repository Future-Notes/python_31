(function () {
    const FA_CSS = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css";
    if (!document.querySelector(`link[href^="${FA_CSS}"]`)) {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = FA_CSS;
        document.head.appendChild(link);
    }

    const MAX_VISIBLE = 3;
    const GAP = 10;
    const activeAlerts = [];
    const alertQueue = [];

    window.alert = function (message, type = "info", timeout = 5000) {
        // If this script runs inside an iframe...
        if (window !== window.parent) {
            // Forward the alert call upward to the parent page
            window.parent.postMessage({
                from: "iframe-alert",
                message,
                type,
                timeout
            }, "*");
            return; // Prevent current iframe from showing the alert
        }

        // If we are NOT in an iframe, handle the alert normally:
        const alertConfig = { message, type, timeout };
        if (activeAlerts.length < MAX_VISIBLE) {
            showAlert(alertConfig);
        } else {
            alertQueue.push(alertConfig);
        }
    };


    // Requires: `activeAlerts`, `GAP`, `alertQueue` exist in outer scope (as in your original code).
    // Optional but recommended: include DOMPurify in your page for best results:
    // <script src="https://cdn.jsdelivr.net/npm/dompurify@2.4.0/dist/purify.min.js"></script>

    function showAlert({ message, type = "info", timeout } = {}) {
        const MAX_CHARS = 5000;
        const isFullPage = /<!DOCTYPE\s+html|<html/i.test(String(message || ""));
        let displayMessage = message;

        // -----------------------
        // Sanitization helpers
        // -----------------------
        function escapeHtml(str) {
            return String(str).replace(/[&<>"']/g, ch => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;"
            })[ch]);
        }

        // Safe link filter for fallback (ensures href starts with http(s) or mailto)
        function safeHref(href) {
            try {
                // Allow http(s), mailto only
                const trimmed = String(href).trim();
                if (/^(https?:|mailto:)/i.test(trimmed)) return trimmed;
            } catch (e) {}
            return null;
        }

        // Sanitize input. Uses DOMPurify if present, otherwise falls back to a conservative escape.
        function sanitizeForAlert(input) {
            input = input == null ? "" : String(input);

            // If DOMPurify is available, use it with a tight whitelist.
            if (typeof DOMPurify !== "undefined") {
                // Allow a small set of tags and safe attributes. No styles, no event handlers.
                // Note: DOMPurify will remove dangerous attributes and scripts.
                const clean = DOMPurify.sanitize(input, {
                    ALLOWED_TAGS: ["a", "b", "strong", "i", "em", "u", "br", "p", "ul", "ol", "li", "code", "pre", "span"],
                    ALLOWED_ATTR: ["href", "title", "target", "rel"],
                    // Force anchors to have rel="noopener noreferrer" and only safe protocols:
                    FORBID_ATTR: ["style"],
                    RETURN_TRUSTED_TYPE: false
                });

                // Post-process links: add rel/noopener and strip unsafe hrefs (DOMPurify may allow them by config).
                // We'll use a temporary DOM node to adjust anchors.
                const tmp = document.createElement("div");
                tmp.innerHTML = clean;
                const anchors = tmp.querySelectorAll("a[href]");
                anchors.forEach(a => {
                    const safe = safeHref(a.getAttribute("href"));
                    if (!safe) {
                        // replace with text node of the href
                        const text = document.createTextNode(a.textContent || a.getAttribute("href") || "");
                        a.parentNode.replaceChild(text, a);
                    } else {
                        a.setAttribute("href", safe);
                        a.setAttribute("rel", "noopener noreferrer");
                        // target is allowed but not required; if you want links to open in new tab:
                        // a.setAttribute("target", "_blank");
                    }
                });
                return tmp.innerHTML;
            }

            // Fallback: no DOMPurify — extremely conservative: escape everything to text.
            // This avoids any injection via attrs or tags.
            return escapeHtml(input);
        }

        // Truncate logic: we want to cap the *plain text* length to MAX_CHARS so we don't cut tags mid-way.
        function truncatePreservingSafety(htmlOrText, maxChars) {
            // If DOMPurify is available, we'll create a sanitized DOM, take its textContent,
            // and if it's over limit, return escaped truncated text (losing markup but staying safe).
            if (typeof DOMPurify !== "undefined") {
                const sanitized = DOMPurify.sanitize(String(htmlOrText));
                const tmp = document.createElement("div");
                tmp.innerHTML = sanitized;
                const plain = tmp.textContent || tmp.innerText || "";
                if (plain.length > maxChars) {
                    return escapeHtml(plain.slice(0, maxChars) + "…");
                }
                // safe to return sanitized HTML
                return sanitized;
            } else {
                // fallback: plain text escape and truncate
                const plain = String(htmlOrText || "");
                if (plain.length > maxChars) {
                    return escapeHtml(plain.slice(0, maxChars) + "…");
                }
                return escapeHtml(plain);
            }
        }

        // -----------------------
        // Validate / prepare message
        // -----------------------
        if (!isFullPage) {
            if (typeof message !== "string" || message.trim() === "") {
                displayMessage = "<i>No message provided.</i>";
            } else {
                // sanitize and truncate safely
                displayMessage = truncatePreservingSafety(message, MAX_CHARS);
            }
        } else {
            // If full page (you said you won't allow this), still sanitize and be strict.
            // IMPORTANT: Do NOT include allow-scripts or allow-same-origin in the sandbox for untrusted content.
            displayMessage = typeof message === "string" ? message : "";
        }

        // -----------------------
        // Build wrapper and UI
        // -----------------------
        const wrapper = document.createElement("div");
        Object.assign(wrapper.style, {
            position: "fixed",
            zIndex: "10010",
            boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
            borderRadius: "6px",
            overflow: "hidden",
            maxWidth: "400px",
            display: "flex",
            flexDirection: "column",
            background: getComputedStyle(document.documentElement).getPropertyValue('--bg-color')?.trim() || "#2e2e2e",
            fontFamily: "Arial, sans-serif",
            color: "white",
            right: "-420px",
            transition: "right 0.3s ease, top 0.3s ease"
        });

        const icons = {
            info: "fa-info-circle",
            success: "fa-check-circle",
            error: "fa-exclamation-circle"
        };
        const iconClass = icons[(type || "info").toLowerCase()] || icons.info;

        let effectiveTimeout = timeout;
        switch ((type || "info").toLowerCase()) {
            case "success":
                wrapper.style.borderTop = "5px solid #4CAF50";
                if (timeout === undefined) effectiveTimeout = 7000;
                break;
            case "error":
                wrapper.style.borderTop = "5px solid #F44336";
                if (timeout === undefined) effectiveTimeout = 10000;
                break;
            default:
                wrapper.style.borderTop = "5px solid #2196F3";
        }

        const header = document.createElement("div");
        Object.assign(header.style, {
            display: "flex",
            justifyContent: "flex-end",
            padding: "5px 10px"
        });

        const closeBtn = document.createElement("button");
        closeBtn.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
        Object.assign(closeBtn.style, {
            background: "none",
            border: "none",
            fontSize: "16px",
            cursor: "pointer"
        });
        header.appendChild(closeBtn);

        let content;
        if (isFullPage) {
            content = document.createElement("iframe");
            // SECURITY: don't allow scripts or same-origin on untrusted HTML.
            // If you must allow scripts, you MUST ensure the HTML is fully trusted.
            content.setAttribute("sandbox", ""); // fully sandboxed iframe: no scripts, no same-origin
            // If you do want to allow forms/popups, add specific tokens like "allow-popups" only.
            // Avoid allow-scripts and allow-same-origin for untrusted input.
            // If you plan to render arbitrary HTML that contains scripts, reconsider entirely.
            // To be safe: use sanitized HTML instead of letting arbitrary scripts run.
            content.srcdoc = sanitizeForAlert(displayMessage);
            Object.assign(content.style, {
                border: "none",
                flex: "1 1 auto",
                minHeight: "100px"
            });
        } else {
            content = document.createElement("div");
            // Build icon element and append sanitized HTML separately
            const iconEl = document.createElement("i");
            iconEl.className = `fa ${iconClass}`;
            iconEl.setAttribute("aria-hidden", "true");
            iconEl.style.marginRight = "8px";
            // Use a container for the message
            const msgWrap = document.createElement("span");

            // If our sanitizer returned pure escaped text (fallback), we still can set innerHTML safely.
            // sanitizeForAlert ensures safety either with DOMPurify or escapeHtml fallback.
            msgWrap.innerHTML = sanitizeForAlert(displayMessage);

            content.appendChild(iconEl);
            content.appendChild(msgWrap);

            Object.assign(content.style, {
                padding: "15px 20px",
                overflow: "auto",
                flex: "1 1 auto",
                display: "flex",
                alignItems: "flex-start"
            });
        }

        wrapper.appendChild(header);
        wrapper.appendChild(content);
        document.body.appendChild(wrapper);

        // Set initial top position
        wrapper.style.top = `${20 + (typeof activeAlerts !== "undefined" ? activeAlerts.reduce((acc, el) => acc + el.offsetHeight + (typeof GAP !== "undefined" ? GAP : 8), 0) : 0)}px`;

        // Trigger slide-in animation (next frame)
        requestAnimationFrame(() => wrapper.style.right = "20px");

        if (typeof activeAlerts !== "undefined") activeAlerts.push(wrapper);

        let hideTimer;
        function startTimeout() {
            if (effectiveTimeout !== null && effectiveTimeout !== undefined) {
                hideTimer = setTimeout(remove, effectiveTimeout);
            }
        }

        function clearTimeoutIfAny() {
            if (hideTimer) {
                clearTimeout(hideTimer);
                hideTimer = null;
            }
        }

        wrapper.addEventListener("mouseenter", clearTimeoutIfAny);
        wrapper.addEventListener("mouseleave", startTimeout);

        closeBtn.onclick = remove;
        startTimeout();

        function remove() {
            clearTimeoutIfAny();
            wrapper.style.right = "-420px"; // slide back out
            setTimeout(() => {
                wrapper.remove();
                if (typeof activeAlerts !== "undefined") {
                    const index = activeAlerts.indexOf(wrapper);
                    if (index !== -1) activeAlerts.splice(index, 1);
                }
                // repositionAlerts is expected to exist (your original code)
                if (typeof repositionAlerts === "function") repositionAlerts();
                if (typeof alertQueue !== "undefined" && alertQueue.length > 0) {
                    showAlert(alertQueue.shift());
                }
            }, 300);
        }
    }


    function repositionAlerts() {
        let currentTop = 20;
        activeAlerts.forEach(alert => {
            alert.style.top = `${currentTop}px`;
            currentTop += alert.offsetHeight + GAP;
        });
    }
})();