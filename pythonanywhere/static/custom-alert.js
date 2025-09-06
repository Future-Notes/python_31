(function () {
    // 1) Inject FontAwesome if missing
    const FA_CSS = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css";
    if (!document.querySelector(`link[href^="${FA_CSS}"]`)) {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = FA_CSS;
        document.head.appendChild(link);
    }

    window.alert = function (message, type = "info", timeout = 5000) {
        const MAX_CHARS = 5000;
        const isFullPage = /<!DOCTYPE\s+html|<html/i.test(message);
        let displayMessage = message;

        if (!isFullPage) {
            if (typeof message !== "string" || message.trim() === "") {
                displayMessage = "<i>No message provided.</i>";
            } else if (message.length > MAX_CHARS) {
                displayMessage = message.slice(0, MAX_CHARS) + "…";
            }
        }

        const wrapper = document.createElement("div");
        Object.assign(wrapper.style, {
            position: "fixed",
            zIndex: "9999",
            boxShadow: "0 4px 6px rgba(0,0,0,0.1)",
            borderRadius: "6px",
            overflow: "hidden",
            maxWidth: "400px",
            maxHeight: "200px",
            display: "flex",
            flexDirection: "column",
            background: getComputedStyle(document.documentElement).getPropertyValue('--bg-color')?.trim() || "#2e2e2e",
            fontFamily: "Arial, sans-serif",
            color: "white"
        });

        const icons = {
            info: "fa-info-circle",
            success: "fa-check-circle",
            error: "fa-exclamation-circle"
        };
        const iconClass = icons[type.toLowerCase()] || icons.info;

        let effectiveTimeout = timeout;
        switch (type.toLowerCase()) {
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
        closeBtn.onclick = remove;
        header.appendChild(closeBtn);

        let content;
        if (isFullPage) {
            content = document.createElement("iframe");
            content.setAttribute("sandbox", "allow-scripts allow-same-origin");
            content.srcdoc = displayMessage;
            Object.assign(content.style, {
                border: "none",
                flex: "1 1 auto"
            });
        } else {
            content = document.createElement("div");
            content.innerHTML = `<i class="fa ${iconClass}" aria-hidden="true" style="margin-right:8px;"></i>${displayMessage}`;
            Object.assign(content.style, {
                padding: "15px 20px",
                overflow: "auto",
                flex: "1 1 auto"
            });
        }

        wrapper.appendChild(header);
        wrapper.appendChild(content);
        document.body.appendChild(wrapper);

        if (isFullPage) {
            Object.assign(wrapper.style, {
                top: "20px",
                left: "50%",
                transform: "translateX(-50%)"
            });
        } else {
            Object.assign(wrapper.style, {
                top: "20px",
                right: "20px"
            });
        }

        let hideTimer;
        let isHovered = false;

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

        // Start initial timeout
        startTimeout();

        wrapper.addEventListener("mouseenter", () => {
            isHovered = true;
            clearTimeoutIfAny();
        });

        wrapper.addEventListener("mouseleave", () => {
            isHovered = false;
            startTimeout();
        });

        function remove() {
            clearTimeoutIfAny();
            wrapper.style.transition = "opacity 0.3s ease";
            wrapper.style.opacity = "0";
            setTimeout(() => wrapper.remove(), 300);
        }
    };
})();
