(function () {
    // 1) Inject FontAwesome if missing
    const FA_CSS = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css";
    if (!document.querySelector(`link[href^="${FA_CSS}"]`)) {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = FA_CSS;
        document.head.appendChild(link);
    }

    // 2) Override alert
    window.alert = function (message, type = "info") {
        // Limit raw message length
        const MAX_CHARS = 5000;
        let isFullPage = /<!DOCTYPE\s+html|<html/i.test(message);
        let displayMessage = message;
        if (!isFullPage && message.length > MAX_CHARS) {
            displayMessage = message.slice(0, MAX_CHARS) + "…";
        }

        // Create wrapper
        const wrapper = document.createElement("div");
        wrapper.style.position = "fixed";
        wrapper.style.zIndex = 9999;
        wrapper.style.boxShadow = "0 4px 6px rgba(0,0,0,0.1)";
        wrapper.style.borderRadius = "6px";
        wrapper.style.overflow = "hidden";
        wrapper.style.maxWidth = "90vw";
        wrapper.style.maxHeight = "80vh";
        wrapper.style.display = "flex";
        wrapper.style.flexDirection = "column";
        wrapper.style.background = "#fff";
        wrapper.style.fontFamily = "Arial, sans-serif";
        wrapper.style.color = "#333";

        // Position & style by type
        let timeout = 5000;
        const iconClass = {
            info:    "fa-info-circle",
            success: "fa-check-circle",
            error:   "fa-exclamation-circle"
        }[type.toLowerCase()] || "fa-info-circle";

        switch (type.toLowerCase()) {
            case "success":
                wrapper.style.borderTop = "5px solid #4CAF50";
                timeout = 7000;
                break;
            case "error":
                wrapper.style.borderTop = "5px solid #F44336";
                timeout = 10000;
                break;
            default:
                wrapper.style.borderTop = "5px solid #2196F3";
        }

        // Container for content
        const content = document.createElement(isFullPage ? "iframe" : "div");
        if (isFullPage) {
            content.setAttribute("sandbox", "");
            content.style.border = "none";
            content.style.flex = "1 1 auto";
            content.srcdoc = displayMessage;
        } else {
            content.style.padding = "15px 20px";
            content.style.overflow = "auto";
            content.style.flex = "1 1 auto";
            content.innerHTML = `<i class="fa ${iconClass}" aria-hidden="true" style="margin-right:8px;"></i>${displayMessage}`;
        }

        // Header with close button
        const header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "flex-end";
        header.style.background = "transparent";
        header.style.padding = "5px 10px";
        const btn = document.createElement("button");
        btn.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
        btn.style.background = "none";
        btn.style.border = "none";
        btn.style.fontSize = "16px";
        btn.style.cursor = "pointer";
        btn.onclick = () => remove();
        header.appendChild(btn);

        // Assemble & position
        wrapper.appendChild(header);
        wrapper.appendChild(content);
        document.body.appendChild(wrapper);

        // Position top-center for full pages, else top-right
        if (isFullPage) {
            wrapper.style.top = "20px";
            wrapper.style.left = "50%";
            wrapper.style.transform = "translateX(-50%)";
        } else {
            wrapper.style.top = "20px";
            wrapper.style.right = "20px";
        }

        // Auto-remove
        const hideTimer = setTimeout(remove, timeout);
        function remove() {
            clearTimeout(hideTimer);
            wrapper.style.transition = "opacity 0.3s ease";
            wrapper.style.opacity = "0";
            setTimeout(() => wrapper.remove(), 300);
        }
    };
})();
