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
        const MAX_CHARS = 5000;
        const isFullPage = /<!DOCTYPE\s+html|<html/i.test(message);
        let displayMessage = message;
        if (!isFullPage && message.length > MAX_CHARS) {
            displayMessage = message.slice(0, MAX_CHARS) + "…";
        }

        // wrapper container
        const wrapper = document.createElement("div");
        Object.assign(wrapper.style, {
            position:     "fixed",
            zIndex:       "9999",
            boxShadow:    "0 4px 6px rgba(0,0,0,0.1)",
            borderRadius: "6px",
            overflow:     "hidden",
            maxWidth:     "400px",
            maxHeight:    "200px",
            display:      "flex",
            flexDirection:"column",
            background:   "#fff",
            fontFamily:   "Arial, sans-serif",
            color:        "#333"
        });

        // type-specific border & timeout
        let timeout = 5000;
        const icons = { info: "fa-info-circle", success: "fa-check-circle", error: "fa-exclamation-circle" };
        const iconClass = icons[type.toLowerCase()] || icons.info;
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

        // header + close button
        const header = document.createElement("div");
        Object.assign(header.style, { display: "flex", justifyContent: "flex-end", padding: "5px 10px" });
        const closeBtn = document.createElement("button");
        closeBtn.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
        Object.assign(closeBtn.style, {
            background: "none", border: "none",
            fontSize:   "16px", cursor: "pointer"
        });
        closeBtn.onclick = remove;
        header.appendChild(closeBtn);

        // content area (iframe for full-page HTML, div otherwise)
        let content;
        if (isFullPage) {
            content = document.createElement("iframe");
            content.setAttribute("sandbox", "allow-scripts allow-same-origin");
            content.srcdoc = displayMessage;
            Object.assign(content.style, {
                border: "none",
                flex:   "1 1 auto"
            });
        } else {
            content = document.createElement("div");
            content.innerHTML = `<i class="fa ${iconClass}" aria-hidden="true" style="margin-right:8px;"></i>${displayMessage}`;
            Object.assign(content.style, {
                padding:  "15px 20px",
                overflow: "auto",
                flex:     "1 1 auto"
            });
        }

        // assemble
        wrapper.appendChild(header);
        wrapper.appendChild(content);
        document.body.appendChild(wrapper);

        // position: full-page centered top, else top-right
        if (isFullPage) {
            Object.assign(wrapper.style, {
                top:       "20px",
                left:      "50%",
                transform: "translateX(-50%)"
            });
        } else {
            Object.assign(wrapper.style, {
                top:   "20px",
                right: "20px"
            });
        }

        // auto-hide
        const hideTimer = setTimeout(remove, timeout);
        function remove() {
            clearTimeout(hideTimer);
            wrapper.style.transition = "opacity 0.3s ease";
            wrapper.style.opacity = "0";
            setTimeout(() => wrapper.remove(), 300);
        }
    };
})();
