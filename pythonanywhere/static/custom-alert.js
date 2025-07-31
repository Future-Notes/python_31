(function () {
    // Override the default alert function
    window.alert = function (message, type = "info") {
        let alertBox = document.createElement("div");
        alertBox.style.position = "fixed";
        alertBox.style.padding = "15px 20px";
        alertBox.style.borderRadius = "5px";
        alertBox.style.color = "#fff";
        alertBox.style.fontFamily = "Arial, sans-serif";
        alertBox.style.fontSize = "14px";
        alertBox.style.boxShadow = "0px 4px 6px rgba(0, 0, 0, 0.1)";
        alertBox.style.opacity = "1";
        alertBox.style.transition = "opacity 0.3s ease-in-out";

        // Default: Info messages (small, top-right)
        alertBox.style.top = "20px";
        alertBox.style.right = "20px";
        alertBox.style.zIndex = "9999";

        // Determine alert type styles
        switch (type.toLowerCase()) {
            case "success":
                alertBox.style.backgroundColor = "#4CAF50"; // Green
                alertBox.style.fontSize = "20px"; // Bigger text
                alertBox.style.padding = "20px 30px";
                alertBox.style.width = "300px";
                alertBox.style.textAlign = "center";
                alertBox.style.left = "50%";
                alertBox.style.transform = "translateX(-50%)"; // Horizontally centered
                alertBox.style.top = "20px"; // Still at the top
                break;
            case "error":
                alertBox.style.backgroundColor = "#F44336"; // Red
                alertBox.style.fontSize = "20px"; // Bigger text
                alertBox.style.padding = "20px 30px";
                alertBox.style.width = "300px";
                alertBox.style.textAlign = "center";
                alertBox.style.left = "50%";
                alertBox.style.transform = "translateX(-50%)"; // Horizontally centered
                alertBox.style.top = "20px"; // Still at the top
                break;
            default:
                alertBox.style.backgroundColor = "#2196F3"; // Blue (info)
                break;
        }

        // Set message text
        alertBox.innerHTML = message;
        document.body.appendChild(alertBox);

        // Auto-remove after 3 seconds
        setTimeout(() => {
            alertBox.style.opacity = "0";
            setTimeout(() => alertBox.remove(), 300);
        }, 3000);
    };
})();
