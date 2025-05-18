document.getElementById("settings-form").addEventListener("submit", event => {
    event.preventDefault();

    const honeypotPort = document.getElementById("honeypot-port").value;
    const loggingLevel = document.getElementById("logging-level").value;

    fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ honeypotPort, loggingLevel })
    })
    .then(response => {
        if (response.ok) {
            alert("Settings saved successfully!");
        } else {
            alert("Failed to save settings.");
        }
    })
    .catch(error => console.error("Error saving settings:", error));
});