chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkUrl") {
        fetch("http://127.0.0.1:5001/predict", { // Your AI API URL (updated port)
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ "url": request.url })
        })
        .then(response => response.json())
        .then(data => {
            let message = "";
            let title = "";

            if (data.prediction === "Phishing") {
                title = "Phishing Alert!";
                message = `This website might be unsafe! (Confidence: ${data.confidence}%)`;
            } else {
                title = "Safe Website";
                message = `This website is secure. (Confidence: ${data.confidence}%)`;
            }

            chrome.notifications.create({
                type: "basic",
                iconUrl: "icon.png",
                title: title,
                message: message
            });

            sendResponse(data);
        })
        .catch(error => {
            console.error("Error:", error);
            sendResponse({ error: true });
        });

        return true; // Required to allow async sendResponse
    }
});
