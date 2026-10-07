chrome.runtime.sendMessage({ action: "checkUrl", url: window.location.href }, (response) => {
    // We defer the threshold logic entirely to the backend (`response.safe`)
    // instead of hardcoding confidence >= 50
    if (response && response.safe === false) {
        // Block the UI
        document.documentElement.innerHTML = `
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    background-color: #d32f2f;
                    color: white;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    text-align: center;
                }
                .container {
                    background: rgba(0,0,0,0.2);
                    padding: 40px;
                    border-radius: 10px;
                    max-width: 600px;
                }
                h1 { font-size: 3em; margin-bottom: 10px; }
                p { font-size: 1.2em; line-height: 1.5; }
            </style>
            <body>
                <div class="container">
                    <h1>Dangerous Website Blocked</h1>
                    <p>This website has been flagged as a phishing site by our AI detection system.</p>
                    <p>Confidence Score: <strong>${response.confidence}%</strong></p>
                    <p>For your safety, access to this site has been restricted.</p>
                </div>
            </body>
        `;
        // Stop any further script execution on the page
        window.stop();
    }
});
