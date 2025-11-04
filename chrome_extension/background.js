// background.js
// ---------------------------------------------------
// Handles communication between content scripts and local API
// ---------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const API_URL = "http://127.0.0.1:5000";
  const headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer MySuperStrongRandomToken123!"
  };

  // Helper function to make API requests safely
  const callAPI = async (endpoint, body) => {
    try {
      const res = await fetch(`${API_URL}${endpoint}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body)
      });
      return await res.json();
    } catch (err) {
      return { status: "error", message: err.message };
    }
  };

  // Handle get password request
  if (msg.action === "getPassword") {
    callAPI("/get_password", { domain: msg.domain })
      .then(data => sendResponse(data));
    return true; // Required to keep async channel open
  }

  // Handle save password (auto or manual)
  if (msg.action === "savePassword" || msg.action === "savePasswordPrompt") {
    callAPI("/save_password", {
      domain: msg.domain,
      username: msg.username,
      password: msg.password
    })
      .then(data => sendResponse(data));
    return true;
  }
});
