// content.js
(() => {
  // Prevent duplicate save prompts
  let hasPrompted = false;

  // Wait until DOM is ready
  document.addEventListener("DOMContentLoaded", () => {
    const domain = window.location.hostname.replace(/^www\./, "");

    // --- Autofill password if saved ---
    chrome.runtime.sendMessage({ action: "getPassword", domain }, response => {
      if (response && response.status === "ok" && response.password) {
        const pwFields = document.querySelectorAll('input[type="password"]');
        pwFields.forEach(field => {
          field.value = response.password;

          // Optional: visually highlight autofilled fields for clarity
          field.style.outline = "2px solid #00bcd4";
          field.style.transition = "outline 0.3s ease-in-out";

          setTimeout(() => {
            field.style.outline = "none";
          }, 1200);
        });
      }
    });

    // --- Detect password submissions ---
    document.addEventListener("submit", e => {
      // Avoid multiple prompts on the same page
      if (hasPrompted) return;
      hasPrompted = true;

      const form = e.target;
      const pwField = form.querySelector('input[type="password"]');
      const userField =
        form.querySelector('input[type="email"]') ||
        form.querySelector('input[type="text"]');

      if (pwField && pwField.value && userField && userField.value) {
        const username = userField.value.trim();
        const password = pwField.value;

        // Ask user for permission to save
        const confirmSave = confirm(
          `💾 Do you want to save this password for ${domain}?\n\nUsername: ${username}`
        );

        if (confirmSave) {
          chrome.runtime.sendMessage(
            {
              action: "savePassword",
              domain,
              username,
              password
            },
            response => {
              if (response && response.status === "ok") {
                alert("✅ Password saved successfully!");
              } else {
                alert("⚠️ Could not save password. Please check your manager.");
              }
            }
          );
        }

        // Wipe sensitive data from memory quickly
        setTimeout(() => {
          pwField.value = "";
        }, 500);
      }
    });
  });
})();
