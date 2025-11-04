document.addEventListener("DOMContentLoaded", () => {
  const fetchBtn = document.getElementById("fetchPasswordsBtn");
  const saveBtn = document.getElementById("savePasswordBtn");
  const passwordList = document.getElementById("passwordList");
  const unlockBtn = document.getElementById("unlockVaultBtn");
  const unlockStatus = document.getElementById("unlockStatus");

  let vaultUnlocked = false;

  // --- Unlock vault ---
  unlockBtn.addEventListener("click", () => {
    const masterPassword = document.getElementById("masterPassword").value.trim();
    if (!masterPassword) {
      unlockStatus.textContent = "⚠️ Please enter your master password.";
      unlockStatus.classList.remove("unlocked");
      return;
    }

    fetch("http://127.0.0.1:5000/unlock_vault", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ master_password: masterPassword })
    })
      .then(res => res.json())
      .then(data => {
        if (data.status === "success") {
          vaultUnlocked = true;
          unlockStatus.textContent = "✅ Vault Unlocked!";
          unlockStatus.classList.add("unlocked");
        } else {
          vaultUnlocked = false;
          unlockStatus.textContent = "❌ " + data.message;
          unlockStatus.classList.remove("unlocked");
        }
      })
      .catch(err => {
        unlockStatus.textContent = "❌ Error: " + err.message;
        unlockStatus.classList.remove("unlocked");
      });
  });

  // --- Get current domain ---
  function getCurrentDomain(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const url = new URL(tabs[0].url);
      callback(url.hostname.replace("www.", ""));
    });
  }

  // --- Fetch password for current site ---
  fetchBtn.addEventListener("click", () => {
    if (!vaultUnlocked) {
      alert("🔒 Please unlock the vault first.");
      return;
    }

    getCurrentDomain(domain => {
      chrome.runtime.sendMessage({ action: "getPassword", domain: domain }, response => {
        passwordList.innerHTML = "";

        if (!response) {
          passwordList.innerHTML = "<i>❌ No response from local API. Make sure it's running.</i>";
          return;
        }

        if (response.status === "success" && response.password) {
          const entryDiv = document.createElement("div");
          entryDiv.className = "entry";

          const masked = "•".repeat(response.password.length);
          entryDiv.innerHTML = `
            <span><strong>Domain:</strong> ${domain}</span>
            <span><strong>Username:</strong> ${response.username || "(none)"} </span>
            <span><strong>Password:</strong> <span class="pwMask">${masked}</span></span>
            <div>
              <button class="toggleBtn">👁 Show</button>
              <button class="copyBtn">📋 Copy</button>
            </div>
          `;

          const pwMask = entryDiv.querySelector(".pwMask");
          const toggleBtn = entryDiv.querySelector(".toggleBtn");
          const copyBtn = entryDiv.querySelector(".copyBtn");

          toggleBtn.addEventListener("click", () => {
            if (pwMask.textContent === masked) {
              pwMask.textContent = response.password;
              toggleBtn.textContent = "🙈 Hide";
            } else {
              pwMask.textContent = masked;
              toggleBtn.textContent = "👁 Show";
            }
          });

          copyBtn.addEventListener("click", () => {
            navigator.clipboard.writeText(response.password);
            alert("✅ Password copied to clipboard!");
          });

          passwordList.appendChild(entryDiv);
        } else {
          passwordList.innerHTML = `<i>${response.message || "No stored password for this site."}</i>`;
        }
      });
    });
  });

  // --- Save new password manually ---
  saveBtn.addEventListener("click", () => {
    if (!vaultUnlocked) {
      alert("🔒 Please unlock the vault first.");
      return;
    }

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    if (!username || !password) {
      alert("⚠️ Please enter both username and password.");
      return;
    }

    getCurrentDomain(domain => {
      // Check if password exists first
      chrome.runtime.sendMessage({ action: "getPassword", domain }, existing => {
        if (existing && existing.status === "success") {
          if (!confirm("A password already exists for this site. Update it?")) {
            return;
          }
        }

        chrome.runtime.sendMessage({
          action: "savePassword",
          domain,
          username,
          password
        }, response => {
          if (response && response.status === "success") {
            alert("✅ Password saved successfully!");
          } else {
            alert("❌ Failed to save password: " + (response?.message || "Unknown error"));
          }
        });
      });
    });
  });
});
