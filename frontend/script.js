const apiBaseInput = document.getElementById("apiBase");
const messageBox = document.getElementById("messageBox");
const profileOutput = document.getElementById("profileOutput");

const registerForm = document.getElementById("registerForm");
const loginForm = document.getElementById("loginForm");
const mfaLoginForm = document.getElementById("mfaLoginForm");
const verifyMfaForm = document.getElementById("verifyMfaForm");

const profileBtn = document.getElementById("profileBtn");
const logoutBtn = document.getElementById("logoutBtn");
const setupMfaBtn = document.getElementById("setupMfaBtn");

const mfaSetupArea = document.getElementById("mfaSetupArea");
const qrImage = document.getElementById("qrImage");
const secretText = document.getElementById("secretText");

function getApiBase() {
  return apiBaseInput.value.trim().replace(/\/+$/, "");
}

function setMessage(text, type = "info") {
  messageBox.textContent = text;
  messageBox.className = `message ${type}`;
}

function setProfile(data) {
  profileOutput.textContent = JSON.stringify(data, null, 2);
  profileOutput.classList.remove("empty");
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`${getApiBase()}${path}`, {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    credentials: "include",
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }

  if (!response.ok) {
    throw new Error(data.message || "Request failed.");
  }

  return data;
}

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.getElementById("registerEmail").value.trim();
  const password = document.getElementById("registerPassword").value;

  try {
    const data = await apiFetch("/register", {
      method: "POST",
      body: { email, password },
    });

    setMessage(data.message || "Registration successful.", "success");
    registerForm.reset();
  } catch (error) {
    setMessage(error.message, "error");
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;

  try {
    const data = await apiFetch("/login", {
      method: "POST",
      body: { email, password },
    });

    if (data.mfaRequired) {
      setMessage(
        "MFA required. Please enter your OTP code in the MFA Login section.",
        "info",
      );
      return;
    }

    setMessage(data.message || "Login successful.", "success");
    setProfile(data);
    loginForm.reset();
  } catch (error) {
    setMessage(error.message, "error");
  }
});

mfaLoginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const token = document.getElementById("mfaLoginToken").value.trim();

  try {
    const data = await apiFetch("/mfa/login", {
      method: "POST",
      body: { token },
    });

    setMessage(data.message || "MFA login successful.", "success");
    setProfile(data);
    mfaLoginForm.reset();
  } catch (error) {
    setMessage(error.message, "error");
  }
});

profileBtn.addEventListener("click", async () => {
  try {
    const data = await apiFetch("/profile");
    setMessage(data.message || "Profile loaded.", "success");
    setProfile(data);
  } catch (error) {
    setMessage(error.message, "error");
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    const data = await apiFetch("/logout", {
      method: "POST",
    });

    setMessage(data.message || "Logout successful.", "success");
    profileOutput.textContent = "No profile loaded.";
    profileOutput.classList.add("empty");
    mfaSetupArea.classList.add("hidden");
    qrImage.removeAttribute("src");
    secretText.textContent = "No secret yet.";
  } catch (error) {
    setMessage(error.message, "error");
  }
});

setupMfaBtn.addEventListener("click", async () => {
  try {
    const data = await apiFetch("/mfa/setup", {
      method: "POST",
    });

    qrImage.src = data.qrCode;
    secretText.textContent = data.secret || "";
    mfaSetupArea.classList.remove("hidden");

    setMessage(data.message || "MFA setup started.", "success");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

verifyMfaForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const token = document.getElementById("verifyMfaToken").value.trim();

  try {
    const data = await apiFetch("/mfa/verify", {
      method: "POST",
      body: { token },
    });

    setMessage(data.message || "MFA enabled successfully.", "success");
    verifyMfaForm.reset();

    try {
      const profile = await apiFetch("/profile");
      setProfile(profile);
    } catch (innerError) {
      // ignore profile refresh failure
    }
  } catch (error) {
    setMessage(error.message, "error");
  }
});
