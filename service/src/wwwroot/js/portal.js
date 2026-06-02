(function () {
    const tokenKey = "signmemaybe.sessionToken";
    const userKey = "signmemaybe.username";

    const elements = {
        authForm: document.getElementById("auth-form"),
        username: document.getElementById("username"),
        password: document.getElementById("password"),
        registerButton: document.getElementById("register-button"),
        logoutButton: document.getElementById("logout-button"),
        sessionCard: document.getElementById("session-card"),
        sessionUser: document.getElementById("session-user"),
        contractForm: document.getElementById("contract-form"),
        contractTitle: document.getElementById("contract-title"),
        contractContent: document.getElementById("contract-content"),
        contractList: document.getElementById("contract-list"),
        contractViewer: document.getElementById("contract-viewer"),
        refreshButton: document.getElementById("refresh-button"),
        messageArea: document.getElementById("message-area")
    };

    function getToken() {
        return localStorage.getItem(tokenKey);
    }

    function setSession(username, token) {
        localStorage.setItem(tokenKey, token);
        localStorage.setItem(userKey, username);
        renderSession();
    }

    function clearSession() {
        localStorage.removeItem(tokenKey);
        localStorage.removeItem(userKey);
        renderSession();
        elements.contractList.innerHTML = '<p class="muted">Log in to load records.</p>';
        elements.contractViewer.innerHTML = '<p class="muted">Select a contract to inspect its latest version.</p>';
    }

    function renderSession() {
        const username = localStorage.getItem(userKey);
        const token = getToken();
        if (!username || !token) {
            elements.sessionCard.classList.add("hidden");
            return;
        }

        elements.sessionCard.classList.remove("hidden");
        elements.sessionUser.textContent = `${username} authenticated`;
    }

    async function api(path, options) {
        const headers = {
            "Accept": "application/json",
            ...(options && options.headers ? options.headers : {})
        };

        const token = getToken();
        if (token) {
            headers["X-Session-Token"] = token;
        }

        const response = await fetch(path, {
            ...options,
            headers
        });

        const text = await response.text();
        let data = null;
        if (text) {
            try {
                data = JSON.parse(text);
            } catch {
                throw new Error("The service returned a response that was not JSON.");
            }
        }

        if (!response.ok) {
            const message = data && data.error ? data.error : `Request failed with HTTP ${response.status}`;
            throw new Error(message);
        }

        return data;
    }

    function showMessage(message, isError) {
        const box = document.createElement("div");
        box.className = isError ? "message error" : "message";
        box.textContent = message;
        elements.messageArea.appendChild(box);
        window.setTimeout(() => box.remove(), 4200);
    }

    async function authenticate(mode) {
        const username = elements.username.value.trim();
        const password = elements.password.value;
        const path = mode === "register" ? "/api/register" : "/api/login";
        const data = await api(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        setSession(data.username, data.token);
        showMessage(mode === "register" ? "Identity registered." : "Session established.", false);
        await loadContracts();
    }

    async function loadContracts() {
        if (!getToken()) {
            elements.contractList.innerHTML = '<p class="muted">Log in to load records.</p>';
            return;
        }

        const data = await api("/api/contracts");
        const contracts = Array.isArray(data.contracts) ? data.contracts : [];
        if (contracts.length === 0) {
            elements.contractList.innerHTML = '<p class="muted">No contracts sealed yet.</p>';
            return;
        }

        elements.contractList.innerHTML = "";
        for (const contract of contracts) {
            const item = document.createElement("button");
            item.type = "button";
            item.className = "contract-item";
            item.innerHTML = `
                <strong>${escapeHtml(contract.title)}</strong>
                <span class="meta-row">
                    <span>ID ${contract.contractId}</span>
                    <span>Version ${contract.latestVersion.versionNumber}</span>
                    <span>${escapeHtml(contract.latestVersion.approvalState)}</span>
                </span>`;
            item.addEventListener("click", () => loadContract(contract.contractId));
            elements.contractList.appendChild(item);
        }
    }

    async function loadContract(contractId) {
        const data = await api(`/api/contracts/${contractId}/versions/latest`);
        elements.contractViewer.innerHTML = `
            <h3>${escapeHtml(data.title)}</h3>
            <div class="meta-row">
                <span><strong>Contract:</strong> ${data.contractId}</span>
                <span><strong>Owner:</strong> ${data.ownerUserId}</span>
                <span><strong>Version:</strong> ${data.versionNumber}</span>
                <span><strong>State:</strong> ${escapeHtml(data.approvalState)}</span>
                <span><strong>Checksum:</strong> ${escapeHtml(data.checksum)}</span>
            </div>
            <p><button type="button" id="open-pdf-button" class="pdf-link secondary">Open generated PDF</button></p>
            <div class="viewer-content">${escapeHtml(data.content || "")}</div>`;

        document.getElementById("open-pdf-button").addEventListener("click", async function () {
            try {
                await openPdf(data.pdfUrl);
            } catch (error) {
                showMessage(error.message, true);
            }
        });
    }

    async function openPdf(pdfUrl) {
        const token = getToken();
        const response = await fetch(pdfUrl, {
            headers: token ? { "X-Session-Token": token } : {}
        });

        if (!response.ok) {
            throw new Error(`PDF request failed with HTTP ${response.status}`);
        }

        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        window.open(objectUrl, "_blank", "noreferrer");
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
    }

    async function createContract(event) {
        event.preventDefault();
        const title = elements.contractTitle.value.trim();
        const content = elements.contractContent.value;

        const created = await api("/api/contracts", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title, content })
        });

        elements.contractForm.reset();
        showMessage("Contract sealed into the archive.", false);
        await loadContracts();
        await loadContract(created.contractId);
    }

    function escapeHtml(value) {
        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    elements.authForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        try {
            await authenticate("login");
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    elements.registerButton.addEventListener("click", async function () {
        try {
            await authenticate("register");
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    elements.logoutButton.addEventListener("click", clearSession);

    elements.contractForm.addEventListener("submit", async function (event) {
        try {
            await createContract(event);
        } catch (error) {
            event.preventDefault();
            showMessage(error.message, true);
        }
    });

    elements.refreshButton.addEventListener("click", async function () {
        try {
            await loadContracts();
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    renderSession();
    if (getToken()) {
        loadContracts().catch(error => showMessage(error.message, true));
    }
})();
