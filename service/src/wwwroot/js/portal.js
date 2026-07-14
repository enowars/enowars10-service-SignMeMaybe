(function () {
    const tokenKey = "signmemaybe.sessionToken";
    const userKey = "signmemaybe.username";
    const viewKey = "signmemaybe.activeView";
    const viewLabels = {
        access: "Access Terminal",
        intake: "Record Intake",
        archive: "Archive Cabinet",
        public: "Public Ledger",
        signing: "Signing Desk"
    };

    const elements = {
        viewTabs: Array.from(document.querySelectorAll("[data-view]")),
        viewPanels: Array.from(document.querySelectorAll("[data-view-panel]")),
        activeViewLabel: document.getElementById("active-view-label"),
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
        publicLookupForm: document.getElementById("public-lookup-form"),
        publicUsername: document.getElementById("public-username"),
        publicContractList: document.getElementById("public-contract-list"),
        signingAuthorityForm: document.getElementById("signing-authority-form"),
        signingDisplayName: document.getElementById("signing-display-name"),
        signingCurve: document.getElementById("signing-curve"),
        signingSecret: document.getElementById("signing-secret"),
        signingAuthorityList: document.getElementById("signing-authority-list"),
        signingLookupForm: document.getElementById("signing-lookup-form"),
        signingPublicUsername: document.getElementById("signing-public-username"),
        signingPublicList: document.getElementById("signing-public-list"),
        refreshSigningButton: document.getElementById("refresh-signing-button"),
        signatureCeremonyForm: document.getElementById("signature-ceremony-form"),
        ceremonyAuthorityId: document.getElementById("ceremony-authority-id"),
        ceremonyMessage: document.getElementById("ceremony-message"),
        ceremonyCustomBase: document.getElementById("ceremony-custom-base"),
        ceremonyBaseFields: document.getElementById("ceremony-base-fields"),
        ceremonyBaseX: document.getElementById("ceremony-base-x"),
        ceremonyBaseY: document.getElementById("ceremony-base-y"),
        ceremonyResult: document.getElementById("ceremony-result"),
        refreshButton: document.getElementById("refresh-button"),
        messageArea: document.getElementById("message-area")
    };

    function setActiveView(viewName) {
        const knownView = elements.viewPanels.some(panel => panel.dataset.viewPanel === viewName);
        const activeView = knownView ? viewName : "access";

        for (const tab of elements.viewTabs) {
            const isActive = tab.dataset.view === activeView;
            tab.classList.toggle("is-active", isActive);
            tab.setAttribute("aria-selected", isActive ? "true" : "false");
        }

        for (const panel of elements.viewPanels) {
            const isActive = panel.dataset.viewPanel === activeView;
            panel.classList.toggle("is-active", isActive);
            panel.hidden = !isActive;
        }

        if (elements.activeViewLabel) {
            elements.activeViewLabel.textContent = viewLabels[activeView] || activeView;
        }

        localStorage.setItem(viewKey, activeView);
    }

    function initializeNavigation() {
        for (const tab of elements.viewTabs) {
            tab.addEventListener("click", () => setActiveView(tab.dataset.view));
        }

        const savedView = localStorage.getItem(viewKey) || "access";
        setActiveView(savedView);
    }

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
        elements.signingAuthorityList.innerHTML = '<p class="muted">Log in to load signing authorities.</p>';
        elements.ceremonyResult.innerHTML = '<p class="muted">Start a ceremony to inspect and validate the receipt.</p>';
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
        await loadSigningAuthorities();
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
            elements.contractList.appendChild(renderContractButton(contract));
        }
    }

    async function loadSigningCurves() {
        const data = await api("/api/signing/curves");
        const curves = Array.isArray(data.curves) ? data.curves : [];
        elements.signingCurve.innerHTML = "";
        for (const curve of curves) {
            const option = document.createElement("option");
            option.value = curve.name;
            option.textContent = curve.name;
            elements.signingCurve.appendChild(option);
        }
    }

    async function loadSigningAuthorities() {
        if (!getToken()) {
            elements.signingAuthorityList.innerHTML = '<p class="muted">Log in to load signing authorities.</p>';
            return;
        }

        const data = await api("/api/signing/authorities");
        const authorities = Array.isArray(data.authorities) ? data.authorities : [];
        if (authorities.length === 0) {
            elements.signingAuthorityList.innerHTML = '<p class="muted">No signing authorities registered yet.</p>';
            return;
        }

        elements.signingAuthorityList.innerHTML = "";
        for (const authority of authorities) {
            elements.signingAuthorityList.appendChild(renderSigningAuthorityButton(authority));
        }
    }

    function renderSigningAuthorityButton(authority) {
        const authorityId = authority.authorityId || "";
        const secretBlob = authority.secretBlob
            ? `<span>Secret blob ${escapeHtml(authority.secretBlob)}</span>`
            : "";
        const checksum = authority.secretChecksum
            ? `<span>Secret checksum ${escapeHtml(authority.secretChecksum)}</span>`
            : "";
        const item = document.createElement("button");
        item.type = "button";
        item.className = "contract-item";
        item.innerHTML = `
            <strong>${escapeHtml(authority.displayName || authorityId)}</strong>
            <span class="meta-row">
                <span>Authority ${escapeHtml(authorityId)}</span>
                <span>Curve ${escapeHtml(authority.curveName || "")}</span>
                ${checksum}
                ${secretBlob}
            </span>`;
        item.addEventListener("click", () => {
            elements.ceremonyAuthorityId.value = authorityId;
            if (authority.curveName) {
                elements.signingCurve.value = authority.curveName;
            }
            showMessage("Signing authority selected.", false);
        });
        return item;
    }

    async function createSigningAuthority(event) {
        event.preventDefault();
        const displayName = elements.signingDisplayName.value.trim();
        const curveName = elements.signingCurve.value;
        const signingSecret = elements.signingSecret.value;
        const body = { displayName, curveName };
        if (signingSecret.length > 0) {
            body.signingSecret = signingSecret;
        }

        await api("/api/signing/authorities", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        elements.signingAuthorityForm.reset();
        showMessage("Signing authority registered.", false);
        await loadSigningAuthorities();
    }

    async function lookupPublicSigningAuthorities(event) {
        event.preventDefault();
        const username = elements.signingPublicUsername.value.trim();
        const data = await api(`/api/users/${encodeURIComponent(username)}/signing-authorities`);
        const authorities = Array.isArray(data.authorities) ? data.authorities : [];

        if (authorities.length === 0) {
            elements.signingPublicList.innerHTML = '<p class="muted">No public signing authorities found for this holder.</p>';
            return;
        }

        elements.signingPublicList.innerHTML = "";
        for (const authority of authorities) {
            elements.signingPublicList.appendChild(renderSigningAuthorityButton(authority));
        }
    }

    async function createSignatureCeremony(event) {
        event.preventDefault();
        const authorityId = elements.ceremonyAuthorityId.value.trim();
        const body = {
            message: elements.ceremonyMessage.value,
            curveName: elements.signingCurve.value
        };

        if (elements.ceremonyCustomBase.checked) {
            body.basePoint = {
                x: elements.ceremonyBaseX.value.trim(),
                y: elements.ceremonyBaseY.value.trim()
            };
        }

        const ceremony = await api(`/api/signing/authorities/${encodeURIComponent(authorityId)}/ceremonies`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        renderCeremonyResult(ceremony);
        showMessage("Server-side signature ceremony completed.", false);
    }

    function renderCeremonyResult(ceremony) {
        const signature = ceremony.signaturePoint && ceremony.signaturePoint.infinity
            ? "infinity"
            : `${ceremony.signaturePoint.x}, ${ceremony.signaturePoint.y}`;
        elements.ceremonyResult.innerHTML = `
            <h3>Receipt ${escapeHtml(ceremony.ceremonyId)}</h3>
            <div class="meta-row">
                <span><strong>Authority:</strong> ${escapeHtml(ceremony.authorityId)}</span>
                <span><strong>Curve:</strong> ${escapeHtml(ceremony.curveName)}</span>
                <span><strong>Status:</strong> ${escapeHtml(ceremony.validationState)}</span>
            </div>
            <p><strong>Signature point:</strong> <code>${escapeHtml(signature)}</code></p>
            <p><strong>Receipt tag:</strong> <code>${escapeHtml(ceremony.receiptTag)}</code></p>
            <button type="button" id="validate-ceremony-button" class="secondary">Validate on server</button>`;

        document.getElementById("validate-ceremony-button").addEventListener("click", async function () {
            try {
                const validation = await api(`/api/signing/ceremonies/${encodeURIComponent(ceremony.ceremonyId)}/validate`, {
                    method: "POST"
                });
                showMessage(validation.valid ? "Receipt validated." : "Receipt rejected.", !validation.valid);
                elements.ceremonyResult.querySelector(".meta-row").innerHTML = `
                    <span><strong>Authority:</strong> ${escapeHtml(validation.authorityId)}</span>
                    <span><strong>Status:</strong> ${escapeHtml(validation.validationState)}</span>`;
            } catch (error) {
                showMessage(error.message, true);
            }
        });
    }

    function renderContractButton(contract) {
        const reference = contract.reference || "";
        const latestVersion = contract.latestVersion || {};
        const notaryStamp = contract.notaryStamp
            ? `<span>Notary stamp ${escapeHtml(contract.notaryStamp)}</span>`
            : "";
        const referenceLabel = reference
            ? `<span>Ref ${escapeHtml(reference)}</span>`
            : "";
        const checksumLabel = latestVersion.checksum
            ? `<span>Checksum ${escapeHtml(latestVersion.checksum)}</span>`
            : "";
        const item = document.createElement(reference ? "button" : "article");
        if (reference) {
            item.type = "button";
        }
        item.className = "contract-item";
        item.innerHTML = `
            <strong>${escapeHtml(contract.title)}</strong>
            <span class="meta-row">
                ${referenceLabel}
                <span>Version ${latestVersion.versionNumber}</span>
                <span>${escapeHtml(latestVersion.approvalState)}</span>
                ${checksumLabel}
                ${notaryStamp}
            </span>`;
        if (reference) {
            item.addEventListener("click", () => loadContract(reference));
        }
        return item;
    }

    async function loadContract(reference) {
        const data = await api(`/api/contracts/${encodeURIComponent(reference)}/versions/latest`);
        elements.contractViewer.innerHTML = `
            <h3>${escapeHtml(data.title)}</h3>
            <div class="meta-row">
                <span><strong>Reference:</strong> ${escapeHtml(data.reference)}</span>
                <span><strong>Owner:</strong> ${escapeHtml(data.ownerUsername)}</span>
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
        await loadContract(created.reference);
        setActiveView("archive");
    }

    async function lookupPublicContracts(event) {
        event.preventDefault();

        const username = elements.publicUsername.value.trim();
        const data = await api(`/api/users/${encodeURIComponent(username)}/contracts`);
        const contracts = Array.isArray(data.contracts) ? data.contracts : [];

        if (contracts.length === 0) {
            elements.publicContractList.innerHTML = '<p class="muted">No public contract metadata found for this holder.</p>';
            return;
        }

        elements.publicContractList.innerHTML = "";
        for (const contract of contracts) {
            elements.publicContractList.appendChild(renderContractButton(contract));
        }
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

    elements.publicLookupForm.addEventListener("submit", async function (event) {
        try {
            await lookupPublicContracts(event);
        } catch (error) {
            event.preventDefault();
            showMessage(error.message, true);
        }
    });

    elements.signingAuthorityForm.addEventListener("submit", async function (event) {
        try {
            await createSigningAuthority(event);
        } catch (error) {
            event.preventDefault();
            showMessage(error.message, true);
        }
    });

    elements.signingLookupForm.addEventListener("submit", async function (event) {
        try {
            await lookupPublicSigningAuthorities(event);
        } catch (error) {
            event.preventDefault();
            showMessage(error.message, true);
        }
    });

    elements.signatureCeremonyForm.addEventListener("submit", async function (event) {
        try {
            await createSignatureCeremony(event);
        } catch (error) {
            event.preventDefault();
            showMessage(error.message, true);
        }
    });

    elements.ceremonyCustomBase.addEventListener("change", function () {
        elements.ceremonyBaseFields.classList.toggle("hidden", !elements.ceremonyCustomBase.checked);
    });

    elements.refreshButton.addEventListener("click", async function () {
        try {
            await loadContracts();
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    elements.refreshSigningButton.addEventListener("click", async function () {
        try {
            await loadSigningAuthorities();
        } catch (error) {
            showMessage(error.message, true);
        }
    });

    initializeNavigation();
    renderSession();
    loadSigningCurves().catch(error => showMessage(error.message, true));
    if (getToken()) {
        loadContracts().catch(error => showMessage(error.message, true));
        loadSigningAuthorities().catch(error => showMessage(error.message, true));
    }
})();
