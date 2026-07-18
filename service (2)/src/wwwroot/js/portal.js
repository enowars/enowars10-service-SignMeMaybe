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
        ceremonyContractPicker: document.getElementById("ceremony-contract-picker"),
        ceremonyContractReference: document.getElementById("ceremony-contract-reference"),
        ceremonyResult: document.getElementById("ceremony-result"),
        refreshButton: document.getElementById("refresh-button"),
        messageArea: document.getElementById("message-area")
    };

    let ownerContracts = [];
    let activeContractReference = "";

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
        elements.ceremonyResult.innerHTML = '<p class="muted">Start a contract signature to inspect and validate the receipt.</p>';
        ownerContracts = [];
        activeContractReference = "";
        elements.ceremonyContractReference.value = "";
        populateContractPicker();
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
            ownerContracts = [];
            populateContractPicker();
            return;
        }

        const data = await api("/api/contracts");
        const contracts = Array.isArray(data.contracts) ? data.contracts : [];
        ownerContracts = contracts;
        populateContractPicker();
        if (contracts.length === 0) {
            elements.contractList.innerHTML = '<p class="muted">No contracts filed yet.</p>';
            return;
        }

        elements.contractList.innerHTML = "";
        for (const contract of contracts) {
            elements.contractList.appendChild(renderContractButton(contract));
        }
    }

    function populateContractPicker() {
        const currentReference = elements.ceremonyContractReference.value.trim();
        elements.ceremonyContractPicker.innerHTML = "";

        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = ownerContracts.length === 0
            ? "No contracts filed yet"
            : "Select a contract...";
        elements.ceremonyContractPicker.appendChild(placeholder);

        for (const contract of ownerContracts) {
            const reference = contract.reference || "";
            if (!reference) {
                continue;
            }

            const latestVersion = contract.latestVersion || {};
            const option = document.createElement("option");
            option.value = reference;
            option.textContent = formatContractOption(contract, latestVersion, reference);
            elements.ceremonyContractPicker.appendChild(option);
        }

        selectMatchingContract(currentReference);
    }

    function formatContractOption(contract, latestVersion, reference) {
        const title = contract.title || "Untitled contract";
        const version = latestVersion.versionNumber || "?";
        const state = latestVersion.approvalState || "draft";
        return `${title} - v${version} - ${state} - ${shortReference(reference)}`;
    }

    function shortReference(reference) {
        return reference.length > 17
            ? `${reference.slice(0, 12)}...${reference.slice(-4)}`
            : reference;
    }

    function setCeremonyContractReference(reference) {
        elements.ceremonyContractReference.value = reference || "";
        selectMatchingContract(elements.ceremonyContractReference.value.trim());
    }

    function selectMatchingContract(reference) {
        const hasMatch = ownerContracts.some(contract => contract.reference === reference);
        elements.ceremonyContractPicker.value = hasMatch ? reference : "";
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
            ? `<span>Receipt blob ${escapeHtml(authority.secretBlob)}</span>`
            : "";
        const item = document.createElement("button");
        item.type = "button";
        item.className = "contract-item";
        item.innerHTML = `
            <strong>${escapeHtml(authority.displayName || authorityId)}</strong>
            <span class="meta-row">
                <span>Authority ${escapeHtml(authorityId)}</span>
                <span>Curve ${escapeHtml(authority.curveName || "")}</span>
                ${secretBlob}
            </span>`;
        item.addEventListener("click", () => {
            elements.ceremonyAuthorityId.value = authorityId;
            elements.ceremonyAuthorityId.setCustomValidity("");
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
            contractReference: elements.ceremonyContractReference.value.trim(),
            curveName: elements.signingCurve.value
        };

        const ceremony = await api(`/api/signing/authorities/${encodeURIComponent(authorityId)}/ceremonies`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });

        renderCeremonyResult(ceremony);
        showMessage("Contract signature ceremony completed.", false);
    }

    function renderCeremonyResult(ceremony) {
        const contract = ceremony.contract || {};
        const signature = ceremony.signaturePoint && ceremony.signaturePoint.infinity
            ? "infinity"
            : `${ceremony.signaturePoint.x}, ${ceremony.signaturePoint.y}`;
        elements.ceremonyResult.innerHTML = `
            <h3>Receipt ${escapeHtml(ceremony.ceremonyId)}</h3>
            <div class="meta-row">
                <span><strong>Authority:</strong> ${escapeHtml(ceremony.authorityId)}</span>
                <span><strong>Contract:</strong> ${escapeHtml(contract.reference || "")}</span>
                <span><strong>Version:</strong> ${escapeHtml(contract.versionNumber || "")}</span>
                <span><strong>Curve:</strong> ${escapeHtml(ceremony.curveName)}</span>
                <span><strong>Status:</strong> ${escapeHtml(ceremony.validationState)}</span>
            </div>
            <p><strong>Checksum:</strong> <code>${escapeHtml(contract.checksum || "")}</code></p>
            <p><strong>Signature point:</strong> <code>${escapeHtml(signature)}</code></p>
            <p><strong>Receipt tag:</strong> <code>${escapeHtml(ceremony.receiptTag)}</code></p>
            <button type="button" id="validate-ceremony-button" class="secondary">Validate on server</button>`;

        document.getElementById("validate-ceremony-button").addEventListener("click", async function () {
            try {
                const validation = await api(`/api/signing/ceremonies/${encodeURIComponent(ceremony.ceremonyId)}/validate`, {
                    method: "POST"
                });
                showMessage(validation.valid ? "Receipt validated." : "Receipt rejected.", !validation.valid);
                if (validation.valid) {
                    await loadContracts();
                    const signedReference = validation.contract && validation.contract.reference
                        ? validation.contract.reference
                        : "";
                    if (signedReference && signedReference === activeContractReference) {
                        await loadContract(signedReference);
                    }
                }
                elements.ceremonyResult.querySelector(".meta-row").innerHTML = `
                    <span><strong>Authority:</strong> ${escapeHtml(validation.authorityId)}</span>
                    <span><strong>Contract:</strong> ${escapeHtml(validation.contract && validation.contract.reference ? validation.contract.reference : "")}</span>
                    <span><strong>Status:</strong> ${escapeHtml(validation.validationState)}</span>`;
            } catch (error) {
                showMessage(error.message, true);
            }
        });
    }

    function renderContractButton(contract) {
        const reference = contract.reference || "";
        const latestVersion = contract.latestVersion || {};
        const archiveTicket = contract.archiveTicket
            ? `<span>Archive ticket ${escapeHtml(contract.archiveTicket)}</span>`
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
                ${archiveTicket}
            </span>`;
        if (reference) {
            item.addEventListener("click", () => loadContract(reference));
        }
        return item;
    }

    async function loadContract(reference) {
        const data = await api(`/api/contracts/${encodeURIComponent(reference)}/versions/latest`);
        const isOwner = data.ownerUsername && data.ownerUsername === localStorage.getItem(userKey);
        const isSigned = String(data.approvalState || "").toLowerCase() === "signed";
        const editButton = isOwner && !isSigned
            ? '<button type="button" id="edit-contract-button" class="secondary">Edit</button>'
            : "";
        activeContractReference = data.reference || reference;
        elements.contractViewer.innerHTML = `
            <h3>${escapeHtml(data.title)}</h3>
            <div class="meta-row">
                <span><strong>Reference:</strong> ${escapeHtml(data.reference)}</span>
                <span><strong>Owner:</strong> ${escapeHtml(data.ownerUsername)}</span>
                <span><strong>Version:</strong> ${data.versionNumber}</span>
                <span><strong>State:</strong> ${escapeHtml(data.approvalState)}</span>
                <span><strong>Checksum:</strong> ${escapeHtml(data.checksum)}</span>
            </div>
            <p class="button-row contract-action-row">
                <button type="button" id="open-pdf-button" class="pdf-link secondary">Open generated PDF</button>
                ${editButton}
                <button type="button" id="sign-contract-button" class="secondary">Sign contract</button>
            </p>
            <div class="viewer-content">${escapeHtml(data.content || "")}</div>`;

        document.getElementById("open-pdf-button").addEventListener("click", async function () {
            try {
                await openPdf(data.pdfUrl);
            } catch (error) {
                showMessage(error.message, true);
            }
        });

        const editContractButton = document.getElementById("edit-contract-button");
        if (editContractButton) {
            editContractButton.addEventListener("click", function () {
                if (String(data.approvalState || "").toLowerCase() === "signed") {
                    showMessage("Signed contracts cannot be edited.", true);
                    loadContract(data.reference).catch(error => showMessage(error.message, true));
                    return;
                }
                renderContractEditForm(data);
            });
        }

        document.getElementById("sign-contract-button").addEventListener("click", function () {
            setCeremonyContractReference(data.reference);
            setActiveView("signing");
            showMessage("Contract queued for signing.", false);
        });
    }

    function renderContractEditForm(contract) {
        if (String(contract.approvalState || "").toLowerCase() === "signed") {
            showMessage("Signed contracts cannot be edited.", true);
            loadContract(contract.reference).catch(error => showMessage(error.message, true));
            return;
        }

        elements.contractViewer.innerHTML = `
            <h3>Edit ${escapeHtml(contract.reference)}</h3>
            <form id="contract-edit-form" class="stack">
                <label>
                    Title
                    <input id="edit-contract-title" name="editContractTitle" maxlength="120" value="${escapeHtml(contract.title || "")}" required />
                </label>
                <label>
                    Content
                    <textarea id="edit-contract-content" name="editContractContent" rows="8" required>${escapeHtml(contract.content || "")}</textarea>
                    <span class="field-note">Saving overwrites the current stored version and increments the version number.</span>
                </label>
                <p class="button-row">
                    <button type="submit">Save changes</button>
                    <button type="button" id="cancel-contract-edit-button" class="secondary">Cancel</button>
                </p>
            </form>`;

        document.getElementById("contract-edit-form").addEventListener("submit", async function (event) {
            event.preventDefault();
            try {
                await saveContractEdit(contract.reference);
            } catch (error) {
                showMessage(error.message, true);
            }
        });

        document.getElementById("cancel-contract-edit-button").addEventListener("click", function () {
            loadContract(contract.reference).catch(error => showMessage(error.message, true));
        });
    }

    async function saveContractEdit(reference) {
        const title = document.getElementById("edit-contract-title").value.trim();
        const content = document.getElementById("edit-contract-content").value;
        try {
            await api(`/api/contracts/${encodeURIComponent(reference)}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ title, content })
            });
        } catch (error) {
            if (/signed contracts cannot be edited/i.test(error.message)) {
                await loadContracts();
                await loadContract(reference);
            }
            throw error;
        }

        showMessage("Contract updated.", false);
        await loadContracts();
        await loadContract(reference);
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
        showMessage("Contract filed into the archive.", false);
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

    elements.ceremonyContractPicker.addEventListener("change", function () {
        setCeremonyContractReference(elements.ceremonyContractPicker.value);
    });

    elements.ceremonyContractReference.addEventListener("input", function () {
        selectMatchingContract(elements.ceremonyContractReference.value.trim());
    });

    elements.ceremonyAuthorityId.addEventListener("invalid", function () {
        if (!elements.ceremonyAuthorityId.value.trim()) {
            elements.ceremonyAuthorityId.setCustomValidity("Please create and select a Signing Authority first.");
        }
    });

    elements.ceremonyAuthorityId.addEventListener("input", function () {
        elements.ceremonyAuthorityId.setCustomValidity("");
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
    populateContractPicker();
    loadSigningCurves().catch(error => showMessage(error.message, true));
    if (getToken()) {
        loadContracts().catch(error => showMessage(error.message, true));
        loadSigningAuthorities().catch(error => showMessage(error.message, true));
    }
})();
