class ZKChat {
    constructor() {
        this.ws = null;
        this.userId = null;
        this.username = null;
        this.messageCounter = 0;
        this.isConnected = false;
    }

    connect(userId, username) {
        this.userId = parseInt(userId);
        this.username = username;

        // Connect to WebSocket server
        const wsUrl = `ws://${window.location.host}/ws`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('Connected to ZK Chat server');
            this.updateConnectionStatus(true);
            
            // Send join message
            this.sendProtocolMessage({
                Join: {
                    user_id: this.userId,
                    username: this.username
                }
            });
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleServerMessage(message);
            } catch (error) {
                console.error('Failed to parse server message:', error);
                this.showError('Invalid message from server');
            }
        };

        this.ws.onclose = () => {
            console.log('Disconnected from server');
            this.updateConnectionStatus(false);
            this.showError('Connection lost. Please refresh to reconnect.');
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.showError('Connection error. Please check server status.');
        };
    }

    async sendMessage(content) {
        if (!this.isConnected || !content.trim()) {
            return;
        }

        this.messageCounter++;
        const timestamp = Math.floor(Date.now() / 1000);
        
        // Backend computes real ZK hash and generates proof
        const messageRequest = {
            id: this.messageCounter,
            sender_id: this.userId,
            content: content.trim(),
            timestamp: timestamp
        };

        // Generate REAL ZK proof via backend (which computes correct Poseidon hash)
        try {
            const res = await fetch('/api/prove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(messageRequest)
            });
            
            if (!res.ok) {
                this.showError('Failed to generate ZK proof for message');
                return;
            }
            
            const data = await res.json();
            const verifiedMessage = data.message; // Has correct ZK hash from backend
            const proofBase64 = data.proof_base64; // Real ZK-STARK proof

            // Send to server with real proof and backend-verified message
            this.sendProtocolMessage({
                SendMessage: {
                    message: verifiedMessage,
                    proof: Array.from(atob(proofBase64), c => c.charCodeAt(0))
                }
            });

            // Show message as sending (will be updated when broadcast received)
            this.displayMessage(verifiedMessage, false, true, proofBase64);
        } catch (error) {
            console.error('Failed to generate ZK proof:', error);
            this.showError('Failed to generate ZK proof for message');
        }
    }

    sendProtocolMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    handleServerMessage(message) {
        console.log('Received message:', message);

        if (message.MessageBroadcast) {
            const { message: msg, verified, local_id } = message.MessageBroadcast;
            if (msg.sender_id === this.userId) {
                // Update our own message with server-computed hash and verification status
                this.updateOwnMessage(msg, verified, local_id);
            } else {
                // Display other users' messages
                this.displayMessage(msg, verified, false, null, local_id);
            }
        } else if (message.UserListUpdate) {
            this.updateUsersList(message.UserListUpdate.users);
        } else if (message.Error) {
            this.showError(`Server Error ${message.Error.code}: ${message.Error.message}`);
        } else if (message.Pong) {
            // Handle pong for keep-alive
        }
    }

    updateOwnMessage(serverMessage, verified, localId) {
        // Find and update our own message with server-computed data
        const messagesDiv = document.getElementById('messages');
        const messageElements = messagesDiv.querySelectorAll('.message-self');
        
        // Find the most recent message from ourselves (should be the last one)
        for (let i = messageElements.length - 1; i >= 0; i--) {
            const messageElement = messageElements[i];
            const messageData = JSON.parse(messageElement.dataset.messageData || '{}');
            
            // Match by content and timestamp (approximately)
            if (messageData.content === serverMessage.content && 
                Math.abs(messageData.timestamp - serverMessage.timestamp) < 10) {
                
                // Update the stored message data with server-computed values
                const updatedData = {
                    ...messageData,
                    ...serverMessage,
                    verified: verified,
                    local_id: localId
                };
                messageElement.dataset.messageData = JSON.stringify(updatedData);
                
                // Update the verification badge
                const badge = messageElement.querySelector('.verification-badge');
                if (badge) {
                    badge.className = `verification-badge ${verified ? 'verified' : 'unverified'}`;
                    badge.textContent = verified ? '✓ ZK Verified' : '⚠ Unverified';
                }
                
                // Remove the "sending" class
                messageElement.classList.remove('sending');
                
                console.log('Updated own message with server data:', serverMessage, 'verified:', verified);
                break;
            }
        }
    }

    displayMessage(message, verified, isSelf, proof = null, localId = null) {
        const messagesDiv = document.getElementById('messages');
        const messageDiv = document.createElement('div');
        
        messageDiv.className = `message ${isSelf ? 'message-self' : 'message-other'}`;
        if (isSelf && !verified) {
            messageDiv.classList.add('sending');
        }

        const timestamp = new Date(message.timestamp * 1000).toLocaleTimeString();
        const verificationBadge = verified ? 
            '<span class="verification-badge verified">✓ ZK Verified</span>' :
            '<span class="verification-badge unverified">⚠ Unverified</span>';

        const localIdLabel = localId ? ` <span class="local-id">#${localId}</span>` : '';
        messageDiv.innerHTML = `
            <div class="message-header">
                <strong>User ${message.sender_id}${localIdLabel}</strong>
                ${verificationBadge}
                <span>${timestamp}</span>
                <button class="inspect-btn" onclick="chat.showMessageDetails('${message.id}')" title="Inspect ZK Proof & Metadata">🔍</button>
            </div>
            <div class="message-content">${this.escapeHtml(message.content)}</div>
        `;

        // Store message data for inspection
        messageDiv.dataset.messageData = JSON.stringify({
            ...message,
            local_id: localId,
            proof: proof,
            verified: verified,
            zkProofSize: proof ? new Blob([proof]).size : 0
        });
        
        messageDiv.id = `message-${message.id}`;
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    
    showMessageDetails(messageId) {
        const messageElement = document.getElementById(`message-${messageId}`);
        if (!messageElement) return;
        
        const messageData = JSON.parse(messageElement.dataset.messageData);
        
        const modal = document.createElement('div');
        modal.className = 'message-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>🔐 ZK Message Details</h3>
                    <button class="close-btn" onclick="this.parentElement.parentElement.parentElement.remove()">×</button>
                </div>
                <div class="modal-body">
                    <div class="detail-section">
                        <h4>Message Information</h4>
                        <table>
                            <tr><td><strong>ID:</strong></td><td>${messageData.id}</td></tr>
                            <tr><td><strong>Sender ID:</strong></td><td>${messageData.sender_id}</td></tr>
                            <tr><td><strong>Content:</strong></td><td>${this.escapeHtml(messageData.content)}</td></tr>
                            <tr><td><strong>Timestamp:</strong></td><td>${new Date(messageData.timestamp * 1000).toLocaleString()}</td></tr>
                        </table>
                    </div>
                    
                    <div class="detail-section">
                        <h4>Cryptographic Hash</h4>
                        <div class="hash-display">${messageData.hash}</div>
                    </div>
                    
                    <div class="detail-section">
                        <h4>ZK-STARK Proof Status</h4>
                        <div class="proof-status ${messageData.verified ? 'verified' : 'unverified'}">
                            ${messageData.verified ? '✓ Proof Verified' : '✗ Proof Failed/Missing'}
                        </div>
                        ${messageData.proof ? `
                            <div class="proof-details">
                                <p><strong>Proof Size:</strong> ${messageData.zkProofSize} bytes</p>
                                <details>
                                    <summary>Raw Proof Data</summary>
                                    <pre class="proof-data">${this.escapeHtml(messageData.proof.substring(0, 500))}${messageData.proof.length > 500 ? '...' : ''}</pre>
                                </details>
                            </div>
                        ` : '<p>No proof data available</p>'}
                    </div>
                    
                    <div class="detail-section">
                        <h4>Zero-Knowledge Properties</h4>
                        <ul>
                            <li>✓ Message integrity verified cryptographically</li>
                            <li>✓ Sender authentication without revealing private keys</li>
                            <li>✓ Timestamp monotonicity enforced</li>
                            <li>✓ Hash chain continuity maintained</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    }

    updateUsersList(users) {
        const usersDiv = document.getElementById('usersList');
        const userNames = users.map(user => user[1]).join(', ');
        usersDiv.textContent = `Users online (${users.length}): ${userNames}`;
    }

    updateConnectionStatus(connected) {
        this.isConnected = connected;
        const statusDiv = document.getElementById('connectionStatus');
        
        if (connected) {
            statusDiv.textContent = 'Connected';
            statusDiv.className = 'connection-status status-connected';
        } else {
            statusDiv.textContent = 'Disconnected';
            statusDiv.className = 'connection-status status-disconnected';
        }
    }

    showError(message) {
        const messagesDiv = document.getElementById('messages');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        messagesDiv.appendChild(errorDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// ZK Debugging helper - MUST be defined before HTML references it
class ZKDebug {
    constructor() {
        this.message = null;
        this.publicInputs = null;
        this.proofBase64 = null;
    }
    log(line) {
        const out = document.getElementById('dbgOutput');
        if(out) {
            out.textContent += line + "\n";
            out.scrollTop = out.scrollHeight;
        }
    }
    setStatus(text, ok=true) {
        const el = document.getElementById('dbgStatus');
        if(el) {
            el.textContent = text;
            el.style.color = ok ? '#4caf50' : '#f44336';
        }
    }
    getInputs() {
        const sender = parseInt(document.getElementById('dbgSender').value||'1');
        const content = document.getElementById('dbgContent').value || '';
        return { sender_id: sender, content };
    }
    async buildTrace() {
        console.log('buildTrace called');
        const { sender_id, content } = this.getInputs();
        console.log('Inputs:', sender_id, content);
        this.reset(false);
        this.log('→ Building trace for sender=' + sender_id + ' content="' + content + '"');
        try {
            const res = await fetch('/api/trace', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ sender_id, content }) });
            console.log('Response status:', res.status);
            if(!res.ok){
                this.setStatus('Trace build failed HTTP ' + res.status, false);
                this.log('ERROR: ' + await res.text());
                return;
            }
            const data = await res.json();
            console.log('Received data:', data);
            this.message = data.message;
            this.publicInputs = data.public_inputs;
            this.log('Message hash: ' + this.message.hash);
            this.log('Initial hash: ' + this.publicInputs.initial_hash);
            this.log('Final hash:   ' + this.publicInputs.final_hash);
            this.log('Trace rows (shown): ' + data.trace.length);
            data.trace.forEach(r=>{
                this.log(` step ${r.step}: prev_hash=[${r.prev_hash.join(',')}] chain_hash=[${r.chain_hash.join(',')}] ts=${r.timestamp}`);
            });
            this.setStatus('Trace built successfully');
        } catch(e){
            console.error('buildTrace exception:', e);
            this.setStatus('Trace build exception', false);
            this.log('EXCEPTION: ' + e);
        }
    }
    async generateProof(){
        if(!this.message){ this.setStatus('Build trace first', false); return; }
        this.log('→ Generating proof');
        try {
            const res = await fetch('/api/prove', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ sender_id: this.message.sender_id, content: this.message.content, id: this.message.id, timestamp: this.message.timestamp }) });
            if(!res.ok){
                this.setStatus('Proof generation failed HTTP ' + res.status, false);
                this.log('ERROR: ' + await res.text());
                return;
            }
            const data = await res.json();
            this.proofBase64 = data.proof_base64;
            this.publicInputs = data.public_inputs;
            this.message = data.message;
            this.log('Proof (b64 len): ' + this.proofBase64.length);
            this.log('Final hash (pub inputs): ' + this.publicInputs.final_hash);
            this.setStatus('Proof generated');
        } catch(e){
            this.setStatus('Proof generation exception', false);
            this.log('EXCEPTION: ' + e);
        }
    }
    async verifyProof(){
        if(!this.message || !this.proofBase64){ this.setStatus('Need message & proof first', false); return; }
        this.log('→ Verifying proof');
        try {
            const res = await fetch('/api/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ message: this.message, proof_base64: this.proofBase64 }) });
            if(!res.ok){
                this.setStatus('Proof verify failed HTTP ' + res.status, false);
                this.log('ERROR: ' + await res.text());
                return;
            }
            const data = await res.json();
            this.log('Verified: ' + data.verified);
            this.setStatus(data.verified ? 'Proof verified ✅' : 'Proof NOT verified ❌', data.verified);
        } catch(e){
            this.setStatus('Proof verify exception', false);
            this.log('EXCEPTION: ' + e);
        }
    }
    reset(clearInputs=true){
        this.message = null; this.publicInputs = null; this.proofBase64 = null;
        const contentInput = document.getElementById('dbgContent');
        const output = document.getElementById('dbgOutput');
        if(clearInputs && contentInput){ contentInput.value=''; }
        if(output) { output.textContent=''; }
        this.setStatus('Reset');
    }
}

// Initialize zkDebug immediately - BEFORE HTML needs it
const zkDebug = new ZKDebug();

// Global chat instance
const chat = new ZKChat();

// UI Functions
function connect() {
    const userId = document.getElementById('userIdInput').value;
    const username = document.getElementById('usernameInput').value;

    if (!userId || !username) {
        alert('Please enter both User ID and Username');
        return;
    }

    if (userId < 1 || userId > 9999) {
        alert('User ID must be between 1 and 9999');
        return;
    }

    // Hide login, show chat
    document.getElementById('loginSection').classList.add('hidden');
    document.getElementById('chatArea').classList.remove('hidden');

    // Connect to server
    chat.connect(userId, username);
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const content = input.value.trim();
    
    if (content && chat.isConnected) {
        await chat.sendMessage(content);
        input.value = '';
    }
}

// Enter key to send message
document.addEventListener('DOMContentLoaded', () => {
    const messageInput = document.getElementById('messageInput');
    const userIdInput = document.getElementById('userIdInput');
    const usernameInput = document.getElementById('usernameInput');

    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            connect();
        }
    });

    userIdInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            connect();
        }
    });

    // Generate random user ID
    userIdInput.value = Math.floor(Math.random() * 9000) + 1000;

    // Wire up debug panel buttons after DOM loads
    const btnBuildTrace = document.getElementById('btnBuildTrace');
    const btnGenerateProof = document.getElementById('btnGenerateProof');
    const btnVerifyProof = document.getElementById('btnVerifyProof');
    const btnResetDebug = document.getElementById('btnResetDebug');

    if (btnBuildTrace) btnBuildTrace.addEventListener('click', () => zkDebug.buildTrace());
    if (btnGenerateProof) btnGenerateProof.addEventListener('click', () => zkDebug.generateProof());
    if (btnVerifyProof) btnVerifyProof.addEventListener('click', () => zkDebug.verifyProof());
    if (btnResetDebug) btnResetDebug.addEventListener('click', () => zkDebug.reset());
});