// Lab 4 (2.2 - 2.5): Privacy-Preserving Keystroke Dynamics Collector
// Captures ONLY numeric inter-keystroke timing intervals (ms) and paste flag.
// NEVER captures, stores, or transmits raw typed characters!
(function () {
    const pwdInput = document.getElementById("passwordInput");
    const intervalsField = document.getElementById("keystrokeIntervals");
    const isPastedField = document.getElementById("isPasted");
    if (!pwdInput || !intervalsField || !isPastedField) {
        return;
    }

    let lastTimestamp = null;
    const intervals = [];

    pwdInput.addEventListener("keydown", function () {
        const now = performance.now();
        if (lastTimestamp !== null) {
            const delta = Math.round(now - lastTimestamp);
            if (delta >= 0 && delta <= 5000 && intervals.length < 100) {
                intervals.push(delta);
            }
        }
        lastTimestamp = now;
        intervalsField.value = JSON.stringify(intervals);
    });

    pwdInput.addEventListener("paste", function () {
        isPastedField.value = "1";
    });
})();
