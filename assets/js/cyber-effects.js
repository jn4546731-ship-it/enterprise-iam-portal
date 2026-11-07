/**
 * Enterprise Zero-Trust IAM - Cyber Visual & Audio Engine
 * Lightweight, 60FPS Interactive Node Canvas + Web Audio API Synthesizer
 * 100% Offline & Air-Gapped
 */

// ==============================================================================
// 1. CYBER AUDIO SYNTHESIZER (Web Audio API)
// ==============================================================================
const CyberAudio = (function () {
    let ctx = null;
    let isMuted = localStorage.getItem('cyber_sfx_muted') === 'true';

    function getContext() {
        if (!ctx) {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) {
                ctx = new AudioContextClass();
            }
        }
        if (ctx && ctx.state === 'suspended') {
            ctx.resume();
        }
        return ctx;
    }

    function playTone(freq, type = 'sine', duration = 0.08, volume = 0.05) {
        if (isMuted) return;
        try {
            const c = getContext();
            if (!c) return;

            const osc = c.createOscillator();
            const gain = c.createGain();

            osc.type = type;
            osc.frequency.setValueAtTime(freq, c.currentTime);

            gain.gain.setValueAtTime(volume, c.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + duration);

            osc.connect(gain);
            gain.connect(c.destination);

            osc.start();
            osc.stop(c.currentTime + duration);
        } catch (e) {
            // Audio context not allowed until user gesture
        }
    }

    return {
        isMuted: () => isMuted,
        toggleMute: function () {
            isMuted = !isMuted;
            localStorage.setItem('cyber_sfx_muted', isMuted);
            if (!isMuted) {
                this.hover();
            }
            return isMuted;
        },
        hover: function () {
            playTone(1350, 'sine', 0.035, 0.03);
        },
        click: function () {
            playTone(880, 'triangle', 0.04, 0.05);
            setTimeout(() => playTone(1420, 'triangle', 0.06, 0.06), 40);
        },
        accessGranted: function () {
            if (isMuted) return;
            const c = getContext();
            if (!c) return;
            [523.25, 659.25, 783.99, 1046.50].forEach((freq, i) => {
                setTimeout(() => playTone(freq, 'sine', 0.22, 0.08), i * 90);
            });
        },
        accessDenied: function () {
            if (isMuted) return;
            [220, 196, 174].forEach((freq, i) => {
                setTimeout(() => playTone(freq, 'sawtooth', 0.18, 0.09), i * 110);
            });
        },
        terminalKeystroke: function () {
            playTone(900 + Math.random() * 400, 'sine', 0.02, 0.015);
        }
    };
})();

// ==============================================================================
// 2. INTERACTIVE CYBER DEFENSE NODE CANVAS
// ==============================================================================
class CyberBackground {
    constructor() {
        this.canvas = document.getElementById('cyberBackgroundCanvas');
        if (!this.canvas) {
            this.canvas = document.createElement('canvas');
            this.canvas.id = 'cyberBackgroundCanvas';
            this.canvas.style.position = 'fixed';
            this.canvas.style.top = '0';
            this.canvas.style.left = '0';
            this.canvas.style.width = '100vw';
            this.canvas.style.height = '100vh';
            this.canvas.style.pointerEvents = 'none';
            this.canvas.style.zIndex = '0';
            this.canvas.style.opacity = '0.45';
            document.body.prepend(this.canvas);
        }

        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];
        this.nodeCount = window.innerWidth < 768 ? 32 : 65;
        this.maxDistance = 130;
        this.mouse = { x: null, y: null, maxDistance: 150 };
        this.isRunning = true;

        this.init();
    }

    init() {
        this.resize();
        window.addEventListener('resize', () => this.resize());

        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });

        window.addEventListener('mouseleave', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });

        document.addEventListener('visibilitychange', () => {
            this.isRunning = !document.hidden;
            if (this.isRunning) this.animate();
        });

        this.createNodes();
        this.animate();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    createNodes() {
        this.nodes = [];
        const colors = ['#00f3ff', '#38bdf8', '#818cf8', '#a855f7'];

        for (let i = 0; i < this.nodeCount; i++) {
            this.nodes.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * 0.45,
                vy: (Math.random() - 0.5) * 0.45,
                radius: Math.random() * 1.8 + 0.8,
                color: colors[Math.floor(Math.random() * colors.length)],
                pulse: Math.random() * Math.PI
            });
        }
    }

    animate() {
        if (!this.isRunning) return;

        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        // Update and draw nodes
        for (let i = 0; i < this.nodes.length; i++) {
            const node = this.nodes[i];
            node.x += node.vx;
            node.y += node.vy;
            node.pulse += 0.03;

            // Bounce on boundary
            if (node.x < 0 || node.x > this.canvas.width) node.vx *= -1;
            if (node.y < 0 || node.y > this.canvas.height) node.vy *= -1;

            // Pulsing glow
            const currentRadius = node.radius + Math.sin(node.pulse) * 0.4;
            this.ctx.beginPath();
            this.ctx.arc(node.x, node.y, Math.max(0.4, currentRadius), 0, Math.PI * 2);
            this.ctx.fillStyle = node.color;
            this.ctx.shadowBlur = 8;
            this.ctx.shadowColor = node.color;
            this.ctx.fill();
            this.ctx.shadowBlur = 0;

            // Connect nearby nodes
            for (let j = i + 1; j < this.nodes.length; j++) {
                const other = this.nodes[j];
                const dx = node.x - other.x;
                const dy = node.y - other.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < this.maxDistance) {
                    const alpha = (1 - dist / this.maxDistance) * 0.22;
                    this.ctx.beginPath();
                    this.ctx.moveTo(node.x, node.y);
                    this.ctx.lineTo(other.x, other.y);
                    this.ctx.strokeStyle = `rgba(0, 243, 255, ${alpha})`;
                    this.ctx.lineWidth = 0.75;
                    this.ctx.stroke();
                }
            }

            // Mouse interaction (laser beam connection)
            if (this.mouse.x !== null && this.mouse.y !== null) {
                const mdx = node.x - this.mouse.x;
                const mdy = node.y - this.mouse.y;
                const mdist = Math.sqrt(mdx * mdx + mdy * mdy);

                if (mdist < this.mouse.maxDistance) {
                    const mAlpha = (1 - mdist / this.mouse.maxDistance) * 0.45;
                    this.ctx.beginPath();
                    this.ctx.moveTo(node.x, node.y);
                    this.ctx.lineTo(this.mouse.x, this.mouse.y);
                    this.ctx.strokeStyle = `rgba(168, 85, 247, ${mAlpha})`;
                    this.ctx.lineWidth = 1;
                    this.ctx.stroke();
                }
            }
        }

        requestAnimationFrame(() => this.animate());
    }
}

// ==============================================================================
// 3. NUMBER ANIMATOR & CYBER HELPER UTILITIES
// ==============================================================================
const CyberFX = {
    animateCounter: function (el, endValue, duration = 1200, prefix = '', suffix = '') {
        if (!el) return;
        const startValue = 0;
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            const ease = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(startValue + (endValue - startValue) * ease);

            el.textContent = `${prefix}${current.toLocaleString()}${suffix}`;

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                el.textContent = `${prefix}${endValue.toLocaleString()}${suffix}`;
            }
        }

        requestAnimationFrame(update);
    }
};

// ==============================================================================
// 4. AUTO-ATTACH EVENT LISTENERS ON PAGE LOAD
// ==============================================================================
window.addEventListener('DOMContentLoaded', function () {
    // 1. Initialize background particle canvas
    new CyberBackground();

    // 2. Attach hover & click sound triggers
    const interactiveElements = document.querySelectorAll('button, a, input[type="submit"], .cyber-interactive');
    interactiveElements.forEach((el) => {
        el.addEventListener('mouseenter', () => CyberAudio.hover());
        el.addEventListener('click', () => CyberAudio.click());
    });

    // 3. Animate numbers tagged with data-cyber-count
    document.querySelectorAll('[data-cyber-count]').forEach((el) => {
        const target = parseFloat(el.getAttribute('data-cyber-count')) || 0;
        const prefix = el.getAttribute('data-prefix') || '';
        const suffix = el.getAttribute('data-suffix') || '';
        CyberFX.animateCounter(el, target, 1000, prefix, suffix);
    });
});
