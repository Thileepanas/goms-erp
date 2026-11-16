// ===== Quick Actions Toggle =====
function toggleQuickMenu() {
    const menu = document.getElementById("quickMenu");
    if (!menu) return;
    menu.style.display = (menu.style.display === "flex") ? "none" : "flex";
}

document.addEventListener('click', function(event) {
    const menu = document.getElementById("quickMenu");
    const btn = document.querySelector(".quick-action-btn");
    if (menu && btn && !menu.contains(event.target) && !btn.contains(event.target)) {
        menu.style.display = "none";
    }
});

// ===== Keyboard Shortcuts (URLs base.html-ல் window.APP_URLS) =====
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.altKey && window.APP_URLS) {
        const map = {
            KeyB: window.APP_URLS.newBill,
            KeyP: window.APP_URLS.newPayment,
            KeyI: window.APP_URLS.newIndent,
            KeyW: window.APP_URLS.workProgress,
            KeyL: window.APP_URLS.clientLedger,
            KeyC: window.APP_URLS.projectPnl,
            KeyD: window.APP_URLS.dashboard,
        };
        const url = map[e.code];
        if (url) { e.preventDefault(); window.location.href = url; }
    }
});

// ===== Sidebar Collapse + Mobile Dropdown =====
document.addEventListener("DOMContentLoaded", function() {
    const toggleBtn = document.getElementById("sidebarToggle");
    if (toggleBtn) {
        if (localStorage.getItem("sidebarState") === "collapsed" && window.innerWidth > 768) {
            document.body.classList.add("sidebar-collapsed");
        }
        toggleBtn.addEventListener("click", function() {
            if (window.innerWidth <= 768) return;
            document.body.classList.toggle("sidebar-collapsed");
            localStorage.setItem("sidebarState",
                document.body.classList.contains("sidebar-collapsed") ? "collapsed" : "expanded");
        });
    }

    if (window.innerWidth <= 1024) {
        document.querySelectorAll('.dropdown > a').forEach(toggle => {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                const menu = this.nextElementSibling;
                const isVisible = menu.style.display === 'block';
                document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
                if (!isVisible) menu.style.display = 'block';
            });
        });
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.dropdown')) {
                document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
            }
        });
    }
});

// ===== Delete Confirmation =====
document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll('a[href*="/delete/"]').forEach(function(link) {
        link.addEventListener('click', function(e) {
            var msg = "⚠️ Are you sure you want to delete this record?\n\n" +
                      "This action CANNOT be undone.\n\n" +
                      "Click OK to delete, or Cancel to keep it.";
            if (!confirm(msg)) {
                e.preventDefault();
                return false;
            }
        });
    });
});
// ===== Global Toast Notification =====
window.showToast = function(message, type = 'success') {
    const bgColor = type === 'success' ? '#176b38' : '#e31e24';
    const toast = document.createElement('div');
    toast.innerHTML = message;
    toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; 
        background: ${bgColor}; color: white; 
        padding: 15px 25px; border-radius: 8px; 
        box-shadow: 0 4px 12px rgba(0,0,0,0.15); 
        z-index: 9999; font-weight: bold; font-size: 14px;
        transition: opacity 0.5s ease;
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 500);
    }, 3000);
};
