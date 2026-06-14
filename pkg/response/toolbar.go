package response

import (
	"encoding/json"
	"go-reauth-proxy/pkg/i18n"
	"go-reauth-proxy/pkg/models"
	"net/http"
	"strings"
)

const toolbarTemplate = `
<script>
(function(window, document) {
    if (window.self !== window.top) return;
    if (document.getElementById('reauth-proxy-toolbar')) return;

    var container = document.createElement('div');
    container.id = 'reauth-proxy-toolbar';
    container.style.position = 'fixed';
    container.style.zIndex = '2147483647';
    container.style.fontFamily = 'ui-sans-serif, system-ui, sans-serif';

    function applyPosition(pos) {
        var margin = 20;

        container.style.bottom = 'auto';
        container.style.right = 'auto';

        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;

        var fabSize = 44;

        if (pos === 'tl') {
            container.style.top = (vvTop + margin) + 'px';
            container.style.left = (vvLeft + margin) + 'px';
        } else if (pos === 'tr') {
            container.style.top = (vvTop + margin) + 'px';
            container.style.left = (vvLeft + vvWidth - margin - fabSize) + 'px';
        } else if (pos === 'bl') {
            container.style.top = (vvTop + vvHeight - margin - fabSize) + 'px';
            container.style.left = (vvLeft + margin) + 'px';
        } else {
            container.style.top = (vvTop + vvHeight - margin - fabSize) + 'px';
            container.style.left = (vvLeft + vvWidth - margin - fabSize) + 'px';
        }
    }

    applyPosition(localStorage.getItem('reauth_proxy_toolbar_pos') || 'br');

    var shadow = container.attachShadow({mode: 'open'});

    var style = document.createElement('style');
    style.textContent = ` + "`" + `
        .dot {
            width: 8px;
            height: 8px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-block;
        }
        #fab {
            width: 44px;
            height: 44px;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            color: #fff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: move;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(255, 255, 255, 0.1);
            user-select: none;
            transition: transform 0.2s, background 0.2s;
            position: relative;
        }
        #fab:hover {
            transform: scale(1.05);
            background: rgba(0, 0, 0, 0.95);
        }
        #fab:active {
            transform: scale(0.95);
        }
        #fab svg {
            width: 20px;
            height: 20px;
            pointer-events: none;
        }
        #menu {
            position: absolute;
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            width: 220px;
            display: none;
            flex-direction: column;
            overflow: hidden;
            box-sizing: border-box;
            max-height: calc(100vh - 96px);
            transform-origin: bottom right;
            opacity: 0;
            transform: scale(0.95) translateY(10px);
            transition: opacity 0.15s ease, transform 0.15s ease;
        }
        #menu.open {
            display: flex;
            opacity: 1;
            transform: scale(1) translateY(0);
        }
        .menu-item {
            padding: 10px 16px;
            color: #4b5563;
            text-decoration: none;
            font-size: 14px;
            border-bottom: 1px solid #f3f4f6;
            transition: background-color 0.15s, color 0.15s;
            display: flex; /* Make menu items flex containers. */
            align-items: center; /* Vertically center all content. */
            justify-content: space-between; /* Keep the path left and status/action right. */
            white-space: nowrap;
            overflow: hidden;
            position: relative;
        }
        .menu-item:last-child {
            border-bottom: none;
        }
        .menu-item:hover {
            background-color: #f9fafb;
            color: #111827;
        }
        .menu-item.active {
            color: #18181b;
            font-weight: 600;
        }
        .menu-item.active:hover {
            background-color: #f9fafb;
        }
        /* Path segment styles. */
        .menu-item-path {
            flex-grow: 1; /* Let the path take the remaining space. */
            overflow: hidden;
            text-overflow: ellipsis;
        }
        /* Right-side status/action styles. */
        .menu-item-right-content {
            display: flex; /* Provide flex layout for the dot/text. */
            align-items: center; /* Vertically center the dot and text. */
            gap: 6px; /* Space between the dot and Go text when active. */
            font-size: 12px; /* Right-side content size. */
            color: #6b7280; /* Default color. */
            margin-left: 12px; /* Space between path and right-side content. */
        }
        .menu-item.active .menu-item-right-content {
            color: #18181b; /* Active text color. */
        }
        .menu-item.active .menu-item-right-content .dot {
            background-color: #10b981; /* Active dot color. */
        }
        .menu-empty {
            padding: 12px 16px;
            color: #6b7280;
            font-size: 13px;
            background: #fff;
            border-bottom: 1px solid #f3f4f6;
        }
        .menu-scroll {
            flex: 1 1 auto;
            min-height: 0;
            overflow-y: auto;
            overscroll-behavior: contain;
            -webkit-overflow-scrolling: touch;
        }
        .menu-divider {
            height: 4px;
            background: #f9fafb;
            flex-shrink: 0;
        }
        .logout-btn {
            color: #ef4444;
            font-weight: 500;
        }
        .logout-btn:hover {
            background-color: #fef2f2;
            color: #b91c1c;
        }
        .menu-header {
            padding: 12px 16px;
            font-size: 12px;
            text-transform: uppercase;
            color: #6b7280;
            font-weight: 600;
            letter-spacing: 0.05em;
            background: #f9fafb;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .menu-header span {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        /* Dot styles are defined near the top of this file. */
        .toolbar-alert-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            opacity: 0;
            transition: opacity 0.2s ease;
        }
        .toolbar-alert-overlay.show {
            opacity: 1;
        }
        .toolbar-alert-box {
            background: #fff;
            border-radius: 8px;
            padding: 24px;
            width: 320px;
            max-width: 90vw;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            transform: scale(0.95) translateY(10px);
            transition: transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            text-align: center;
            box-sizing: border-box;
        }
        .toolbar-alert-overlay.show .toolbar-alert-box {
            transform: scale(1) translateY(0);
        }
        .toolbar-alert-title {
            font-size: 18px;
            font-weight: 600;
            color: #111827;
            margin: 0 0 8px 0;
        }
        .toolbar-alert-message {
            font-size: 14px;
            color: #4b5563;
            margin: 0 0 24px 0;
            line-height: 1.5;
        }
        .toolbar-alert-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
        }
        .toolbar-alert-btn {
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
            flex: 1;
            font-family: inherit;
        }
        .toolbar-alert-btn-cancel {
            background: #f3f4f6;
            color: #4b5563;
        }
        .toolbar-alert-btn-cancel:hover {
            background: #e5e7eb;
            color: #111827;
        }
        .toolbar-alert-btn-confirm {
            background: #ef4444;
            color: #fff;
        }
        .toolbar-alert-btn-confirm:hover {
            background: #dc2626;
        }
    ` + "`" + `;

	var toolbarData = __REAUTH_TOOLBAR_DATA__;
	var toolbarLabels = toolbarData.labels || {};
	function label(key, fallback) {
	    return typeof toolbarLabels[key] === 'string' && toolbarLabels[key] ? toolbarLabels[key] : fallback;
	}
	var html = ` + "`" + `
	    <div id="wrapper" style="position: relative;">
	        <div id="menu">
	            <div class="menu-header">
	                <span><i class="dot"></i> Go Reauth Proxy</span>
	            </div>
	            <div class="menu-scroll"></div>
	            <div class="menu-divider"></div>
	            <a href="/__auth__/api/auth/logout" class="menu-item logout-btn">${label('logout', 'Logout')}</a>
	        </div>
            <div id="fab">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                    <circle cx="18" cy="6" r="3" fill="#3b82f6" stroke="none" />
                </svg>
            </div>
        </div>
    ` + "`" + `;

    shadow.appendChild(style);
    var div = document.createElement('div');
    div.innerHTML = html;
    shadow.appendChild(div);

	var fab = shadow.getElementById('fab');
	var menu = shadow.getElementById('menu');
	var menuScroll = shadow.querySelector('.menu-scroll');

	function asString(value) {
	    return typeof value === 'string' ? value : '';
	}

	function ensureSlash(path) {
	    path = asString(path);
	    return path.endsWith('/') ? path : path + '/';
	}

	function normalizeHost(host) {
	    return asString(host).trim().toLowerCase().replace(/\.$/, '');
	}

	function isActivePath(rulePath, currentPath) {
	    currentPath = asString(currentPath);
	    if (!currentPath) return false;
	    var rp = asString(rulePath).replace(/\/$/, '');
	    var cp = currentPath.replace(/\/$/, '');
	    return rp === cp || cp.indexOf(rp + '/') === 0 || cp.indexOf(rp) === 0;
	}

	function isActiveHost(ruleHost, currentHost) {
	    var rh = normalizeHost(ruleHost);
	    var ch = normalizeHost(currentHost);
	    return !!rh && rh === ch;
	}

	function appendRightContent(anchor, active) {
	    var right = document.createElement('span');
	    right.className = 'menu-item-right-content';
	    if (active) {
	        var dot = document.createElement('i');
	        dot.className = 'dot';
	        right.appendChild(dot);
	    } else {
	        var go = document.createElement('span');
	        go.className = 'menu-item-go-text';
	        go.textContent = label('go', 'Go');
	        right.appendChild(go);
	    }
	    anchor.appendChild(right);
	}

	function createMenuLink(label, href, extraClass, active) {
	    var anchor = document.createElement('a');
	    anchor.href = href;
	    anchor.target = '_blank';
	    anchor.rel = 'noopener noreferrer';
	    anchor.className = 'menu-item nav-link ' + extraClass + (active ? ' active' : '');

	    var text = document.createElement('span');
	    text.className = 'menu-item-path';
	    text.textContent = label;
	    anchor.appendChild(text);
	    appendRightContent(anchor, active);
	    return anchor;
	}

	function appendEmptyMenu() {
	    var empty = document.createElement('div');
	    empty.className = 'menu-empty';
	    empty.textContent = label('noRoutesConfigured', 'No routes configured');
	    menuScroll.appendChild(empty);
	}

	function populateMenu() {
	    if (!menuScroll) return;
	    var hostRules = Array.isArray(toolbarData.host_rules) ? toolbarData.host_rules : [];
	    var rules = Array.isArray(toolbarData.rules) ? toolbarData.rules : [];

	    if (hostRules.length > 0) {
	        for (var i = 0; i < hostRules.length; i++) {
	            var host = asString(hostRules[i].host);
	            var label = asString(hostRules[i].label) || host;
	            var hostLink = createMenuLink(label, '/', 'host-link', isActiveHost(host, toolbarData.current_host));
	            hostLink.setAttribute('data-host', host);
	            menuScroll.appendChild(hostLink);
	        }
	        return;
	    }

	    if (rules.length > 0) {
	        for (var j = 0; j < rules.length; j++) {
	            var path = asString(rules[j].path);
	            menuScroll.appendChild(createMenuLink(path, ensureSlash(path), 'rule-link', isActivePath(path, toolbarData.current_path)));
	        }
	        return;
	    }

	    appendEmptyMenu();
	}

	populateMenu();

	function buildHostHref(host) {
	    host = asString(host).trim();
	    if (!host) return '/';
	    var port = window.location.port ? ':' + window.location.port : '';
	    var candidate = window.location.protocol + '//' + host + port + '/';
	    try {
	        return new URL(candidate).href;
	    } catch (err) {
	        return '/';
	    }
	}

    var navLinks = shadow.querySelectorAll('.nav-link');
    for (var i = 0; i < navLinks.length; i++) {
        var host = navLinks[i].getAttribute('data-host');
        if (host) {
            navLinks[i].setAttribute('href', buildHostHref(host));
        }

        navLinks[i].addEventListener('click', function(e) {
            e.preventDefault(); 
            e.stopPropagation(); 
            window.open(this.getAttribute('href'), '_blank', 'noopener,noreferrer');
            menu.classList.remove('open');
        });
    }

    var isDragging = false;
    var startX, startY, initialLeft, initialTop;
    var dragged = false;
    var lastTouchTime = 0;

    fab.addEventListener('mousedown', onDragStart);
    fab.addEventListener('touchstart', onDragStart, { passive: false });

    function onDragStart(e) {
        if (e.type === 'touchstart') {
            lastTouchTime = Date.now();
        } else if (e.type === 'mousedown') {
            if (Date.now() - lastTouchTime < 500) return;
            if (e.button !== 0) return;
        }
        
        var clientX = e.type === 'touchstart' ? e.touches[0].clientX : e.clientX;
        var clientY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY;
        
        isDragging = true;
        dragged = false;
        startX = clientX;
        startY = clientY;
        
        var rect = container.getBoundingClientRect();
        
        container.style.bottom = 'auto';
        container.style.right = 'auto';
        container.style.left = rect.left + 'px';
        container.style.top = rect.top + 'px';
        
        initialLeft = rect.left;
        initialTop = rect.top;
        
        if (e.type === 'mousedown') {
            document.addEventListener('mousemove', onDragMove);
            document.addEventListener('mouseup', onDragEnd);
            e.preventDefault();
        } else {
            document.addEventListener('touchmove', onDragMove, { passive: false });
            document.addEventListener('touchend', onDragEnd);
            document.addEventListener('touchcancel', onDragEnd);
        }
    }

    function onDragMove(e) {
        if (!isDragging) return;
        
        var clientX = e.type === 'touchmove' ? e.touches[0].clientX : e.clientX;
        var clientY = e.type === 'touchmove' ? e.touches[0].clientY : e.clientY;
        
        var dx = clientX - startX;
        var dy = clientY - startY;
        
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
            dragged = true;
        }
        
        var newLeft = initialLeft + dx;
        var newTop = initialTop + dy;
        
        container.style.left = newLeft + 'px';
        container.style.top = newTop + 'px';
        
        if (e.type === 'touchmove' && dragged) {
            e.preventDefault(); // prevent scrolling
        }
    }

    function onDragEnd(e) {
        if (!isDragging) return;
        isDragging = false;
        
        if (e.type === 'mouseup') {
            document.removeEventListener('mousemove', onDragMove);
            document.removeEventListener('mouseup', onDragEnd);
        } else {
            document.removeEventListener('touchmove', onDragMove);
            document.removeEventListener('touchend', onDragEnd);
            document.removeEventListener('touchcancel', onDragEnd);
        }
        
        if (e.type === 'touchend' && e.cancelable) {
            e.preventDefault();
        }
        
        if (dragged) {
            snapToEdge();
        } else {
            // Because toggleMenu might cause reflows, defer it slightly
            setTimeout(toggleMenu, 10);
        }
    }
    
    function snapToEdge() {
        var rect = container.getBoundingClientRect();
        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;
        
        var centerX = rect.left + rect.width / 2;
        var centerY = rect.top + rect.height / 2;
        
        var isLeft = centerX < (vvLeft + vvWidth / 2);
        var isTop = centerY < (vvTop + vvHeight / 2);
        
        container.style.transition = 'left 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), top 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)';
        
        var pos = '';
        if (isTop && isLeft) pos = 'tl';
        else if (isTop && !isLeft) pos = 'tr';
        else if (!isTop && isLeft) pos = 'bl';
        else pos = 'br';
        
        localStorage.setItem('reauth_proxy_toolbar_pos', pos);
        
        applyPosition(pos);
        
        setTimeout(() => {
            container.style.transition = '';
        }, 300);
        
        updateMenuPosition();
    }

    function toggleMenu() {
        if (menu.classList.contains('open')) {
            menu.classList.remove('open');
        } else {
            updateMenuPosition();
            if (menuScroll) {
                menuScroll.scrollTop = 0;
            }
            menu.classList.add('open');
        }
    }
    
    function updateMenuPosition() {
        var rect = container.getBoundingClientRect();
        var vv = window.visualViewport;
        var vvLeft = vv ? vv.offsetLeft : 0;
        var vvTop = vv ? vv.offsetTop : 0;
        var vvWidth = vv ? vv.width : window.innerWidth;
        var vvHeight = vv ? vv.height : window.innerHeight;
        
        var centerX = rect.left + rect.width / 2;
        var centerY = rect.top + rect.height / 2;
        
        var isLeft = centerX < (vvLeft + vvWidth / 2);
        var isTop = centerY < (vvTop + vvHeight / 2);
        
        if (isLeft) {
            menu.style.right = 'auto';
            menu.style.left = '0';
            menu.style.transformOrigin = isTop ? 'top left' : 'bottom left';
        } else {
            menu.style.left = 'auto';
            menu.style.right = '0';
            menu.style.transformOrigin = isTop ? 'top right' : 'bottom right';
        }
        
        if (!isTop) {
            menu.style.bottom = '56px';
            menu.style.top = 'auto';
        } else {
            menu.style.top = '56px';
            menu.style.bottom = 'auto';
        }

        var viewportPadding = 20;
        var menuOffset = 56;
        var menuBottomAnchor = rect.top + rect.height - menuOffset;
        var menuTopAnchor = rect.top + menuOffset;
        var availableHeight = isTop ?
            (vvTop + vvHeight - viewportPadding) - menuTopAnchor :
            menuBottomAnchor - (vvTop + viewportPadding);

        var constrainedHeight = Math.max(0, Math.floor(availableHeight));
        menu.style.maxHeight = constrainedHeight + 'px';
    }

    var logoutBtn = shadow.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation(); 
            var href = this.getAttribute('href');
            
            var overlay = document.createElement('div');
            overlay.className = 'toolbar-alert-overlay';
            
            var box = document.createElement('div');
            box.className = 'toolbar-alert-box';
            
            var titleHtml = '<h3 class="toolbar-alert-title">' + label('logoutTitle', 'Logout') + '</h3>';
            var msgHtml = '<p class="toolbar-alert-message">' + label('logoutMessage', 'Are you sure you want to logout?') + '</p>';
            var actionsHtml = '<div class="toolbar-alert-actions">' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-cancel">' + label('cancel', 'Cancel') + '</button>' +
                '<button class="toolbar-alert-btn toolbar-alert-btn-confirm">' + label('confirm', 'Confirm') + '</button>' +
                '</div>';
                
            box.innerHTML = titleHtml + msgHtml + actionsHtml;
            overlay.appendChild(box);
            
            var cancelBtn = box.querySelector('.toolbar-alert-btn-cancel');
            var confirmBtn = box.querySelector('.toolbar-alert-btn-confirm');
            
            function updateOverlayPos() {
                var vv = window.visualViewport;
                if (vv) {
                    overlay.style.top = vv.offsetTop + 'px';
                    overlay.style.left = vv.offsetLeft + 'px';
                    overlay.style.width = vv.width + 'px';
                    overlay.style.height = vv.height + 'px';
                    overlay.style.bottom = 'auto';
                    overlay.style.right = 'auto';
                }
            }
            updateOverlayPos();
            
            if (window.visualViewport) {
                window.visualViewport.addEventListener('resize', updateOverlayPos);
                window.visualViewport.addEventListener('scroll', updateOverlayPos);
            }
            window.addEventListener('resize', updateOverlayPos);
            window.addEventListener('scroll', updateOverlayPos);
            
            function close() {
                overlay.classList.remove('show');
                menu.classList.remove('open');
                if (window.visualViewport) {
                    window.visualViewport.removeEventListener('resize', updateOverlayPos);
                    window.visualViewport.removeEventListener('scroll', updateOverlayPos);
                }
                window.removeEventListener('resize', updateOverlayPos);
                window.removeEventListener('scroll', updateOverlayPos);
                setTimeout(function() {
                    if (overlay.parentNode) {
                        overlay.parentNode.removeChild(overlay);
                    }
                }, 200);
            }
            
            cancelBtn.addEventListener('click', close);
            confirmBtn.addEventListener('click', function() {
                close();
                window.location.href = href;
            });
            
            overlay.addEventListener('click', function(evt) {
                if (evt.target === overlay) {
                    close();
                }
            });
            
            shadow.appendChild(overlay);
            
            // Trigger reflow for animation
            overlay.offsetHeight;
            overlay.classList.add('show');
        });
    }

    document.addEventListener('click', function(e) {
        if (isDragging || dragged) return;
        var path = e.composedPath ? e.composedPath() : e.path;
        var clickedInside = false;
        if (path) {
            for (var i = 0; i < path.length; i++) {
                if (path[i] === container) {
                    clickedInside = true;
                    break;
                }
            }
        } else {
            clickedInside = container.contains(e.target);
        }
        
        if (!clickedInside && menu.classList.contains('open')) {
            menu.classList.remove('open');
        }
    });

    function updateToolbarPosition() {
        if (isDragging) return;
        var pos = localStorage.getItem('reauth_proxy_toolbar_pos') || 'br';
        applyPosition(pos);
        if (menu.classList.contains('open')) {
            updateMenuPosition();
        }
    }

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', updateToolbarPosition);
        window.visualViewport.addEventListener('scroll', updateToolbarPosition);
    }
    window.addEventListener('resize', updateToolbarPosition);
    window.addEventListener('scroll', updateToolbarPosition);

    document.body.appendChild(container);
})(window, document);
	</script>
	`

const toolbarDataMarker = "__REAUTH_TOOLBAR_DATA__"

type toolbarRuleData struct {
	Path string `json:"path"`
}

type toolbarHostRuleData struct {
	Host  string `json:"host"`
	Label string `json:"label,omitempty"`
}

type toolbarData struct {
	Rules       []toolbarRuleData     `json:"rules"`
	HostRules   []toolbarHostRuleData `json:"host_rules"`
	CurrentPath string                `json:"current_path"`
	CurrentHost string                `json:"current_host"`
	Labels      map[string]string     `json:"labels"`
}

func ShouldSuppressToolbarForUserAgent(userAgent string) bool {
	normalized := strings.ToLower(strings.TrimSpace(userAgent))
	if normalized == "" {
		return false
	}

	return strings.Contains(normalized, "com.trim.app") ||
		strings.Contains(normalized, "com.trim.media") ||
		strings.Contains(normalized, "fnos")
}

func GenerateToolbar(rules []models.Rule, currentPath string) string {
	return GenerateToolbarForLocale(i18n.DefaultLocaleValue(), rules, currentPath)
}

func GenerateToolbarForRequest(r *http.Request, rules []models.Rule, currentPath string) string {
	return GenerateToolbarForLocale(i18n.ResolveRequestLocale(r), rules, currentPath)
}

func GenerateToolbarForLocale(locale string, rules []models.Rule, currentPath string) string {
	return GenerateToolbarWithHostsForLocale(locale, rules, nil, currentPath, "", "", models.GatewayPortalConfig{})
}

func GatewayPortalHostLabel(rule models.HostRule, portalConfig models.GatewayPortalConfig) string {
	if models.NormalizeGatewayPortalConfig(portalConfig).DisplayStyle == models.GatewayPortalDisplayStyleTitle {
		if title := strings.TrimSpace(rule.Title); title != "" {
			return title
		}
	}
	return rule.Host
}

func normalizeToolbarHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func filterToolbarHostRules(hostRules []models.HostRule, excludedHost string) []models.HostRule {
	normalizedExcludedHost := normalizeToolbarHost(excludedHost)
	if normalizedExcludedHost == "" {
		return hostRules
	}

	filtered := make([]models.HostRule, 0, len(hostRules))
	for _, rule := range hostRules {
		if normalizeToolbarHost(rule.Host) == normalizedExcludedHost {
			continue
		}
		filtered = append(filtered, rule)
	}
	return filtered
}

func GenerateToolbarWithHosts(rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarWithHostsForLocale(i18n.DefaultLocaleValue(), rules, hostRules, currentPath, currentHost, excludedHost, portalConfig)
}

func GenerateToolbarWithHostsForRequest(r *http.Request, rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	return GenerateToolbarWithHostsForLocale(i18n.ResolveRequestLocale(r), rules, hostRules, currentPath, currentHost, excludedHost, portalConfig)
}

func GenerateToolbarWithHostsForLocale(locale string, rules []models.Rule, hostRules []models.HostRule, currentPath string, currentHost string, excludedHost string, portalConfig models.GatewayPortalConfig) string {
	filteredHostRules := filterToolbarHostRules(hostRules, excludedHost)

	data := toolbarData{
		Rules:       make([]toolbarRuleData, 0, len(rules)),
		HostRules:   make([]toolbarHostRuleData, 0, len(filteredHostRules)),
		CurrentPath: currentPath,
		CurrentHost: currentHost,
		Labels: map[string]string{
			"logout":             i18n.T(locale, "gateway.logout"),
			"logoutTitle":        i18n.T(locale, "gateway.logoutConfirmTitle"),
			"logoutMessage":      i18n.T(locale, "gateway.logoutConfirmMessage"),
			"cancel":             i18n.T(locale, "gateway.cancel"),
			"confirm":            i18n.T(locale, "gateway.confirm"),
			"go":                 i18n.T(locale, "gateway.go"),
			"noRoutesConfigured": i18n.T(locale, "gateway.noRoutesConfigured"),
		},
	}
	for _, rule := range rules {
		data.Rules = append(data.Rules, toolbarRuleData{Path: rule.Path})
	}
	for _, rule := range filteredHostRules {
		data.HostRules = append(data.HostRules, toolbarHostRuleData{
			Host:  rule.Host,
			Label: GatewayPortalHostLabel(rule, portalConfig),
		})
	}

	payload, err := json.Marshal(data)
	if err != nil {
		payload = []byte(`{"rules":[],"host_rules":[],"current_path":"","current_host":""}`)
	}
	return strings.Replace(toolbarTemplate, toolbarDataMarker, string(payload), 1)
}
