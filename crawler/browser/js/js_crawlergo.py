#!/user/bin/env python
"""
@Time   : 2022-02-24 16:14
@Author : LFY
@File   : js_crawlergo.py
"""

# here put the import lib

TabInitJS = """
// Pass the Webdriver Test.
Object.defineProperty(navigator, 'webdriver', {
    get: () => false,
});

// Pass the Plugins Length Test.
// Overwrite the plugins property to use a custom getter.
Object.defineProperty(navigator, 'plugins', {
    // This just needs to have length > 0 for the current test,
    // but we could mock the plugins too if necessary.
    get: () => [1, 2, 3, 4, 5],
});

// Pass the Chrome Test.
// We can mock this in as much depth as we need for the test.
window.chrome = {
    runtime: {},
};

// Pass the Permissions Test.
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

//Pass the Permissions Test. navigator.userAgent
Object.defineProperty(navigator, 'userAgent', {
    get: () => "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36",
});

// 修改浏览器对象的属性
Object.defineProperty(navigator, 'platform', {
    get: function () { return 'win32'; }
});

Object.defineProperty(navigator, 'language', {
    get: function () { return 'zh-CN'; }
});

Object.defineProperty(navigator, 'languages', {
    get: function () { return ["zh-CN", "zh"]; }
});

window.__toAbsUrl = function(url) {
    try {
        if (url === undefined || url === null || url === "") {
            return "";
        }
        return new URL(String(url), document.baseURI).href;
    } catch(e) {
        return String(url);
    }
};

window.__logNavigationUrl = function(url) {
    try {
        const normalized = window.__toAbsUrl(url);
        if (normalized && normalized !== "undefined" && normalized !== "null") {
            console.log("getNavigationUrl:" + normalized);
        }
    } catch(e) {}
};

// history api hook
window.history.pushState = function(a, b, c) {
    window.__logNavigationUrl(c);
    return null;
}
window.history.replaceState = function(a, b, c) {
    window.__logNavigationUrl(c);
    return null;
}
Object.defineProperty(window.history,"pushState",{"writable": false, "configurable": false});
Object.defineProperty(window.history,"replaceState",{"writable": false, "configurable": false});

// hook location.assign/location.replace when possible
try {
    window.location.assign = function(url) {
        window.__logNavigationUrl(url);
        return null;
    }
} catch(e) {}
try {
    window.location.replace = function(url) {
        window.__logNavigationUrl(url);
        return null;
    }
} catch(e) {}

// 监听hash改变
window.addEventListener("hashchange", function() {
    window.__logNavigationUrl(document.location.href);
});

var oldWebSocket = window.WebSocket;
window.WebSocket = function(url, arg) {
    window.__logNavigationUrl(url);
    return new oldWebSocket(url, arg);
}
window.WebSocket.prototype = oldWebSocket.prototype;

var oldEventSource = window.EventSource;
window.EventSource = function(url) {
    window.__logNavigationUrl(url);
    return new oldEventSource(url);
}
window.EventSource.prototype = oldEventSource.prototype;

// fetch请求有时需要options
var oldFetch = window.fetch;
window.fetch = function(url, options) {
    const defaultOptions = {
        method: 'GET', 
        headers: {
            'Content-Type': 'application/json'
        }
    };
    const fetchOptions = options === undefined ? defaultOptions : {...defaultOptions, ...options};
    window.__logNavigationUrl(url);
    return oldFetch(url, fetchOptions);
};


// 锁定表单重置
HTMLFormElement.prototype.reset = function() {};
Object.defineProperty(HTMLFormElement.prototype,"reset",{"writable": false, "configurable": false});

window.__sec_auto_global_sig_count = {};

function getElementSignature(node, eventName) {
    if (!node) return "unknown|" + eventName;

    let tag = node.tagName || "";
    let id = node.id ? "#" + node.id : "";
    let nameAttr = node.name ? "[name=" + node.name + "]" : "";

    let cls = "";
    if (typeof node.className === "string" && node.className) {
        cls = "." + node.className.trim().split(" ").filter(Boolean).sort().join(".");
    }

    let parentTag = (node.parentNode && node.parentNode.tagName) ? node.parentNode.tagName + ">" : "";

    return parentTag + tag + id + nameAttr + cls + "|" + eventName;
}

let old_event_handle = Element.prototype.addEventListener;
Element.prototype.addEventListener = function(event_name, event_func, useCapture) {
    old_event_handle.apply(this, arguments);

    if (!this.__sec_auto_marked_events) {
        this.__sec_auto_marked_events = {};
    }
    if (this.__sec_auto_marked_events[event_name]) {
        return;
    }

    let signature = getElementSignature(this, event_name);
    if (!window.__sec_auto_global_sig_count[signature]) {
        window.__sec_auto_global_sig_count[signature] = 0;
    }

    if (window.__sec_auto_global_sig_count[signature] >= 5) {
        return;
    }

    window.__sec_auto_global_sig_count[signature] += 1;
    this.__sec_auto_marked_events[event_name] = true;

    if (this.hasAttribute("sec_auto_dom2_event_flag")) {
        let sec_auto_dom2_event_flag = this.getAttribute("sec_auto_dom2_event_flag");
        let flags = sec_auto_dom2_event_flag.split("|");
        if (!flags.includes(event_name)) {
            this.setAttribute("sec_auto_dom2_event_flag", sec_auto_dom2_event_flag + "|" + event_name);
        }
    } else {
        this.setAttribute("sec_auto_dom2_event_flag", event_name);
    }
};

const __dom0EventMap = {
    onclick: "click", onchange: "change", onblur: "blur", ondblclick: "dblclick",
    onfocus: "focus", onkeydown: "keydown", onkeypress: "keypress", onkeyup: "keyup",
    onmousedown: "mousedown", onmousemove: "mousemove", onmouseout: "mouseout",
    onmouseover: "mouseover", onmouseup: "mouseup", onreset: "reset", onresize: "resize",
    onselect: "select", onsubmit: "submit", onunload: "unload", onabort: "abort", onerror: "error",
};

function dom0_listener_hook(that, event_name) {
    if (!that.__sec_auto_marked_events) {
        that.__sec_auto_marked_events = {};
    }
    if (that.__sec_auto_marked_events[event_name]) {
        return;
    }

    let signature = getElementSignature(that, event_name);
    if (!window.__sec_auto_global_sig_count[signature]) {
        window.__sec_auto_global_sig_count[signature] = 0;
    }

    if (window.__sec_auto_global_sig_count[signature] >= 5) {
        return;
    }

    window.__sec_auto_global_sig_count[signature] += 1;
    that.__sec_auto_marked_events[event_name] = true;

    if (that.hasAttribute("sec_auto_dom2_event_flag")) {
        let sec_auto_dom2_event_flag = that.getAttribute("sec_auto_dom2_event_flag");
        let flags = sec_auto_dom2_event_flag.split("|");
        if (!flags.includes(event_name)) {
            that.setAttribute("sec_auto_dom2_event_flag", sec_auto_dom2_event_flag + "|" + event_name);
        }
    } else {
        that.setAttribute("sec_auto_dom2_event_flag", event_name);
    }
}

// hook dom0 级事件监听 (preserve native getter/setter behavior)
for (const propName in __dom0EventMap) {
    try {
        const nativeDescriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, propName);
        const eventName = __dom0EventMap[propName];
        Object.defineProperty(HTMLElement.prototype, propName, {
            configurable: true,
            enumerable: nativeDescriptor ? nativeDescriptor.enumerable : true,
            get: function() {
                if (nativeDescriptor && nativeDescriptor.get) {
                    return nativeDescriptor.get.call(this);
                }
                return this["__sec_auto_" + propName];
            },
            set: function(newValue) {
                dom0_listener_hook(this, eventName);
                if (nativeDescriptor && nativeDescriptor.set) {
                    nativeDescriptor.set.call(this, newValue);
                } else {
                    this["__sec_auto_" + propName] = newValue;
                }
            }
        });
    } catch(e) {}
}

// hook window.open
window.__originalWindowOpen = window.open;
window.open = function (url) {
    window.__logNavigationUrl(url);
    return null;
}
Object.defineProperty(window,"open",{"writable": false, "configurable": false});

// hook window close
window.close = function() {};
Object.defineProperty(window,"close",{"writable": false, "configurable": false});

// hook setTimeout
//window.__originalSetTimeout = window.setTimeout;
//window.setTimeout = function() {
//    arguments[1] = 0;
//    return window.__originalSetTimeout.apply(this, arguments);
//};
//Object.defineProperty(window,"setTimeout",{"writable": false, "configurable": false});

// hook setInterval 时间设置为2秒 目的是减轻chrome的压力
window.__originalSetInterval = window.setInterval;
window.setInterval = function() {
    arguments[1] = 2000;
    return window.__originalSetInterval.apply(this, arguments);
};
Object.defineProperty(window,"setInterval",{"writable": false, "configurable": false});

// 劫持原生ajax，并对每个请求设置最大请求次数
window.ajax_req_count_sec_auto = {};
XMLHttpRequest.prototype.__originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    // hook code
    this.url = url;
    this.method = method;
    let name = method + url;
    if (!window.ajax_req_count_sec_auto.hasOwnProperty(name)) {
        window.ajax_req_count_sec_auto[name] = 1
    } else {
        window.ajax_req_count_sec_auto[name] += 1
    }
    
    if (window.ajax_req_count_sec_auto[name] <= 10) {
        return this.__originalOpen(method, url, true, user, password);
    }
}
Object.defineProperty(XMLHttpRequest.prototype,"open",{"writable": false, "configurable": false});

XMLHttpRequest.prototype.__originalSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(data) {
    // hook code
    let name = this.method + this.url;
    if (window.ajax_req_count_sec_auto[name] <= 10) {
        return this.__originalSend(data);
    }
}
Object.defineProperty(XMLHttpRequest.prototype,"send",{"writable": false, "configurable": false});

XMLHttpRequest.prototype.__originalAbort = XMLHttpRequest.prototype.abort;
XMLHttpRequest.prototype.abort = function() {
    // hook code
}
Object.defineProperty(XMLHttpRequest.prototype,"abort",{"writable": false, "configurable": false});

// 打乱数组的方法
window.randArr = function (arr) {
    for (var i = 0; i < arr.length; i++) {
        var iRand = parseInt(arr.length * Math.random());
        var temp = arr[i];
        arr[i] = arr[iRand];
        arr[iRand] = temp;
    }
    return arr;
}

window.sleep = function(time) {
    return new Promise((resolve) => setTimeout(resolve, time));
}

window.__isElementVisible = function(node) {
    // 暂时全部返回 true，保留接口
    return true;
};

window.__safeDispatchEvent = function(node, eventName) {
    try {
        if (!node) {
            return;
        }
        let evt = null;
        if (["click", "dblclick", "mousedown", "mouseup", "mousemove", "mouseover", "mouseout"].includes(eventName)) {
            evt = new MouseEvent(eventName, {bubbles: true, cancelable: true, view: window});
        } else if (["focus", "blur", "change", "input", "submit", "select"].includes(eventName)) {
            evt = new Event(eventName, {bubbles: true, cancelable: true});
        } else if (["keydown", "keypress", "keyup"].includes(eventName)) {
            evt = new KeyboardEvent(eventName, {bubbles: true, cancelable: true, key: "Enter"});
        } else {
            evt = new CustomEvent(eventName, {bubbles: true, cancelable: true, detail: null});
        }
        node.dispatchEvent(evt);
    } catch(e) {}
};

window.__rewriteBlankTargets = function(node) {
    try {
        if (!node || typeof node.closest !== "function") {
            return;
        }
        const anchor = node.closest("a[target]");
        if (anchor) {
            const target = (anchor.getAttribute("target") || "").toLowerCase();
            if (target && target !== "_self") {
                anchor.setAttribute("sec_auto_original_target", anchor.getAttribute("target"));
                anchor.setAttribute("target", "_self");
            }
        }
        const form = node.closest("form[target]");
        if (form) {
            const target = (form.getAttribute("target") || "").toLowerCase();
            if (target === "_blank") {
                form.setAttribute("sec_auto_original_target", form.getAttribute("target"));
                form.setAttribute("target", "_self");
            }
        }
    } catch(e) {}
};

window.__safeNodeClick = function(node) {
    try {
        if (!node || (window.__isElementVisible && !window.__isElementVisible(node))) {
            return false;
        }
        // For <a> tags with a real href, only log the URL without clicking.
        // Clicking would trigger SPA router navigation (hash change / pushState),
        // switching the page away and preventing other elements from being triggered.
        // The href is already collected via collect_href_links and the DOM observer.
        if (node.tagName === "A") {
            var href = (node.getAttribute("href") || "").trim();
            if (href && href !== "#" && !href.startsWith("javascript:")) {
                if (window.__logNavigationUrl) {
                    window.__logNavigationUrl(href);
                }
                return true;
            }
        }
        if (window.__rewriteBlankTargets) {
            window.__rewriteBlankTargets(node);
        }
        if (typeof node.focus === "function") {
            try {
                node.focus();
            } catch(e) {}
        }
        window.__safeDispatchEvent(node, "mousedown");
        window.__safeDispatchEvent(node, "mouseup");
        if (typeof node.click === "function") {
            node.click();
            return true;
        }
        window.__safeDispatchEvent(node, "click");
        return true;
    } catch(e) {
        return false;
    }
};

window.__dangerousKeywords = ["logout","log out","log-out","signout","sign out","sign-out","exit","quit","退出","登出","注销"];
window.__isDangerousElement = function(node) {
    if (!node) return false;
    let text = "";
    try {
        text = [
            node.textContent || "",
            node.getAttribute ? (node.getAttribute("aria-label") || "") : "",
            node.getAttribute ? (node.getAttribute("title") || "") : "",
            node.value || "",
        ].join(" ").trim().toLowerCase();
    } catch(e) {}
    if (!text) {
        text = "";
    }
    if (text.length > 200) return false;
    for (let kw of window.__dangerousKeywords) {
        if (text.includes(kw)) return true;
    }
    let href = node.getAttribute && node.getAttribute("href");
    if (href) {
        href = href.toLowerCase();
        for (let kw of window.__dangerousKeywords) {
            if (href.includes(kw)) return true;
        }
    }
    return false;
};
"""

ObserverJS = """
(function init_observer_sec_auto_b() {
    window.dom_listener_func_sec_auto = function (e) {
        let node = e.target;
        let nodeListSrc = node.querySelectorAll("[src]");
        for (let each of nodeListSrc) {
            if (each.src) {
                console.log("getNavigationUrl:" + each.src);
                let attrValue = each.getAttribute("src");
                if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
                    try {
                        eval(attrValue.substring(11));
                    }
                    catch {}
                }
            }
        }

        let nodeListHref = node.querySelectorAll("[href]");
        nodeListHref = window.randArr(nodeListHref);
        for (let each of nodeListHref) {
            if (each.href) {
                console.log("getNavigationUrl:" + each.href);
                let attrValue = each.getAttribute("href");
                if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
                    try {
                        eval(attrValue.substring(11));
                    }
                    catch {}
                }
            }
        }
    };
    document.addEventListener('DOMNodeInserted', window.dom_listener_func_sec_auto, true);
    document.addEventListener('DOMSubtreeModified', window.dom_listener_func_sec_auto, true);
    document.addEventListener('DOMNodeInsertedIntoDocument', window.dom_listener_func_sec_auto, true);
    document.addEventListener('DOMAttrModified', window.dom_listener_func_sec_auto, true);
})()
"""

RemoveDOMListenerJS = """
(function remove_dom_listener() {
    document.removeEventListener('DOMNodeInserted', window.dom_listener_func_sec_auto, true);
    document.removeEventListener('DOMSubtreeModified', window.dom_listener_func_sec_auto, true);
    document.removeEventListener('DOMNodeInsertedIntoDocument', window.dom_listener_func_sec_auto, true);
    document.removeEventListener('DOMAttrModified', window.dom_listener_func_sec_auto, true);
})()
"""

NewFrameTemplate = """
(function sec_auto_new_iframe () {
    let frame = document.createElement("iframe");
    frame.setAttribute("name", "%s");
    frame.setAttribute("id", "%s");
    frame.setAttribute("style", "display: none");
    document.body.appendChild(frame);
})()
"""

FormRawSubmit = """
// migrate from chromedp
(a, rules) => {
    let blacklist = (rules && rules.words) ? rules.words : [];
    let regexList = (rules && rules.regex) ? rules.regex : [];
    let attrs = (rules && rules.attrs) ? rules.attrs : ["id", "class", "name", "action", "formaction", "href", "onclick", "aria-label", "title"];
    function shouldSkip(node) {
        if (!node) {
            return false;
        }
        let hay = "";
        for (let attr of attrs) {
            try {
                let v = node.getAttribute(attr);
                if (v) {
                    hay += " " + v;
                }
            } catch(e) {}
        }
        if (node.textContent) {
            hay += " " + node.textContent;
        }
        hay = hay.toLowerCase();
        for (let kw of blacklist) {
            if (kw && hay.includes(kw)) {
                return true;
            }
        }
        for (let pattern of regexList) {
            try {
                let re = new RegExp(pattern, "i");
                if (re.test(hay)) {
                    return true;
                }
            } catch(e) {}
        }
        return false;
    }
    try {
        if (shouldSkip(a)) {
            return;
        }
        if (a.nodeName === 'FORM') {
            a.submit();
        } else if (a.form !== null) {
            a.form.submit();
        }
    } catch(e) {}
}"""

TriggerInlineEventJS = """
(async function trigger_all_inline_event(){
    let rules = %s;
    let randomize = %s;
    let maxNodes = %s;
    let blacklist = (rules && rules.words) ? rules.words : [];
    let regexList = (rules && rules.regex) ? rules.regex : [];
    let attrs = (rules && rules.attrs) ? rules.attrs : ["id", "class", "name", "href", "action", "onclick", "aria-label", "title"];
    function shouldSkip(node) {
        if (!node) {
            return false;
        }
        let hay = "";
        for (let attr of attrs) {
            try {
                let v = node.getAttribute(attr);
                if (v) {
                    hay += " " + v;
                }
            } catch(e) {}
        }
        if (node.textContent) {
            hay += " " + node.textContent;
        }
        hay = hay.toLowerCase();
        for (let kw of blacklist) {
            if (kw && hay.includes(kw)) {
                return true;
            }
        }
        for (let pattern of regexList) {
            try {
                let re = new RegExp(pattern, "i");
                if (re.test(hay)) {
                    return true;
                }
            } catch(e) {}
        }
        return false;
    }
    let eventNames = ["onabort", "onblur", "onchange", "onclick", "ondblclick", "onerror", "onfocus", "onkeydown", "onkeypress", "onkeyup", "onload", "onmousedown", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onreset", "onresize", "onselect", "onsubmit", "onunload"];
    for (let eventName of eventNames) {
        let event = eventName.replace("on", "");
        let nodeList = Array.from(document.querySelectorAll("[" + eventName + "]"));
        if (randomize) {
            nodeList = window.randArr(nodeList);
        }
        if (maxNodes > 0 && nodeList.length > maxNodes) {
            nodeList = nodeList.slice(0, maxNodes);
        }
        for (let node of nodeList) {
            if (shouldSkip(node)) {
                continue;
            }
            await window.sleep(%s);
            node.setAttribute("sec_auto_inline_event_triggered", "1");
            let evt = document.createEvent('CustomEvent');
            evt.initCustomEvent(event, false, true, null);
            try {
                node.dispatchEvent(evt);
            }
            catch {}
        }
    }
})()
"""

TriggerDom2EventJS = """
(async function trigger_all_dom2_custom_event() {
    let rules = %s;
    let randomize = %s;
    let maxNodes = %s;
    let timeout = 25000;
    let startTime = Date.now();
    let blacklist = (rules && rules.words) ? rules.words : [];
    let regexList = (rules && rules.regex) ? rules.regex : [];
    let attrs = (rules && rules.attrs) ? rules.attrs : ["id", "class", "name", "href", "action", "onclick", "aria-label", "title"];
    function shouldSkip(node) {
        if (!node) {
            return false;
        }
        let hay = "";
        for (let attr of attrs) {
            try {
                let v = node.getAttribute(attr);
                if (v) {
                    hay += " " + v;
                }
            } catch(e) {}
        }
        if (node.textContent) {
            hay += " " + node.textContent;
        }
        hay = hay.toLowerCase();
        for (let kw of blacklist) {
            if (kw && hay.includes(kw)) {
                return true;
            }
        }
        for (let pattern of regexList) {
            try {
                let re = new RegExp(pattern, "i");
                if (re.test(hay)) {
                    return true;
                }
            } catch(e) {}
        }
        return false;
    }
    function transmit_child(node, event, loop) {
        let _loop = loop + 1
        if (_loop > 4) {
            return;
        }
        if (node.nodeType === 1) {
            if (node.hasChildNodes) {
                let children = Array.from(node.children);
                if (randomize) {
                    children = window.randArr(children);
                }
                for (let child of children) {
                    if (child && !shouldSkip(child)) {
                        child.setAttribute("sec_auto_dom2_event_triggered", "1");
                        child.dispatchEvent(event);
                        transmit_child(child, event, _loop);
                    }
                }
            }
        }
    }
    let nodes = Array.from(document.querySelectorAll("[sec_auto_dom2_event_flag]"));
    if (randomize) {
        nodes = window.randArr(nodes);
    }
    if (maxNodes > 0 && nodes.length > maxNodes) {
        nodes = nodes.slice(0, maxNodes);
    }
    let triggered = 0;
    for (let node of nodes) {
        if ((Date.now() - startTime) > timeout) {
            break;
        }
        if (shouldSkip(node)) {
            continue;
        }
        let loop = 0;
        await window.sleep(%s);
        node.setAttribute("sec_auto_dom2_event_triggered", "1");
        let event_name_list = node.getAttribute("sec_auto_dom2_event_flag").split("|");
        let event_name_set = new Set(event_name_list);
        event_name_list = [...event_name_set];
        for (let event_name of event_name_list) {
            let evt = document.createEvent('CustomEvent');
            evt.initCustomEvent(event_name, true, true, null);

            if (event_name == "click" || event_name == "focus" || event_name == "mouseover" || event_name == "select") {
                transmit_child(node, evt, loop);
            }
            if ( (node.className && node.className.includes("close")) || (node.id && node.id.includes("close"))) {
                continue;
            }

            try {
                node.dispatchEvent(evt);
                triggered++;
            } catch(e) {}
        }
    }
    return {triggered: triggered, elapsed: Date.now() - startTime};
})()
"""

TriggerUntriggeredClickableJS = r"""
(async function trigger_untriggered_clickables() {

    function fillInput(inputElement, value) {
        if (!inputElement || inputElement.getAttribute("sec_auto_filled")) return;
        try {
            inputElement.focus && inputElement.focus();

            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
            if (nativeInputValueSetter) {
                nativeInputValueSetter.call(inputElement, value);
            } else {
                inputElement.value = value;
            }

            inputElement.dispatchEvent(new Event('input', { bubbles: true }));
            inputElement.dispatchEvent(new Event('change', { bubbles: true }));
            inputElement.blur && inputElement.blur();

            inputElement.setAttribute("sec_auto_filled", "1");
        } catch (e) { }
    }

    function autoFillVisibleInputs() {
        let inputs = document.querySelectorAll("input:not([type='hidden']):not([type='button']):not([type='submit']):not([type='checkbox']):not([type='radio'])");
        let randStr = Math.floor(Math.random() * 100000).toString();

        for (let input of inputs) {
            if (input.offsetWidth > 0 && input.offsetHeight > 0 && !input.getAttribute("sec_auto_filled")) {
                let type = (input.getAttribute("type") || "").toLowerCase();

                if (type === "password") {
                    fillInput(input, "admin");
                } else {
                    let hint = "";
                    try {
                        hint = (input.placeholder || "") + " " + (input.parentElement ? input.parentElement.textContent : "");
                    } catch(e) {}
                    hint = hint.toLowerCase();
                    if (hint.includes("email")) {
                        fillInput(input, "BACScan@test.com");
                    } else if (hint.includes("title") || hint.includes("content") || hint.includes("nickname")) {
                        fillInput(input, "test_title_" + randStr);
                    } else {
                        let currentVal = input.value || "admin";
                        if (!currentVal.includes("_")) {
                            fillInput(input, currentVal + "_" + randStr);
                        } else {
                            fillInput(input, "admin_" + randStr);
                        }
                    }
                }
            }
        }
    }

    function isDisabled(node) {
        return !!(node && (node.disabled || node.getAttribute("aria-disabled") === "true"));
    }

    function isCloseLike(node) {
        if (!node) return false;
        let className = typeof node.className === "string" ? node.className : (node.getAttribute("class") || "");
        let nodeId = node.id || "";
        return className.toLowerCase().includes("close") || nodeId.toLowerCase().includes("close");
    }

    function isButtonLike(node) {
        if (!node) return false;
        let tag = node.tagName.toLowerCase();
        if (tag === "button") return true;
        if (tag === "input") {
            let inputType = (node.getAttribute("type") || "").toLowerCase();
            if (["button", "submit", "reset", "image"].includes(inputType)) return true;
        }
        let role = (node.getAttribute("role") || "").toLowerCase();
        if (role === "button") return true;
        let className = typeof node.className === "string" ? node.className : (node.getAttribute("class") || "");
        return /(^|\s)(btn|button)([-_\s]|$)/i.test(className);
    }

    function isSectionLike(node) {
        if (!node) return false;
        let className = typeof node.className === "string" ? node.className : (node.getAttribute("class") || "");
        return /(^|\s)section-item([-_\s]|$)/i.test(className);
    }

    function isIgnoredContainer(node) {
        if (!node || node.nodeType !== 1 || typeof node.closest !== "function") return false;

        if (node.closest(".tag-item-container, .tag-text-container, .tag-text, .tag-item")) {
            return true;
        }

        let btnAncestor = node.closest(".btn, button");
        if (btnAncestor && btnAncestor.querySelector(".tip-text")) {
            return true;
        }

        return false;
    }

    function isWhitelisted(node) {
        if (!node) return false;
        let whitelist = ["setting", "edit", "update", "change", "preference", "save"];
        let parentWhitelist = ["shortcut"];
        let hay = "";
        try {
            hay += " " + (node.innerText || node.textContent || "");
            let attrs = ["id", "class", "name", "aria-label", "title", "value"];
            for (let attr of attrs) {
                let v = node.getAttribute(attr);
                if (v) hay += " " + v;
            }
        } catch (e) { }
        hay = hay.toLowerCase();
        for (let kw of whitelist) {
            if (hay.includes(kw)) {
                return true;
            }
        }
        if (node.parentElement && node.parentElement.textContent) {
            let parentHay = node.parentElement.textContent.toLowerCase();
            for (let kw of parentWhitelist) {
                if (parentHay.includes(kw)) {
                    return true;
                }
            }
        }
        return false;
    }

    function keyFor(node) {
        try {
            let text = (node.innerText || node.textContent || "").trim().slice(0, 64);
            let className = typeof node.className === "string" ? node.className : (node.getAttribute("class") || "");
            return (node.tagName || "") + "|" + className + "|" + (node.id || "") + "|" + text;
        } catch (e) {
            return String(Math.random());
        }
    }

    window.__crawlergo_clicked_elements = window.__crawlergo_clicked_elements || new Set();
    window.__crawlergo_sig_count = window.__crawlergo_sig_count || {};
    let maxPerSig = 5;
    function sigFor(node) {
        try {
            let tag = node.tagName || "";
            let className = typeof node.className === "string" ? node.className : (node.getAttribute("class") || "");
            let cls = className.trim().split(/\s+/).filter(Boolean).sort().join(".");
            let text = "";
            for (let child of node.childNodes) {
                if (child.nodeType === 3) text += child.textContent;
            }
            text = text.trim().slice(0, 32);
            return tag + "." + cls + "|" + text;
        } catch(e) { return ""; }
    }

    function isTargetNode(node) {
        if (!node || node.nodeType !== 1) return false;

        if (node.getAttribute("sec_auto_untriggered_triggered") === "1" || node.getAttribute("sec_auto_dom2_event_triggered") === "1") {
            return false;
        }

        if (isDisabled(node) || isCloseLike(node) || isIgnoredContainer(node)) {
            return false;
        }

        let nodeKey = keyFor(node);
        if (window.__crawlergo_clicked_elements.has(nodeKey)) {
            return false;
        }

        if (!isWhitelisted(node)) {
            return false;
        }

        let tag = node.tagName.toLowerCase();
        if (tag === "input") {
            let inputType = (node.getAttribute("type") || "").toLowerCase();
            if (["button", "submit", "reset", "image"].includes(inputType)) {
                return true;
            }
        }
        if (tag === "button") {
            return true;
        }
        if (isButtonLike(node)) {
            return true;
        }
        if (isSectionLike(node)) {
            return true;
        }

        return false;
    }

    function triggerNode(node) {
        if (!node || !node.isConnected) return false;
        try {
            let sig = sigFor(node);
            if (sig) {
                let cnt = window.__crawlergo_sig_count[sig] || 0;
                if (cnt >= maxPerSig) return false;
                window.__crawlergo_sig_count[sig] = cnt + 1;
            }
            window.__crawlergo_clicked_elements.add(keyFor(node));
            node.setAttribute("sec_auto_untriggered_triggered", "1");

            try {
                if (typeof node.click === "function") {
                    node.click();
                } else {
                    node.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, composed: true, view: window }));
                }
            } catch (pageError) {
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    let selector = "button, input, span, div";
    let triggered = 0;
    let maxTrigger = 50;
    let maxRounds = 3;
    let actualRounds = 0;
    let totalButtonCandidates = 0;
    let totalOtherCandidates = 0;

    for (let r = 0; r < maxRounds; r++) {
        actualRounds++;
        let nodeList = Array.from(document.querySelectorAll(selector));
        let buttonNodes = [];
        let otherNodes = [];
        let seen = new Set();

        for (let node of nodeList) {
            if (seen.has(node) || !isTargetNode(node)) {
                continue;
            }
            seen.add(node);
            if (isButtonLike(node)) {
                buttonNodes.push(node);
            } else {
                otherNodes.push(node);
            }
        }

        totalButtonCandidates += buttonNodes.length;
        totalOtherCandidates += otherNodes.length;

        let queue = buttonNodes.concat(otherNodes);

        if (queue.length === 0) {
            break;
        }

        let triggeredInThisRound = 0;
        for (let node of queue) {
            if (triggered >= maxTrigger) {
                break;
            }

            autoFillVisibleInputs();

            if (triggerNode(node)) {
                triggered += 1;
                triggeredInThisRound += 1;
                await window.sleep(%s);
            }
        }

        if (triggered >= maxTrigger || triggeredInThisRound === 0) {
            break;
        }
    }

    return {
        button_candidates: totalButtonCandidates,
        other_candidates: totalOtherCandidates,
        rounds: actualRounds,
        triggered: triggered
    };
})()
"""

TriggerJavascriptProtocol = """
(async function click_all_a_tag_javascript(){
    let nodeListHref = document.querySelectorAll("[href]");
    nodeListHref = window.randArr(nodeListHref);
    for (let node of nodeListHref) {
        let attrValue = node.getAttribute("href");
        if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
            await window.sleep(%s);
            try {
                eval(attrValue.substring(11));
            }
            catch {}
        }
    }
    let nodeListSrc = document.querySelectorAll("[src]");
    nodeListSrc = window.randArr(nodeListSrc);
    for (let node of nodeListSrc) {
        let attrValue = node.getAttribute("src");
        if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
            await window.sleep(%s);
            try {
                eval(attrValue.substring(11));
            }
            catch {}
        }
    }
})()
"""

FormNodeClickJS = """
// migrate from chromedp
(a) => {
    try {
        a.click();
        return true;
    } catch(e) {
        return false;
    }
}"""

SetNodeAttr = "(node, obj) => node.setAttribute(obj.attr, obj.value)"

GetCommentByXpath = """
() => {
    headings = document.evaluate("//comment()",document.body, null, XPathResult.ANY_TYPE, null);
    var thisHeading = headings.iterateNext();
    var commentText = "";
    while (thisHeading) {
        commentText += thisHeading.textContent + "\\n";
        thisHeading = headings.iterateNext();
    }
    return commentText;
}"""

#
# func Snippet(js string, f func(n *cdp.Node) string, sel string, n *cdp.Node, v ...interface{}) string {
#     //return fmt.Sprintf(js, append([]interface{}{sel}, v...)...)
#     return fmt.Sprintf(js, append([]interface{}{f(n)}, v...)...)
# }
#
# func CashX(flatten bool) func(*cdp.Node) string {
#     return func(n *cdp.Node) string {
#         if flatten {
#             return fmt.Sprintf(`$x(%q)[0]`, n.FullXPath())
#         }
#         return fmt.Sprintf(`$x(%q)`, n.FullXPath())
#     }
# }
