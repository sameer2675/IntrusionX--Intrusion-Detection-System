/*
  Entron/static/Entron/js/live.js

  One shared WebSocket connection to the Channels consumer at
  /ws/dashboard/. Rather than have every page know about the raw
  WebSocket protocol, this dispatches plain browser CustomEvents --
  "entronx:alert" and "entronx:device" -- that each page's own script
  can listen for and use to update whatever it actually renders.

  Include this on every page that should react live (dashboard.html,
  alerts.html, devices.html, etc.) -- ideally from base_app.html once
  that file's structure is known, but for now it's added per-page in
  each template's {% block extra_scripts %}.

  Reconnects automatically with a short backoff if the connection drops
  (e.g. server restart during development).
*/

(function () {
  const RECONNECT_DELAY_MS = 3000;

  function connect() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws/dashboard/`);

    socket.onmessage = function (event) {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (e) {
        return;
      }

      if (data.type === "alert.new") {
        document.dispatchEvent(new CustomEvent("entronx:alert", { detail: data.alert }));
      } else if (data.type === "device.status") {
        document.dispatchEvent(new CustomEvent("entronx:device", { detail: data.device }));
      }
    };

    socket.onclose = function () {
      setTimeout(connect, RECONNECT_DELAY_MS);
    };

    socket.onerror = function () {
      socket.close();
    };
  }

  connect();
})();