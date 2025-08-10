async function askForAccessToken(client) {
  return new Promise((resolve) => {
    const responseKey = Math.random().toString(36);
    const listener = (event) => {
      if (event.data.responseKey !== responseKey) return;
      resolve(event.data.token);
      self.removeEventListener("message", listener);
    };
    self.addEventListener("message", listener);
    client.postMessage({ responseKey, type: "token" });
  });
}
function fetchConfig(token) {
  if (!token) return void 0;
  return {
    headers: {
      Authorization: `Bearer ${token}`
    },
    cache: "default"
  };
}
self.addEventListener("activate", (event) => {
  event.waitUntil(clients.claim());
});
self.addEventListener("fetch", (event) => {
  const { url, method } = event.request;
  if (method !== "GET") return;
  if (!url.includes("/_matrix/client/v1/media/download") && !url.includes("/_matrix/client/v1/media/thumbnail")) {
    return;
  }
  event.respondWith(
    (async () => {
      const client = await self.clients.get(event.clientId);
      let token;
      if (client) token = await askForAccessToken(client);
      return fetch(url, fetchConfig(token));
    })()
  );
});
//# sourceMappingURL=sw.js.map
