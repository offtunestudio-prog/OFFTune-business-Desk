export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/api" || path.startsWith("/api/") || path === "/healthz") {
      return env.BUSINESS_API.fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
};
