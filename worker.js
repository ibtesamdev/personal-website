// Password-gates the whole site with HTTP Basic Auth — no Cloudflare
// Access/Zero Trust needed. Username/password come from Worker secrets
// (set via the dashboard or `wrangler secret put`), never hardcoded here.
export default {
  async fetch(request, env) {
    const challenge = () =>
      new Response("Authentication required.", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="personal-website", charset="UTF-8"' },
      });

    if (!env.BASIC_AUTH_USER || !env.BASIC_AUTH_PASS) {
      // Secrets not set yet — fail closed rather than serving the site
      // unprotected.
      return new Response("Site auth is not configured.", { status: 500 });
    }

    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Basic ")) return challenge();

    let user, pass;
    try {
      const decoded = atob(auth.slice(6));
      const sep = decoded.indexOf(":");
      user = decoded.slice(0, sep);
      pass = decoded.slice(sep + 1);
    } catch {
      return challenge();
    }

    if (user !== env.BASIC_AUTH_USER || pass !== env.BASIC_AUTH_PASS) {
      return challenge();
    }

    return env.ASSETS.fetch(request);
  },
};
