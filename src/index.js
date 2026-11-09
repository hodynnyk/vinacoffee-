const json = (body, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') {
      if (request.method !== 'GET') return json({ error: 'Метод не підтримується' }, 405);
      // Never claim the database is connected until its binding is configured.
      let database = 'not_configured';
      if (env.DB) {
        try {
          await env.DB.prepare('SELECT 1 AS ok').first();
          database = 'ready';
        } catch {
          database = 'unavailable';
        }
      }
      return json({ status: database === 'unavailable' ? 'degraded' : 'ok', service: 'vinacoffee', database });
    }
    // Production APIs must be authenticated before they can access any records.
    // Until that implementation is complete, fail closed rather than expose demo data.
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      return json({ error: 'Маршрут API недоступний' }, 404);
    }
    return env.ASSETS.fetch(request);
  }
};
