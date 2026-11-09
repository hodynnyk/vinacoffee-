export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') {
      return Response.json({status: 'ok', service: 'vinacoffee', stage: 'prototype'}, {
        headers: {'cache-control': 'no-store'}
      });
    }
    return env.ASSETS.fetch(request);
  }
};
