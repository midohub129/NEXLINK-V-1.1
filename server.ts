import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { SqliteRelayDatabase } from './server/db/sqliteRelayDb';
import { attachRelayUpgrade, createRelayServer } from './server/relay/relayRouter';

const PORT = Number(process.env.NEXLINK_PORT ?? 3000);
const DB_PATH = process.env.NEXLINK_DB_PATH ?? '.data/nexlink_relay.sqlite';

export async function startServer() {
  const app = express();
  const db = new SqliteRelayDatabase(DB_PATH);
  const relay = createRelayServer(db);

  app.use('/api/relay', relay.router);

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('/{*splat}', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const server = http.createServer(app);
  attachRelayUpgrade(server, relay);

  await new Promise<void>((resolve) => {
    server.listen(PORT, '0.0.0.0', () => resolve());
  });

  const shutdown = async () => {
    await relay.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  };

  process.once('SIGINT', () => {
    void shutdown().finally(() => process.exit(0));
  });
  process.once('SIGTERM', () => {
    void shutdown().finally(() => process.exit(0));
  });

  return { server, db, relay, shutdown };
}

const isEntrypoint =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve('server.ts');

if (isEntrypoint) {
  void startServer();
}
