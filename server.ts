import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // --- API Routes for Resilience Dashboard ---

  // 1. Veeam (Server Backups) Integration
  app.get("/api/resilience/veeam", async (req, res) => {
    try {
      // TODO: Replace with actual Veeam Enterprise Manager REST API call
      // const veeamUrl = process.env.VEEAM_API_URL;
      // const token = process.env.VEEAM_API_TOKEN;
      // const response = await fetch(`${veeamUrl}/api/backupSessions`, { headers: { Authorization: `Bearer ${token}` } });
      // const data = await response.json();
      
      // Simulated response
      const serverBackups = [
        { id: 'SRV-001', name: 'DB-Primary', status: 'Success', lastBackup: new Date(Date.now() - 2 * 3600000).toISOString().replace('T', ' ').substring(0, 16), size: '1.2 TB' },
        { id: 'SRV-002', name: 'App-Server-1', status: 'Success', lastBackup: new Date(Date.now() - 3 * 3600000).toISOString().replace('T', ' ').substring(0, 16), size: '450 GB' },
        { id: 'SRV-003', name: 'App-Server-2', status: 'Failed', lastBackup: new Date(Date.now() - 27 * 3600000).toISOString().replace('T', ' ').substring(0, 16), size: '445 GB' },
        { id: 'SRV-004', name: 'File-Share', status: 'Success', lastBackup: new Date(Date.now() - 4 * 3600000).toISOString().replace('T', ' ').substring(0, 16), size: '2.8 TB' },
        { id: 'SRV-005', name: 'DC-01', status: 'Success', lastBackup: new Date(Date.now() - 1 * 3600000).toISOString().replace('T', ' ').substring(0, 16), size: '120 GB' },
      ];
      res.json(serverBackups);
    } catch (error) {
      console.error("Veeam API Error:", error);
      res.status(500).json({ error: "Failed to fetch Veeam backup data" });
    }
  });

  // 2. Microsoft Graph (OneDrive End User Backups) Integration
  app.get("/api/resilience/onedrive", async (req, res) => {
    try {
      // TODO: Replace with actual Microsoft Graph API call
      // const tenantId = process.env.MS_GRAPH_TENANT_ID;
      // const clientId = process.env.MS_GRAPH_CLIENT_ID;
      // const clientSecret = process.env.MS_GRAPH_CLIENT_SECRET;
      // // Authenticate via MSAL, then fetch:
      // const response = await fetch(`https://graph.microsoft.com/v1.0/reports/getOneDriveUsageStorage(period='D7')`);
      
      // Simulated response
      const endUserBackups = [
        { id: 'USR-001', name: 'Alice Smith', email: 'alice@example.com', status: 'Synced', lastSync: new Date(Date.now() - 15 * 60000).toISOString().replace('T', ' ').substring(0, 16), usage: '45 GB' },
        { id: 'USR-002', name: 'Bob Jones', email: 'bob@example.com', status: 'Synced', lastSync: new Date(Date.now() - 45 * 60000).toISOString().replace('T', ' ').substring(0, 16), usage: '12 GB' },
        { id: 'USR-003', name: 'Charlie Brown', email: 'charlie@example.com', status: 'Error', lastSync: new Date(Date.now() - 2880 * 60000).toISOString().replace('T', ' ').substring(0, 16), usage: '88 GB' },
        { id: 'USR-004', name: 'Diana Prince', email: 'diana@example.com', status: 'Synced', lastSync: new Date(Date.now() - 5 * 60000).toISOString().replace('T', ' ').substring(0, 16), usage: '5 GB' },
        { id: 'USR-005', name: 'Evan Wright', email: 'evan@example.com', status: 'Warning', lastSync: new Date(Date.now() - 1440 * 60000).toISOString().replace('T', ' ').substring(0, 16), usage: '110 GB' },
      ];
      res.json(endUserBackups);
    } catch (error) {
      console.error("OneDrive API Error:", error);
      res.status(500).json({ error: "Failed to fetch OneDrive sync data" });
    }
  });

  // 3. Zerto (Disaster Recovery Replication) Integration
  app.get("/api/resilience/zerto", async (req, res) => {
    try {
      // TODO: Replace with actual Zerto REST API call
      // const zertoUrl = process.env.ZERTO_API_URL;
      // const token = process.env.ZERTO_API_TOKEN;
      // const response = await fetch(`${zertoUrl}/v1/vpgs`, { headers: { Authorization: `Bearer ${token}` } });
      
      // Simulated response
      const drReplication = [
        { id: 'REP-001', source: 'DB-Primary (NYC)', target: 'DB-Standby (LON)', status: 'Healthy', lag: '2s', type: 'Synchronous' },
        { id: 'REP-002', source: 'App-Server-1 (NYC)', target: 'App-Server-1-DR (LON)', status: 'Healthy', lag: '5m', type: 'Asynchronous' },
        { id: 'REP-003', source: 'App-Server-2 (NYC)', target: 'App-Server-2-DR (LON)', status: 'Healthy', lag: '5m', type: 'Asynchronous' },
        { id: 'REP-004', source: 'File-Share (NYC)', target: 'File-Share-DR (LON)', status: 'Lagging', lag: '45m', type: 'Asynchronous' },
      ];
      res.json(drReplication);
    } catch (error) {
      console.error("Zerto API Error:", error);
      res.status(500).json({ error: "Failed to fetch Zerto replication data" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
