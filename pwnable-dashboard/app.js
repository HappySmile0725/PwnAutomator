require('dotenv').config();

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const session = require('express-session');

const indexRouter = require('./routers/index.router');
const dashboardRouter = require('./routers/dashboard/dashboard.router');
const authRouter = require('./routers/auth/auth.router');
const checkLogin = require('./middlewares/checkLogin.middleware');
const { stopManagedMcpRuntime } = require('./services/dashboard/pipeline/mcpRuntime.service');

const app = express();
const HOST = process.env.HOST || '0.0.0.0';
const PORT = process.env.PORT || 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(fileUpload({
  limits: { fileSize: Number(process.env.UPLOAD_LIMIT_BYTES) || 200 * 1024 * 1024 },
  abortOnLimit: true,
  createParentPath: true
}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback_secret_key_12345',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: false,
    httpOnly: true,
  }
}));

app.use('/data/storage/history', checkLogin, express.static(path.join(__dirname, 'data', 'storage', 'history'), { index: false }));

app.use(indexRouter);
app.use(authRouter);
app.use(dashboardRouter);

const server = app.listen(PORT, HOST, () => {
  console.log(`Server is running on http://${HOST}:${PORT}`);
});

server.on('error', (error) => {
  if (error?.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use on ${HOST}.`);
    process.exit(1);
  }
  throw error;
});

let shuttingDown = false;
const shutdown = async (signal) => {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  console.log(`Received ${signal}; stopping dashboard and MCP runtime.`);
  await new Promise((resolve) => server.close(resolve));
  await stopManagedMcpRuntime().catch((error) => {
    console.error(`Failed to stop MCP runtime: ${error.message}`);
  });
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
