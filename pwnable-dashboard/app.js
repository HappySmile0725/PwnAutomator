const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const session = require('express-session');

const indexRouter = require('./routers/index.router');
const dashboardRouter = require('./routers/dashboard/dashboard.router');
const authRouter = require('./routers/auth/auth.router');
const checkLogin = require('./middlewares/checkLogin.middleware');

const app = express();
const dotenv = require('dotenv');
const HOST = '0.0.0.0';
const PORT = 3000;
dotenv.config();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(fileUpload());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET,
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

app.listen(PORT, HOST, () => {
  console.log(`Server is running on http://${HOST}:${PORT}`);
});
