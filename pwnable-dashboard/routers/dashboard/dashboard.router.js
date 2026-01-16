const express = require('express');
const router = express.Router();

const dashboardController = require('../../controllers/dashboard/dashboard.controller');
const checklogin = require('../../middlewares/checkLogin.middleware');

router.use('/dashboard', checklogin, dashboardController);

module.exports = router;