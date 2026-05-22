const express = require('express');
const router = express.Router();

const dashboardController = require('../../controllers/dashboard/dashboard.controller');
const checkLogin = require('../../middlewares/checkLogin.middleware');

router.get('/dashboard', checkLogin, dashboardController.showDashboard);
router.get('/dashboard/hardware', checkLogin, dashboardController.hardwareStatus);
router.post('/dashboard/upload', checkLogin, dashboardController.uploadChallenge);
router.get('/dashboard/ai', checkLogin, dashboardController.showAi);
router.get('/dashboard/ai/status', checkLogin, dashboardController.aiStatus);
router.post('/dashboard/ai/run', checkLogin, dashboardController.runPipeline);
router.post('/dashboard/ai/cancel', checkLogin, dashboardController.cancelPipeline);
router.post('/dashboard/ai/dataset', checkLogin, dashboardController.saveDatasetDraft);

module.exports = router;
