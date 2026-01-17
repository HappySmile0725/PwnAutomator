const express = require('express');
const router = express.Router();

const dashboardService = require('../../services/dashboard/dashboard.service');
const getaiDataService = require('../../services/dashboard/ais/getaiData.service');
// const aiService = require('../../services/dashboard/ais/ai.service');

router.get('/', async (req, res) => {
    const dashboardData = await dashboardService.getDashboardData();
    const aiData = await getaiDataService.getAIData();
    if (!dashboardData) {
        return res.status(500).render('dashboard/error', {
            title: 'Dashboard Error',
            error: 'Unable to load dashboard data.'
        });
    }

    return res.status(200).render('dashboard/dashboard', {
        title: 'Dashboard',
        dashboard: dashboardData,
        ai: aiData
    });
});

router.get('/ai', async (req, res) => {
    const aiData = await aiService.getAIData();

    if (!aiData) {
        return res.status(500).render('dashboard/error', {
            title: 'AI Dashboard Error',
            error: 'Unable to load AI dashboard data.'
        });
    }

    return res.status(200).render('dashboard/ai', {
        title: 'AI Dashboard',
        ai: aiData,
    });
});

router.post('/ai/upload', async (req, res) => {
    const result = await aiService.handleUpload(req);

    if (!result.success) {
        return res.status(400).render('dashboard/error', {
            title: 'AI Upload Error',
            error: result.message || 'Failed to upload AI model.'
        });
    }

    return res.status(200).redirect('/dashboard/ai');
});

module.exports = router;
