const express = require('express');
const router = express.Router();

const dashboardService = require('../../services/dashboard/dashboard.service');
const getaiDataService = require('../../services/dashboard/ais/getaiData.service');
const trackService = require('../../services/dashboard/ais/track.service');
const uploadService = require('../../services/dashboard/upload.service');

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

router.post('/upload', async (req, res) => {
    const result = await uploadService.handleFileUpload(req);
    if (result.success) {
        return res.status(200).render('dashboard/ai', {
            title: 'AI Dashboard',
            ai: result.ai,
            status: result.status
        });
    } else {
        return res.status(400).render('dashboard/error', {
            title: 'Upload Error',
            error: result.error || 'File upload failed.'
        });
    }
});

router.get('/ai', async (req, res) => {
    const track = await trackService.getTrackData();
    const getaiData = await getaiDataService.getAIData();

    if (!track) {
        return res.status(500).render('dashboard/error', {
            title: 'AI Dashboard Error',
            error: 'Unable to load AI dashboard data.'
        });
    }

    return res.status(200).render('dashboard/ai', {
        title: 'AI Dashboard',
        ai: track,
        status: getaiData
    });
});

module.exports = router;