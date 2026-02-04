const express = require('express');
const router = express.Router();

const dashboardService = require('../../services/dashboard/dashboard.service');
const getaiDataService = require('../../services/dashboard/ais/getaiData.service');
const trackService = require('../../services/dashboard/ais/track.service');
const uploadService = require('../../services/dashboard/upload.service');
const runService = require('../../services/dashboard/building/run.service');

router.get('/', async (req, res) => {
    try {
        const dashboardData = await dashboardService.getDashboardData();
        const aiData = await getaiDataService.getAIData();

        if (!dashboardData) {
            throw new Error('Unable to load dashboard data.');
        }

        return res.status(200).render('dashboard/dashboard', {
            title: 'Dashboard',
            dashboard: dashboardData,
            ai: aiData
        });
    } catch (error) {
        console.error('Dashboard Error:', error);
        return res.status(500).render('dashboard/error', {
            title: 'Dashboard Error',
            error: 'Unable to load dashboard data.'
        });
    }
});

router.post('/upload', async (req, res) => {
    try {
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
    } catch (error) {
        console.error('Upload Error:', error);
        return res.status(500).render('dashboard/error', {
            title: 'Upload Error',
            error: 'Internal server error during upload.'
        });
    }
});

router.get('/ai', async (req, res) => {
    try {
        const track = await trackService.getTrackData();
        const getaiData = await getaiDataService.getAIData();

        if (!track) {
            throw new Error('Unable to load AI dashboard data.');
        }

        return res.status(200).render('dashboard/ai', {
            title: 'AI Dashboard',
            ai: track,
            status: getaiData
        });
    } catch (error) {
        console.error('AI Dashboard Error:', error);
        return res.status(500).render('dashboard/error', {
            title: 'AI Dashboard Error',
            error: 'Unable to load AI dashboard data.'
        });
    }
});

router.get('/ai/status', async (req, res) => {
    try {
        const track = await trackService.getTrackData();
        const getaiData = await getaiDataService.getAIData();
        return res.status(200).json({
            ai: track,
            status: getaiData
        });
    } catch (error) {
        console.error('AI Status Error:', error);
        return res.status(500).json({ error: 'Failed to fetch AI status.' });
    }
});

router.post('/ai/run', async (req, res) => {
    try {
        const result = await runService.buildProcess();

        if (result.success) {
            return res.status(200).render('dashboard/ai', {
                title: 'AI Dashboard',
                ai: result.ai,
                status: result.status
            });
        } else {
            return res.status(500).render('dashboard/error', {
                title: 'AI Run Error',
                error: result.error || 'Failed to run AI process.'
            });
        }
    } catch (error) {
        console.error('AI Run Error:', error);
        return res.status(500).render('dashboard/error', {
            title: 'AI Run Error',
            error: 'Internal server error during AI run.'
        });
    }
});

module.exports = router;
