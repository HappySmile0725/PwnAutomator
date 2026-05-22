const dashboardService = require('../../services/dashboard/dashboard.service');
const hardwareService = require('../../services/dashboard/hardware.service');
const { handleChallengeUpload } = require('../../services/dashboard/pipeline/challengeUpload.service');
const pipelineService = require('../../services/dashboard/pipeline/pipeline.service');

const wantsJson = (req) => {
    const accept = req.get('accept') || '';
    return req.xhr || accept.includes('application/json');
};

const sendError = (req, res, statusCode, title, message) => {
    if (wantsJson(req)) {
        return res.status(statusCode).json({ success: false, error: message });
    }
    return res.status(statusCode).render('dashboard/error', { title, error: message });
};

const renderAi = (res, statusCode = 200) => {
    const pipeline = pipelineService.getPipelineView();
    return res.status(statusCode).render('dashboard/ai', {
        title: 'AI Dashboard',
        ai: pipeline,
        status: pipeline,
        pipeline
    });
};

const sendPipelineResponse = (req, res, result, statusCode = 200) => {
    const pipeline = pipelineService.getPipelineView();
    if (wantsJson(req)) {
        return res.status(statusCode).json({ ...result, pipeline, ai: pipeline, status: pipeline });
    }
    return renderAi(res, statusCode);
};

const showDashboard = async (req, res) => {
    try {
        const dashboardData = await dashboardService.getDashboardData();
        const aiData = await pipelineService.getPipelineStatus();

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
};

const hardwareStatus = async (req, res) => {
    try {
        return res.status(200).json(await hardwareService.getHardwareStatus());
    } catch (error) {
        return res.status(500).json({ error: 'Unable to load hardware status.' });
    }
};

const uploadChallenge = async (req, res) => {
    try {
        const result = await handleChallengeUpload(req);
        if (result.success) {
            return sendPipelineResponse(req, res, result);
        }

        if (wantsJson(req)) {
            return res.status(400).json(result);
        }
        return sendError(req, res, 400, 'Upload Error', result.error || 'File upload failed.');
    } catch (error) {
        console.error('Upload Error:', error);
        return sendError(req, res, 500, 'Upload Error', 'Internal server error during upload.');
    }
};

const showAi = async (req, res) => renderAi(res);

const aiStatus = async (req, res) => {
    try {
        const pipeline = pipelineService.getPipelineView();
        return res.status(200).json({ ai: pipeline, status: pipeline, pipeline });
    } catch (error) {
        console.error('AI Status Error:', error);
        return res.status(500).json({ error: 'Failed to fetch pipeline status.' });
    }
};

const runPipeline = async (req, res) => {
    try {
        const result = await pipelineService.startPipeline();
        return sendPipelineResponse(req, res, result, result.success ? 202 : 400);
    } catch (error) {
        console.error('AI Run Error:', error);
        return sendError(req, res, 500, 'Pipeline Error', 'Internal server error during pipeline run.');
    }
};

const cancelPipeline = async (req, res) => {
    try {
        const result = await pipelineService.cancelActivePipeline();
        return sendPipelineResponse(req, res, result, result.success ? 200 : 400);
    } catch (error) {
        console.error('AI Cancel Error:', error);
        return res.status(500).json({ success: false, error: 'Internal server error during pipeline cancel.' });
    }
};

const saveDatasetPackage = async (req, res) => {
    try {
        const result = await pipelineService.saveCurrentDatasetPackage();
        return sendPipelineResponse(req, res, result, result.success ? 200 : 400);
    } catch (error) {
        console.error('Dataset Save Error:', error);
        return res.status(500).json({ success: false, error: 'Internal server error during dataset save.' });
    }
};

module.exports = {
    aiStatus,
    cancelPipeline,
    hardwareStatus,
    runPipeline,
    saveDatasetPackage,
    showAi,
    showDashboard,
    uploadChallenge
};
