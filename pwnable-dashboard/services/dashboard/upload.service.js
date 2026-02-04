const fs = require('fs').promises;
const path = require('path');
const { unzipArchive } = require('./building/unzip.service');
const { setRunActive } = require('./ais/runtimeState');

const storageDir = path.join(__dirname, '..', '..', 'data', 'storage', 'now');
const aiDataPath = path.join(__dirname, '..', '..', 'data', 'ai.json');
const targetName = 'chal.zip';

const resetAiData = async () => {
    const payload = {
        status: 'Nothing',
        files: [],
        output: []
    };
    setRunActive(false);
    await fs.writeFile(aiDataPath, JSON.stringify(payload, null, 2));
};

const resolveUploadFile = (req) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return null;
    }
    const uploadedFile = req.files.uploadedFile || req.files.file || Object.values(req.files)[0];
    if (!uploadedFile) {
        return null;
    }
    return Array.isArray(uploadedFile) ? uploadedFile[0] : uploadedFile;
};

const clearExistingArtifacts = async () => {
    try {
        const existingEntries = await fs.readdir(storageDir, { withFileTypes: true });
        const targets = existingEntries.filter((entry) => {
            return entry.isDirectory() || (entry.isFile() && entry.name.toLowerCase().endsWith('.zip'));
        });

        if (targets.length === 0) {
            return;
        }

        for (const entry of targets) {
            await fs.rm(path.join(storageDir, entry.name), { recursive: true, force: true });
        }
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error('Error clearing artifacts:', error);
            throw error;
        }
    }
};

const handleFileUpload = async (req) => {
    try {
        const fileToSave = resolveUploadFile(req);
        if (!fileToSave) {
            return { success: false, error: 'No files were uploaded.' };
        }

        await fs.mkdir(storageDir, { recursive: true });
        await clearExistingArtifacts();

        const uploadPath = path.join(storageDir, targetName);
        await fileToSave.mv(uploadPath);

        const unzipResult = await unzipArchive(uploadPath, storageDir);
        if (!unzipResult.success) {
            return { success: false, error: unzipResult.error || 'Failed to unzip file.' };
        }

        await resetAiData();

        return { success: true };
    } catch (error) {
        console.error('File Upload Error:', error);
        return { success: false, error: 'Internal server error during processing.' };
    }
};

module.exports = { handleFileUpload };
