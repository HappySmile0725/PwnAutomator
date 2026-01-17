const fs = require('fs');
const path = require('path');
const { unzipArchive } = require('./building/unzip.service');

const storageDir = path.join(__dirname, '..', '..', 'data', 'storage', 'now');
const targetName = 'chal.zip';

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

const clearExistingArtifacts = () => {
    const existingEntries = fs.readdirSync(storageDir, { withFileTypes: true });
    const targets = existingEntries.filter((entry) => {
        return entry.isDirectory() || (entry.isFile() && entry.name.toLowerCase().endsWith('.zip'));
    });

    if (targets.length === 0) {
        return;
    }

    for (const entry of targets) {
        fs.rmSync(path.join(storageDir, entry.name), { recursive: true, force: true });
    }
};

const handleFileUpload = async (req) => {
    const fileToSave = resolveUploadFile(req);
    if (!fileToSave) {
        return { success: false, error: 'No files were uploaded.' };
    }

    fs.mkdirSync(storageDir, { recursive: true });
    clearExistingArtifacts();

    const uploadPath = path.join(storageDir, targetName);
    await fileToSave.mv(uploadPath);

    const unzipResult = await unzipArchive(uploadPath, storageDir);
    if (!unzipResult.success) {
        return { success: false, error: unzipResult.error || 'Failed to unzip file.' };
    }

    return { success: true };
};

module.exports = { handleFileUpload };
