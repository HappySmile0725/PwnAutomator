const AdmZip = require('adm-zip');

const unzipArchive = async (zipPath, destDir) => {
    try {
        const zip = new AdmZip(zipPath);
        zip.extractAllTo(destDir, true);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
};

module.exports = { unzipArchive };
