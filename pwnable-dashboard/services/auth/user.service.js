const fs = require('fs');
const path = require('path');

const getUsername = async (id) => {
    const dataPath = path.join(__dirname, '..', '..', 'data', 'cred.json');
    const rawData = fs.readFileSync(dataPath, 'utf-8');
    if (!rawData || rawData.trim().length === 0) {
        return null;
    }
    const usersData = JSON.parse(rawData);

    return usersData.filter(user => user.id === id);
};

const writeUser = async (id, hashedPassword) => {
    const dataPath = path.join(__dirname, '..', '..', 'data', 'cred.json');
    let usersData = [];
    if (fs.existsSync(dataPath)) {
        const rawData = fs.readFileSync(dataPath, 'utf-8');
        if (rawData && rawData.trim().length > 0) {
            usersData = JSON.parse(rawData);
        }
    }

    usersData.push({ id, password: hashedPassword });
    fs.writeFileSync(dataPath, JSON.stringify(usersData, null, 2), 'utf-8');
}

module.exports = { getUsername, writeUser };
