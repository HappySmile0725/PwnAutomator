const userModel = require('../../models/auth/user.model');

const getUsername = async (id) => {
    const users = await userModel.readUsers();
    return users.filter((user) => user.id === id);
};

const writeUser = async (id, hashedPassword) => {
    const users = await userModel.readUsers();
    users.push({ id, password: hashedPassword });
    await userModel.writeUsers(users);
    return true;
};

module.exports = {
    getUsername,
    writeUser
};
