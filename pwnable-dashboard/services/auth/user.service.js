const userModel = require('../../models/auth/user.model');

const getUserById = async (id) => {
    const users = await userModel.readUsers();
    return users.find((user) => user.id === id) || null;
};

const addUser = async (id, hashedPassword) => {
    const users = await userModel.readUsers();
    users.push({ id, password: hashedPassword });
    return userModel.writeUsers(users);
};

module.exports = {
    addUser,
    getUserById
};
