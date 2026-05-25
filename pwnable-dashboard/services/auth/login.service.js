const bcrypt = require('bcrypt');
const { getUserById } = require('./user.service');

const login = async (id, password) => {
  const user = await getUserById(id);
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return { success: false, message: 'Invalid password' };
  }

  return { success: true, user };
};
module.exports = login;
