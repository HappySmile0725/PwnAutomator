const bcrypt = require('bcrypt');
const { getUsername } = require('../user.service');

const login = async (id, password) => {
  const users = await getUsername(id);
  if (!users || users.length === 0) {
    return { success: false, message: 'User not found' };
  }

  const user = users[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return { success: false, message: 'Invalid password' };
  }

  return { success: true, user };
};


module.exports = login;
