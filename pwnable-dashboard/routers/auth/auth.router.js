const express = require('express');
const router = express.Router();

const loginController = require('../../controllers/auth/login.controller');
const registerController = require('../../controllers/auth/register.controller');

router.get('/auth/login', loginController.showLogin);
router.post('/auth/login', loginController.login);
router.post('/auth/logout', loginController.logout);
router.get('/auth/register', registerController.showRegister);
router.post('/auth/register', registerController.register);

module.exports = router;
