const express = require('express');
const router = express.Router();

const resisterController = require('../../controllers/auth/register.controller');
const loginController = require('../../controllers/auth/login.controller');

router.use('/auth', loginController);
router.use('/auth', resisterController);

module.exports = router;