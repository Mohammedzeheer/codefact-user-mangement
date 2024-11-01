const express = require('express');
const { signup, login, refreshToken, getProfile, logout } = require('../controller/userController.js');
const authMiddleware = require('../middleware/authMiddleware.js');
const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/refresh-token', refreshToken);
router.get('/profile', authMiddleware, getProfile);
router.post('/logout', authMiddleware, logout);

module.exports = router;