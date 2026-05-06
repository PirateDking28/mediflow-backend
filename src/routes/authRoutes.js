const express = require('express');
const { registrar, login } = require('../controllers/authController');
const router = express.Router();

router.post('/registro', registrar);
router.post('/login', login);

module.exports = router;