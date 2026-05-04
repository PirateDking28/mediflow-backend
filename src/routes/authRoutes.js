const express = require('express');
const { registrar, login } = require('../controllers/authController');
const router = express.Router();
const pool = require('../db/connection');

router.post('/registro', registrar);
router.post('/login', login);

module.exports = router;