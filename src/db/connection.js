const { Pool } = require('pg');
require('dotenv').config();

// Configuración para producción (Railway) o desarrollo local
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

module.exports = pool;