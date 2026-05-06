const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ========== CONFIGURACIÓN CORS COMPLETA ==========
const corsOptions = {
    origin: [
        'https://mediflow-frontend.vercel.app',
        'https://mediflow-frontend-tau.vercel.app',
        'http://localhost:3000',
        'http://localhost:3001'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// ==============================================

app.use(express.json());

// ========== CONEXIÓN A BASE DE DATOS ==========
console.log('=== DEBUG ===');
console.log('DATABASE_URL existe?', process.env.DATABASE_URL ? 'SÍ' : 'NO');
console.log('DATABASE_URL:', process.env.DATABASE_URL ? process.env.DATABASE_URL.substring(0, 50) + '...' : 'No definida');
console.log('=============');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Clave secreta para JWT
const JWT_SECRET = 'mediFlow_secreto_2026';

// ========== MIDDLEWARE DE AUTENTICACIÓN ==========
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ exito: false, mensaje: 'Token no proporcionado' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ exito: false, mensaje: 'Token inválido' });
    }
};

// ========== RUTAS ==========
const authRoutes = require('./src/routes/authRoutes');
const medicosRoutes = require('./src/routes/medicosRoutes');
const pacientesRoutes = require('./src/routes/pacientesRoutes');
const citasRoutes = require('./src/routes/citasRoutes');
const cobranzaRoutes = require('./src/routes/cobranzaRoutes');
const serviciosRoutes = require('./src/routes/serviciosRoutes');

app.use('/api/auth', authRoutes);
app.use('/api/medicos', medicosRoutes);
app.use('/api/pacientes', pacientesRoutes);
app.use('/api/citas', citasRoutes);
app.use('/api/cobranza', cobranzaRoutes);
app.use('/api/servicios', serviciosRoutes);

// ========== RUTA DE PRUEBA ==========
app.get('/', (req, res) => {
    res.json({ mensaje: '¡Backend de MediFlow funcionando!' });
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});