const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// ========== CORS MUY PERMISIVO (SOLO PARA PRUEBAS) ==========
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
// ============================================================

app.use(express.json());

// ========== CONEXIÓN A BASE DE DATOS ==========
console.log('=== DEBUG ===');
console.log('DATABASE_URL existe?', process.env.DATABASE_URL ? 'SÍ' : 'NO');
console.log('=============');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

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

// ========== REGISTRO DIRECTO (sin usar authRoutes) ==========
app.post('/api/auth/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;

        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }

        const existe = await pool.query('SELECT id FROM consultorios WHERE email = $1', [email]);
        if (existe.rows.length > 0) {
            return res.status(400).json({ exito: false, mensaje: 'El email ya está registrado' });
        }

        const password_hash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, nombre, email`,
            [nombre, email, password_hash, telefono, direccion]
        );

        // Crear usuario admin
        await pool.query(
            `INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol, activo) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [result.rows[0].id, nombre, email, password_hash, 'admin', true]
        );

        res.status(201).json({ exito: true, mensaje: 'Consultorio registrado correctamente', consultorio: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== LOGIN DIRECTO ==========
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            `SELECT c.* FROM consultorios c WHERE c.email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        const consultorio = result.rows[0];

        const passwordValida = await bcrypt.compare(password, consultorio.password_hash);
        if (!passwordValida) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        const token = jwt.sign(
            { id: consultorio.id, email: consultorio.email, nombre: consultorio.nombre },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            exito: true,
            token,
            usuario: {
                id: consultorio.id,
                nombre: consultorio.nombre,
                email: consultorio.email,
                rol: 'admin'
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== RUTA DE PRUEBA ==========
app.get('/', (req, res) => {
    res.json({ mensaje: '¡Backend de MediFlow funcionando!' });
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});