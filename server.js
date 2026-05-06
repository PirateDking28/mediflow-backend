const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

console.log('🔧 Iniciando configuración...');

app.use(cors({ origin: '*' }));
app.use(express.json());

console.log('🔧 Conectando a base de datos...');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
    if (err) {
        console.error('❌ Error conectando a la base de datos:', err);
    } else {
        console.log('✅ Conexión a base de datos exitosa');
    }
});

console.log('🔧 Configurando rutas...');

// Endpoint de prueba
app.get('/api/test', (req, res) => {
    console.log('📡 Petición a /api/test recibida');
    res.json({ mensaje: 'Test exitoso', timestamp: new Date() });
});

app.get('/', (req, res) => {
    res.json({ mensaje: 'Backend funcionando 🚀' });
});

console.log('🔧 Iniciando servidor...');

// ========== ENDPOINT DE REGISTRO ==========
app.post('/api/auth/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;
        
        console.log('📝 Intento de registro:', { nombre, email });
        
        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }
        
        const bcrypt = require('bcrypt');
        const password_hash = await bcrypt.hash(password, 10);
        
        // Verificar si el email ya existe
        const existe = await pool.query('SELECT id FROM consultorios WHERE email = $1', [email]);
        if (existe.rows.length > 0) {
            return res.status(400).json({ exito: false, mensaje: 'El email ya está registrado' });
        }
        
        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, nombre, email`,
            [nombre, email, password_hash, telefono, direccion]
        );
        
        console.log('✅ Registro exitoso:', result.rows[0]);
        res.status(201).json({ exito: true, mensaje: 'Consultorio registrado correctamente', consultorio: result.rows[0] });
    } catch (error) {
        console.error('❌ Error en registro:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== ENDPOINT DE LOGIN ==========
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('🔐 Intento de login:', email);
        
        const result = await pool.query(
            `SELECT * FROM consultorios WHERE email = $1`,
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }
        
        const consultorio = result.rows[0];
        const bcrypt = require('bcrypt');
        const passwordValida = await bcrypt.compare(password, consultorio.password_hash);
        
        if (!passwordValida) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }
        
        const jwt = require('jsonwebtoken');
        const token = jwt.sign(
            { id: consultorio.id, email: consultorio.email, nombre: consultorio.nombre },
            process.env.JWT_SECRET || 'mediFlow_secreto_2026',
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
        console.error('❌ Error en login:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.get('/api/crear-tablas', async (req, res) => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS consultorios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                telefono VARCHAR(50),
                direccion TEXT,
                plan VARCHAR(20) DEFAULT 'basico',
                medicos_max INTEGER DEFAULT 5,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        res.json({ mensaje: 'Tabla consultorios creada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});