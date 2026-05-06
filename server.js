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

// ========== ENDPOINT TEMPORAL PARA MIGRACIÓN (ELIMINAR DESPUÉS) ==========
app.get('/api/migrar', async (req, res) => {
    try {
        // Crear tabla consultorios
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
        
        // Crear tabla usuarios
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                consultorio_id INTEGER REFERENCES consultorios(id) ON DELETE CASCADE,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                rol VARCHAR(20) NOT NULL CHECK (rol IN ('admin', 'medico', 'secretaria')),
                activo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(consultorio_id, email)
            )
        `);
        
        // Crear tabla medicos
        await pool.query(`
            CREATE TABLE IF NOT EXISTS medicos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                especialidad VARCHAR(100),
                cedula VARCHAR(50),
                telefono VARCHAR(20)
            )
        `);
        
        // Crear tabla pacientes
        await pool.query(`
            CREATE TABLE IF NOT EXISTS pacientes (
                id SERIAL PRIMARY KEY,
                consultorio_id INTEGER REFERENCES consultorios(id) ON DELETE CASCADE,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(100),
                telefono VARCHAR(20),
                fecha_nacimiento DATE,
                direccion TEXT,
                activo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Crear tabla citas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS citas (
                id SERIAL PRIMARY KEY,
                consultorio_id INTEGER REFERENCES consultorios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id),
                medico_id INTEGER REFERENCES medicos(id),
                fecha_hora TIMESTAMP NOT NULL,
                duracion INTEGER DEFAULT 30,
                notas TEXT,
                estado_cita VARCHAR(20) DEFAULT 'pendiente',
                registrado_por INTEGER REFERENCES usuarios(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Crear tabla servicios
        await pool.query(`
            CREATE TABLE IF NOT EXISTS servicios (
                id SERIAL PRIMARY KEY,
                consultorio_id INTEGER REFERENCES consultorios(id) ON DELETE CASCADE,
                nombre VARCHAR(100) NOT NULL,
                descripcion TEXT,
                precio DECIMAL(10,2) NOT NULL,
                activo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Crear tabla cita_servicios
        await pool.query(`
            CREATE TABLE IF NOT EXISTS cita_servicios (
                id SERIAL PRIMARY KEY,
                cita_id INTEGER REFERENCES citas(id) ON DELETE CASCADE,
                servicio_id INTEGER REFERENCES servicios(id),
                cantidad INTEGER DEFAULT 1,
                precio_unitario DECIMAL(10,2) NOT NULL,
                subtotal DECIMAL(10,2) GENERATED ALWAYS AS (cantidad * precio_unitario) STORED,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Crear tabla cobranza
        await pool.query(`
            CREATE TABLE IF NOT EXISTS cobranza (
                id SERIAL PRIMARY KEY,
                consultorio_id INTEGER REFERENCES consultorios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id),
                cita_id INTEGER REFERENCES citas(id),
                monto DECIMAL(10,2) NOT NULL,
                monto_pagado DECIMAL(10,2) DEFAULT 0,
                saldo_pendiente DECIMAL(10,2) GENERATED ALWAYS AS (monto - monto_pagado) STORED,
                concepto VARCHAR(200) NOT NULL,
                fecha DATE DEFAULT CURRENT_DATE,
                estado VARCHAR(20) DEFAULT 'pendiente',
                notas TEXT,
                registrado_por INTEGER REFERENCES usuarios(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Crear tabla pagos
        await pool.query(`
            CREATE TABLE IF NOT EXISTS pagos (
                id SERIAL PRIMARY KEY,
                deuda_id INTEGER REFERENCES cobranza(id) ON DELETE CASCADE,
                monto DECIMAL(10,2) NOT NULL,
                metodo_pago VARCHAR(20) DEFAULT 'efectivo',
                registrado_por INTEGER REFERENCES usuarios(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        res.json({ mensaje: 'Todas las tablas fueron creadas exitosamente' });
    } catch (error) {
        console.error('Error en migración:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});