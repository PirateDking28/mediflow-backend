const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors({ origin: '*' }));
app.use(express.json());

// ========== CONEXIÓN A BASE DE DATOS ==========
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ========== MIDDLEWARE DE AUTENTICACIÓN ==========
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ exito: false, mensaje: 'Token no proporcionado' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mediFlow_secreto_2026');
        req.usuario = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ exito: false, mensaje: 'Token inválido' });
    }
};

// ========== ENDPOINTS DE AUTENTICACIÓN ==========
app.post('/api/auth/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;
        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Faltan campos' });
        }
        const existe = await pool.query('SELECT id FROM consultorios WHERE email = $1', [email]);
        if (existe.rows.length > 0) {
            return res.status(400).json({ exito: false, mensaje: 'El email ya está registrado' });
        }
        const password_hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id, nombre, email`,
            [nombre, email, password_hash, telefono, direccion]
        );
        res.status(201).json({ exito: true, mensaje: 'Registrado', consultorio: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query(`SELECT * FROM consultorios WHERE email = $1`, [email]);
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
            process.env.JWT_SECRET || 'mediFlow_secreto_2026',
            { expiresIn: '24h' }
        );
        res.json({ exito: true, token, usuario: { id: consultorio.id, nombre: consultorio.nombre, email: consultorio.email, rol: 'admin' } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== ENDPOINTS DE MÉDICOS ==========
app.get('/api/medicos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM medicos WHERE consultorio_id = $1', [req.usuario.id]);
        res.json({ medicos: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/medicos', verificarToken, async (req, res) => {
    try {
        const { nombre, email, password, especialidad, cedula, telefono } = req.body;
        const password_hash = await bcrypt.hash(password, 10);
        const usuarioResult = await pool.query(
            'INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol, activo) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [req.usuario.id, nombre, email, password_hash, 'medico', true]
        );
        await pool.query(
            'INSERT INTO medicos (usuario_id, especialidad, cedula, telefono, consultorio_id) VALUES ($1, $2, $3, $4, $5)',
            [usuarioResult.rows[0].id, especialidad, cedula, telefono, req.usuario.id]
        );
        res.status(201).json({ message: 'Médico creado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== ENDPOINTS DE PACIENTES ==========
app.get('/api/pacientes', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pacientes WHERE consultorio_id = $1', [req.usuario.id]);
        res.json({ pacientes: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/pacientes', verificarToken, async (req, res) => {
    try {
        const { nombre, email, telefono, fecha_nacimiento, direccion } = req.body;
        const result = await pool.query(
            'INSERT INTO pacientes (consultorio_id, nombre, email, telefono, fecha_nacimiento, direccion, activo) VALUES ($1, $2, $3, $4, $5, $6, true) RETURNING *',
            [req.usuario.id, nombre, email, telefono, fecha_nacimiento, direccion]
        );
        res.status(201).json({ message: 'Paciente creado', paciente: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== ENDPOINTS DE CITAS ==========
app.get('/api/citas', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM citas WHERE consultorio_id = $1', [req.usuario.id]);
        res.json({ citas: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/citas', verificarToken, async (req, res) => {
    try {
        const { paciente_id, medico_id, fecha_hora, duracion, notas } = req.body;
        const result = await pool.query(
            'INSERT INTO citas (consultorio_id, paciente_id, medico_id, fecha_hora, duracion, notas, estado_cita, registrado_por) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [req.usuario.id, paciente_id, medico_id, fecha_hora, duracion, notas, 'pendiente', req.usuario.id]
        );
        res.status(201).json({ message: 'Cita creada', cita: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== ENDPOINTS DE SERVICIOS ==========
app.get('/api/servicios', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM servicios WHERE consultorio_id = $1', [req.usuario.id]);
        res.json({ servicios: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/servicios', verificarToken, async (req, res) => {
    try {
        const { nombre, descripcion, precio } = req.body;
        const result = await pool.query(
            'INSERT INTO servicios (consultorio_id, nombre, descripcion, precio, activo) VALUES ($1, $2, $3, $4, true) RETURNING *',
            [req.usuario.id, nombre, descripcion, precio]
        );
        res.status(201).json({ message: 'Servicio creado', servicio: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== ENDPOINTS DE COBRANZA ==========
app.get('/api/cobranza', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM cobranza WHERE consultorio_id = $1', [req.usuario.id]);
        res.json({ deudas: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/cobranza', verificarToken, async (req, res) => {
    try {
        const { paciente_id, cita_id, monto, concepto, notas } = req.body;
        const result = await pool.query(
            'INSERT INTO cobranza (consultorio_id, paciente_id, cita_id, monto, concepto, notas, estado, registrado_por) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [req.usuario.id, paciente_id, cita_id, monto, concepto, notas, 'pendiente', req.usuario.id]
        );
        res.status(201).json({ message: 'Deuda creada', deuda: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cobranza/activas', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM cobranza WHERE consultorio_id = $1 AND estado != $2', [req.usuario.id, 'pagado']);
        res.json({ deudas: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cobranza/historial', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM cobranza 
             WHERE consultorio_id = $1 
               AND estado = $2 
               AND fecha >= CURRENT_DATE - INTERVAL '7 days'`,
            [req.usuario.id, 'pagado']
        );
        res.json({ historial: result.rows });
    } catch (error) {
        console.error('Error en historial:', error);
        res.status(500).json({ error: error.message });
    }
});
// ========== RUTA PRINCIPAL ==========
app.get('/', (req, res) => {
    res.json({ mensaje: 'Backend funcionando 🚀' });
});

app.get('/api/crear-todas-tablas', async (req, res) => {
    try {
        // Tabla consultorios (ya existe, pero por si acaso)
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
        
        // Tabla usuarios
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
        
        // Tabla medicos
        await pool.query(`
            CREATE TABLE IF NOT EXISTS medicos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                consultorio_id INTEGER REFERENCES consultorios(id),
                especialidad VARCHAR(100),
                cedula VARCHAR(50),
                telefono VARCHAR(20)
            )
        `);
        
        // Tabla pacientes
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
        
        // Tabla citas
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
        
        // Tabla servicios
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
        
        // Tabla cita_servicios
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
        
        // Tabla cobranza
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
        
        // Tabla pagos
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
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});