const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ========== CONFIGURACIÓN CORS ==========
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json());

// ========== CONEXIÓN A BASE DE DATOS ==========
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'mediFlow_secreto_2026';

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

// ========== ENDPOINTS DE AUTENTICACIÓN ==========

// REGISTRO
app.post('/api/auth/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;
        
        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }
        
        // Verificar si el email ya existe
        const existe = await pool.query('SELECT id FROM consultorios WHERE email = $1', [email]);
        if (existe.rows.length > 0) {
            return res.status(400).json({ exito: false, mensaje: 'El email ya está registrado' });
        }
        
        const password_hash = await bcrypt.hash(password, 10);
        const tokenVerificacion = crypto.randomBytes(32).toString('hex');
        
        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, nombre, email`,
            [nombre, email, password_hash, telefono, direccion]
        );
        
        // Crear usuario admin
        await pool.query(
            `INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol, activo, token_verificacion, email_verificado) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [result.rows[0].id, nombre, email, password_hash, 'admin', true, tokenVerificacion, true]
        );
        
        res.status(201).json({ 
            exito: true, 
            mensaje: 'Consultorio registrado correctamente',
            consultorio: result.rows[0] 
        });
    } catch (error) {
        console.error('❌ Error en registro:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Buscar en consultorios
        let consultorioResult = await pool.query('SELECT * FROM consultorios WHERE email = $1', [email]);
        let esConsultorio = true;
        let usuarioData = consultorioResult.rows[0];
        
        // Si no, buscar en usuarios
        if (!usuarioData) {
            const userResult = await pool.query(`
                SELECT u.*, c.nombre as consultorio_nombre 
                FROM usuarios u
                JOIN consultorios c ON u.consultorio_id = c.id
                WHERE u.email = $1
            `, [email]);
            usuarioData = userResult.rows[0];
            esConsultorio = false;
        }
        
        if (!usuarioData) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }
        
        const passwordValida = await bcrypt.compare(password, usuarioData.password_hash);
        if (!passwordValida) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }
        
        let payload;
        if (esConsultorio) {
            payload = { 
                id: usuarioData.id, 
                email: usuarioData.email, 
                nombre: usuarioData.nombre, 
                rol: 'admin', 
                consultorioId: usuarioData.id 
            };
        } else {
            payload = { 
                id: usuarioData.id, 
                email: usuarioData.email, 
                nombre: usuarioData.nombre, 
                rol: usuarioData.rol, 
                consultorioId: usuarioData.consultorio_id 
            };
        }
        
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({
            exito: true,
            token,
            usuario: {
                id: payload.id,
                nombre: payload.nombre,
                email: payload.email,
                rol: payload.rol,
                consultorio: esConsultorio ? usuarioData.nombre : usuarioData.consultorio_nombre
            }
        });
    } catch (error) {
        console.error('❌ Error en login:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== ENDPOINT DE PRUEBA ==========
app.get('/api/test-simple', (req, res) => {
    res.json({ mensaje: 'El servidor funciona' });
});

// ========== RUTA RAIZ ==========
app.get('/', (req, res) => {
    res.json({ mensaje: 'Backend funcionando 🚀' });
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});