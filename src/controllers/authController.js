const pool = require('../db/connection');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'mediFlow_secreto_2026';

// ========== REGISTRO DE NUEVO CONSULTORIO ==========
const registrar = async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion, ruc } = req.body;

        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }

        // Verificar si el email ya existe
        const existe = await pool.query('SELECT id FROM consultorios WHERE email = $1', [email]);
        if (existe.rows.length > 0) {
            return res.status(400).json({ exito: false, mensaje: 'El email ya está registrado' });
        }

        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion, ruc) 
             VALUES ($1, $2, $3, $4, $5, $6) 
             RETURNING id, nombre, email, plan, medicos_max`,
            [nombre, email, password_hash, telefono, direccion, ruc]
        );

        res.status(201).json({ exito: true, mensaje: 'Consultorio registrado correctamente', consultorio: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
};

// ========== LOGIN ==========
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT id, nombre, email, password_hash, plan, medicos_max, activo FROM consultorios WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        const consultorio = result.rows[0];

        if (!consultorio.activo) {
            return res.status(401).json({ exito: false, mensaje: 'Cuenta desactivada' });
        }

        const passwordValida = await bcrypt.compare(password, consultorio.password_hash);
        if (!passwordValida) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        const token = jwt.sign(
            { id: consultorio.id, email: consultorio.email, nombre: consultorio.nombre, plan: consultorio.plan, medicos_max: consultorio.medicos_max },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            exito: true,
            token,
            consultorio: {
                id: consultorio.id,
                nombre: consultorio.nombre,
                email: consultorio.email,
                plan: consultorio.plan,
                medicos_max: consultorio.medicos_max
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
};

module.exports = { registrar, login };