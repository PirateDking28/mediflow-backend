const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middlewares
app.use(cors({
    origin: 'https://mediflow-frontend.vercel.app',
    credentials: true
}));
app.use(express.json());

// Base de datos
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mediflow_db',
    password: 'admin123', // Cambie por su contraseña
    port: 5432,
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

// ========== ENDPOINTS DE AUTENTICACIÓN ==========

// Registro de nuevo consultorio
app.post('/api/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion, ruc } = req.body;
        
        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }
        
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
});

// Login
app.post('/api/login', async (req, res) => {
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
});

// ========== ENDPOINTS DE MÉDICOS ==========

// Obtener médicos del consultorio
app.get('/api/medicos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, nombre, especialidad, email, telefono, activo FROM medicos WHERE consultorio_id = $1',
            [req.usuario.id]
        );
        res.json({ exito: true, medicos: result.rows, max: req.usuario.medicos_max, usados: result.rows.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// Crear médico (validando licencia)
app.post('/api/medicos', verificarToken, async (req, res) => {
    try {
        const { nombre, especialidad, email, telefono } = req.body;
        
        // Verificar cuántos médicos tiene actualmente
        const countResult = await pool.query(
            'SELECT COUNT(*) FROM medicos WHERE consultorio_id = $1',
            [req.usuario.id]
        );
        const medicosActuales = parseInt(countResult.rows[0].count);
        
        if (medicosActuales >= req.usuario.medicos_max) {
            return res.status(400).json({ 
                exito: false, 
                mensaje: `Límite de médicos alcanzado (${req.usuario.medicos_max}). Actualice su plan para agregar más.` 
            });
        }
        
        const result = await pool.query(
            `INSERT INTO medicos (consultorio_id, nombre, especialidad, email, telefono) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, nombre, especialidad, email, telefono, activo`,
            [req.usuario.id, nombre, especialidad, email, telefono]
        );
        
        res.status(201).json({ exito: true, medico: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== ENDPOINTS DE GASTOS (con consultorio_id) ==========

app.get('/api/gastos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM gastos WHERE consultorio_id = $1 ORDER BY fecha DESC',
            [req.usuario.id]
        );
        res.json({ exito: true, gastos: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.post('/api/gastos', verificarToken, async (req, res) => {
    try {
        const { concepto, monto, categoria, descripcion, fecha } = req.body;
        
        if (!concepto || !monto) {
            return res.status(400).json({ exito: false, mensaje: 'Concepto y monto son requeridos' });
        }
        
        const result = await pool.query(
            `INSERT INTO gastos (concepto, monto, categoria, descripcion, fecha, consultorio_id) 
             VALUES ($1, $2, $3, $4, $5, $6) 
             RETURNING *`,
            [concepto, monto, categoria, descripcion, fecha || new Date(), req.usuario.id]
        );
        
        res.status(201).json({ exito: true, gasto: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== ENDPOINTS DE COBRANZA (con medico_id y consultorio_id) ==========

app.get('/api/cobranza', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, m.nombre as medico_nombre 
             FROM cobranza c
             LEFT JOIN medicos m ON c.medico_id = m.id
             WHERE c.consultorio_id = $1 
             ORDER BY c.fecha_consulta DESC`,
            [req.usuario.id]
        );
        res.json({ exito: true, cobranza: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.post('/api/cobranza', verificarToken, async (req, res) => {
    try {
        const { paciente_nombre, concepto, monto, medico_id, telefono, fecha_limite_pago } = req.body;
        
        if (!paciente_nombre || !concepto || !monto) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre, concepto y monto son requeridos' });
        }
        
        const result = await pool.query(
            `INSERT INTO cobranza (paciente_nombre, concepto, monto, medico_id, consultorio_id, telefono, fecha_limite_pago) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *`,
            [paciente_nombre, concepto, monto, medico_id, req.usuario.id, telefono, fecha_limite_pago]
        );
        
        res.status(201).json({ exito: true, registro: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.get('/', (req, res) => {
    res.json({ mensaje: '¡Backend de MediFlow funcionando!' });
});

// ========== MÓDULO DE UTILIDAD ==========
app.get('/api/utilidad', verificarToken, async (req, res) => {
    try {
        const consultorioId = req.usuario.id;
        
        // Total de ingresos (suma de monto_pagado de cobranza)
        const ingresosResult = await pool.query(
            'SELECT COALESCE(SUM(monto_pagado), 0) as total FROM cobranza WHERE consultorio_id = $1',
            [consultorioId]
        );
        
        // Total de gastos
        const gastosResult = await pool.query(
            'SELECT COALESCE(SUM(monto), 0) as total FROM gastos WHERE consultorio_id = $1',
            [consultorioId]
        );
        
        const totalIngresos = parseFloat(ingresosResult.rows[0].total);
        const totalGastos = parseFloat(gastosResult.rows[0].total);
        const utilidad = totalIngresos - totalGastos;
        
        res.json({
            exito: true,
            total_ingresos: totalIngresos,
            total_gastos: totalGastos,
            utilidad_neta: utilidad,
            mensaje: utilidad >= 0 ? 'Ganancia positiva 👍' : 'Pérdida 👎'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== RESUMEN DE PACIENTES CON DEUDA ==========
app.get('/api/cobranza/resumen-pacientes', verificarToken, async (req, res) => {
    try {
        const consultorioId = req.usuario.id;
        
        const result = await pool.query(
            `SELECT 
                paciente_nombre,
                COUNT(*) as total_deudas,
                SUM(monto) as monto_total,
                SUM(monto_pagado) as monto_pagado,
                SUM(saldo_pendiente) as saldo_total
             FROM cobranza 
             WHERE consultorio_id = $1 AND estado != 'pagado'
             GROUP BY paciente_nombre
             ORDER BY saldo_total DESC`,
            [consultorioId]
        );
        
        res.json({ exito: true, pacientes: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.get('/api/cobranza/buscar/:nombre', verificarToken, async (req, res) => {
    try {
        const { nombre } = req.params;
        const consultorioId = req.usuario.id;
        
        const result = await pool.query(
            `SELECT * FROM cobranza 
             WHERE consultorio_id = $1 AND paciente_nombre ILIKE $2 
             ORDER BY fecha_consulta DESC`,
            [consultorioId, `%${nombre}%`]
        );
        
        const totalPendiente = result.rows.reduce((sum, r) => sum + parseFloat(r.saldo_pendiente), 0);
        
        res.json({ 
            exito: true, 
            paciente: nombre,
            total_pendiente: totalPendiente,
            deudas: result.rows 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.put('/api/cobranza/pagar-por-nombre', verificarToken, async (req, res) => {
    try {
        const { paciente_nombre, monto_pagado } = req.body;
        const consultorioId = req.usuario.id;
        
        if (!paciente_nombre || !monto_pagado) {
            return res.status(400).json({ exito: false, mensaje: 'Nombre y monto son requeridos' });
        }
        
        // Obtener deudas pendientes del consultorio
        const deudas = await pool.query(
            `SELECT * FROM cobranza 
             WHERE consultorio_id = $1 AND paciente_nombre ILIKE $2 AND estado != 'pagado' 
             ORDER BY fecha_consulta ASC`,
            [consultorioId, paciente_nombre]
        );
        
        if (deudas.rows.length === 0) {
            return res.status(404).json({ exito: false, mensaje: 'No hay deudas pendientes para este paciente' });
        }
        
        let montoRestante = parseFloat(monto_pagado);
        const actualizados = [];
        
        for (const deuda of deudas.rows) {
            if (montoRestante <= 0) break;
            
            const saldoActual = parseFloat(deuda.saldo_pendiente);
            const abono = Math.min(montoRestante, saldoActual);
            const nuevoPagado = parseFloat(deuda.monto_pagado) + abono;
            const nuevoEstado = nuevoPagado >= parseFloat(deuda.monto) ? 'pagado' : 'parcial';
            
            await pool.query(
                `UPDATE cobranza SET monto_pagado = $1, estado = $2 WHERE id = $3`,
                [nuevoPagado, nuevoEstado, deuda.id]
            );
            
            actualizados.push({ id: deuda.id, abono, saldo_restante: saldoActual - abono });
            montoRestante -= abono;
        }
        
        res.json({ 
            exito: true, 
            mensaje: `Pago registrado para ${paciente_nombre}`,
            monto_aplicado: parseFloat(monto_pagado) - montoRestante,
            monto_sobrante: montoRestante
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// ========== INICIAR SERVIDOR ==========
// Al final del archivo, antes de app.listen, agregar:
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});