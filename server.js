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
        const result = await pool.query(
            `SELECT m.*, u.nombre, u.email, u.activo 
             FROM medicos m
             JOIN usuarios u ON m.usuario_id = u.id
             WHERE u.consultorio_id = $1`,
            [req.usuario.id]
        );
        res.json({ medicos: result.rows });
    } catch (error) {
        console.error(error);
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

app.put('/api/medicos/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, email, especialidad, cedula, telefono, activo } = req.body;

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Actualizar en tabla usuarios
            await client.query(
                `UPDATE usuarios 
                 SET nombre = $1, email = $2, activo = $3
                 WHERE id = (SELECT usuario_id FROM medicos WHERE id = $4)`,
                [nombre, email, activo, id]
            );

            // Actualizar en tabla medicos
            const result = await client.query(
                `UPDATE medicos 
                 SET especialidad = $1, cedula = $2, telefono = $3
                 WHERE id = $4
                 RETURNING *`,
                [especialidad, cedula, telefono, id]
            );

            if (result.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Médico no encontrado' });
            }

            await client.query('COMMIT');
            res.json({ message: 'Médico actualizado exitosamente' });
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/medicos/:id/activar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE usuarios SET activo = true 
             WHERE id = (SELECT usuario_id FROM medicos WHERE id = $1)
             RETURNING id`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Médico no encontrado' });
        }

        res.json({ message: 'Médico activado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/medicos/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE usuarios SET activo = false 
             WHERE id = (SELECT usuario_id FROM medicos WHERE id = $1)
             RETURNING id`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Médico no encontrado' });
        }

        res.json({ message: 'Médico desactivado exitosamente' });
    } catch (error) {
        console.error(error);
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

        const fechaCita = new Date(fecha_hora);
        const ahora = new Date();

        // Crear fechas para comparar solo la fecha (sin hora)
        const hoy = new Date(ahora.getFullYear(), ahora.getMonth(), ahora.getDate());
        const fechaCitaDate = new Date(fechaCita.getFullYear(), fechaCita.getMonth(), fechaCita.getDate());

        // 1. Validar fecha pasada
        if (fechaCitaDate < hoy) {
            return res.status(400).json({ error: 'No se pueden agendar citas en fechas pasadas' });
        }

        // 2. Si es hoy, validar hora (comparar en minutos desde medianoche)
        if (fechaCitaDate.getTime() === hoy.getTime()) {
            const ahoraMinutos = ahora.getHours() * 60 + ahora.getMinutes();
            const citaMinutos = fechaCita.getHours() * 60 + fechaCita.getMinutes();

            // Permitir un margen de 5 minutos para evitar problemas de redondeo
            if (citaMinutos <= ahoraMinutos - 5) {
                return res.status(400).json({ error: 'No se pueden agendar citas en horarios que ya pasaron' });
            }
        }

        // Validar que el médico existe
        const medicoExiste = await pool.query(
            'SELECT id FROM medicos WHERE id = $1 AND consultorio_id = $2',
            [medico_id, req.usuario.id]
        );
        if (medicoExiste.rows.length === 0) {
            return res.status(400).json({ error: 'Médico no válido' });
        }

        // Validar que el paciente existe
        const pacienteExiste = await pool.query(
            'SELECT id FROM pacientes WHERE id = $1 AND consultorio_id = $2',
            [paciente_id, req.usuario.id]
        );
        if (pacienteExiste.rows.length === 0) {
            return res.status(400).json({ error: 'Paciente no válido' });
        }

        // Verificar conflicto de horario
        const conflicto = await pool.query(
            `SELECT id FROM citas 
             WHERE medico_id = $1 
               AND fecha_hora = $2 
               AND estado_cita != 'cancelada'`,
            [medico_id, fecha_hora]
        );
        if (conflicto.rows.length > 0) {
            return res.status(400).json({ error: 'El médico ya tiene una cita en ese horario' });
        }

        // Insertar cita
        const result = await pool.query(
            `INSERT INTO citas (consultorio_id, paciente_id, medico_id, fecha_hora, duracion, notas, estado_cita, registrado_por) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING *`,
            [req.usuario.id, paciente_id, medico_id, fecha_hora, duracion || 30, notas, 'pendiente', req.usuario.id]
        );

        res.status(201).json({ message: 'Cita creada exitosamente', cita: result.rows[0] });
    } catch (error) {
        console.error('❌ Error:', error);
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

app.delete('/api/servicios/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE servicios SET activo = false 
             WHERE id = $1 AND consultorio_id = $2
             RETURNING id`,
            [id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }

        res.json({ message: 'Servicio desactivado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/servicios/:id/activar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE servicios SET activo = true 
             WHERE id = $1 AND consultorio_id = $2
             RETURNING id`,
            [id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }

        res.json({ message: 'Servicio activado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/servicios/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, descripcion, precio, activo } = req.body;

        const result = await pool.query(
            `UPDATE servicios 
             SET nombre = $1, descripcion = $2, precio = $3, activo = $4
             WHERE id = $5 AND consultorio_id = $6
             RETURNING *`,
            [nombre, descripcion, precio, activo, id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }

        res.json({ message: 'Servicio actualizado', servicio: result.rows[0] });
    } catch (error) {
        console.error(error);
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

// ========== ENDPOINT TEMPORAL PARA LIMPIAR BASE DE DATOS ==========
app.get('/api/limpiar-bd', verificarToken, async (req, res) => {
    // Solo admin puede ejecutar esto (verificar que sea admin)
    if (req.usuario.rol !== 'admin') {
        return res.status(403).json({ error: 'No autorizado' });
    }

    try {
        await pool.query('TRUNCATE TABLE pagos CASCADE');
        await pool.query('TRUNCATE TABLE cobranza CASCADE');
        await pool.query('TRUNCATE TABLE cita_servicios CASCADE');
        await pool.query('TRUNCATE TABLE citas CASCADE');
        await pool.query('TRUNCATE TABLE servicios CASCADE');
        await pool.query('TRUNCATE TABLE pacientes CASCADE');
        await pool.query('TRUNCATE TABLE medicos CASCADE');
        await pool.query('TRUNCATE TABLE usuarios CASCADE');
        await pool.query('TRUNCATE TABLE consultorios CASCADE');

        // Reiniciar secuencias
        await pool.query('ALTER SEQUENCE consultorios_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE usuarios_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE medicos_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE pacientes_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE citas_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE servicios_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE cobranza_id_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE pagos_id_seq RESTART WITH 1');

        res.json({ mensaje: 'Base de datos limpiada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/pacientes/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, email, telefono, fecha_nacimiento, direccion, activo } = req.body;

        const result = await pool.query(
            `UPDATE pacientes 
             SET nombre = $1, email = $2, telefono = $3, fecha_nacimiento = $4, direccion = $5, activo = $6
             WHERE id = $7 AND consultorio_id = $8
             RETURNING *`,
            [nombre, email, telefono, fecha_nacimiento, direccion, activo, id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }

        res.json({ message: 'Paciente actualizado', paciente: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/pacientes/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE pacientes SET activo = false WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }

        res.json({ message: 'Paciente desactivado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/pacientes/:id/activar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE pacientes SET activo = true WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }

        res.json({ message: 'Paciente activado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/citas/disponible/:medico_id/:fecha', verificarToken, async (req, res) => {
    try {
        const { medico_id, fecha } = req.params;

        // Generar TODOS los horarios (9:00 a 20:00)
        const horariosBase = [];
        for (let hora = 9; hora <= 19; hora++) {
            horariosBase.push(`${hora.toString().padStart(2, '0')}:00`);
            horariosBase.push(`${hora.toString().padStart(2, '0')}:30`);
        }
        horariosBase.push('20:00');

        // Obtener citas ocupadas del médico en esa fecha
        const inicioDia = new Date(fecha);
        inicioDia.setHours(0, 0, 0, 0);
        const finDia = new Date(fecha);
        finDia.setHours(23, 59, 59, 999);

        const citasOcupadas = await pool.query(
            `SELECT fecha_hora, duracion FROM citas 
             WHERE medico_id = $1 
               AND estado_cita != 'cancelada'
               AND fecha_hora >= $2 
               AND fecha_hora <= $3`,
            [medico_id, inicioDia, finDia]
        );

        // Marcar horarios ocupados
        const horariosOcupados = new Set();
        for (const cita of citasOcupadas.rows) {
            const citaHora = new Date(cita.fecha_hora);
            const duracion = cita.duracion || 30;
            const bloques = duracion / 30;

            for (let i = 0; i < bloques; i++) {
                const horaBloque = new Date(citaHora.getTime() + i * 30 * 60000);
                const horaStr = `${horaBloque.getHours().toString().padStart(2, '0')}:${horaBloque.getMinutes().toString().padStart(2, '0')}`;
                horariosOcupados.add(horaStr);
            }
        }

        // Filtrar solos los ocupados (NO filtrar por hora actual)
        const horariosDisponibles = horariosBase.filter(horario => !horariosOcupados.has(horario));

        res.json({ horarios: horariosDisponibles });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener horarios disponibles' });
    }
});
// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});