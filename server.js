const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors({ origin: '*' }));
app.use(express.json());

app.get('/api/test-simple', (req, res) => {
    res.json({ mensaje: 'El servidor funciona' });
});

app.get('/api/diagnostico', (req, res) => {
    res.json({
        mensaje: 'Endpoint funciona',
        rutas_registradas: app._router.stack.filter(r => r.route).map(r => r.route.path)
    });
});

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
            return res.status(400).json({ exito: false, mensaje: 'Nombre, email y contraseña son requeridos' });
        }

        // Verificar dominio permitido
        const dominio = email.split('@')[1];
        const dominioValido = await pool.query(
            'SELECT id FROM dominios_permitidos WHERE dominio = $1 AND activo = true',
            [dominio]
        );

        if (dominioValido.rows.length === 0) {
            return res.status(400).json({
                exito: false,
                mensaje: 'Dominio de correo no permitido. Usa: gmail.com, hotmail.com, outlook.com, yahoo.com'
            });
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

        // Crear usuario admin con email_verificado = false
        await pool.query(
            `INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol, activo, token_verificacion, email_verificado) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [result.rows[0].id, nombre, email, password_hash, 'admin', true, tokenVerificacion, false]
        );

        // Enviar email de verificación
        const urlVerificacion = `${process.env.FRONTEND_URL || 'https://mediflow-frontend-tau.vercel.app'}/verificar/${tokenVerificacion}`;

        // await resend.emails.send({
        //     from: EMAIL_FROM,
        //     to: email,
        //     subject: 'Verifica tu cuenta - MediFlow Pro',
        //     html: `<h1>Bienvenido a MediFlow Pro</h1><p>Hola ${nombre},</p><p>Gracias por registrarte. Por favor verifica tu cuenta haciendo clic en el siguiente enlace:</p><a href="${urlVerificacion}">${urlVerificacion}</a><p>Este enlace expirará en 24 horas.</p><p>Saludos,<br>El equipo de MediFlow</p>`
        // });
        console.log('Email de verificación enviado a:', email);
        console.log('Token:', tokenVerificacion);

        res.status(201).json({
            exito: true,
            mensaje: 'Consultorio registrado correctamente. Revisa tu correo para verificar tu cuenta.',
            consultorio: result.rows[0]
        });
    } catch (error) {
        console.error('❌ Error en registro:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Buscar en consultorios (administradores)
        let consultorioResult = await pool.query('SELECT * FROM consultorios WHERE email = $1', [email]);
        let esConsultorio = true;
        let usuarioData = consultorioResult.rows[0];

        // 2. Si no se encuentra en consultorios, buscar en usuarios (médicos, secretarias)
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

        // 3. Validar que el usuario existe
        if (!usuarioData) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        // 4. Validar email verificado (solo para usuarios de la tabla usuarios, no para consultorios)
        if (!esConsultorio && usuarioData.email_verificado === false) {
            return res.status(401).json({
                exito: false,
                mensaje: 'Por favor verifica tu correo electrónico antes de iniciar sesión. Revisa tu bandeja de entrada.'
            });
        }

        // 5. Validar contraseña
        const passwordValida = await bcrypt.compare(password, usuarioData.password_hash);
        if (!passwordValida) {
            return res.status(401).json({ exito: false, mensaje: 'Email o contraseña incorrectos' });
        }

        // 6. Generar payload del token
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

        // 7. Generar token JWT
        const token = jwt.sign(payload, process.env.JWT_SECRET || 'mediFlow_secreto_2026', { expiresIn: '24h' });

        // 8. Respuesta exitosa
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
        res.status(500).json({ exito: false, mensaje: 'Error interno del servidor' });
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

        if (!nombre) {
            return res.status(400).json({ error: 'El nombre es requerido' });
        }

        // ========== VALIDACIONES DE DUPLICADOS ==========
        // 1. Verificar si ya existe un paciente con el mismo email
        if (email) {
            const emailExistente = await pool.query(
                `SELECT id FROM pacientes WHERE email = $1 AND consultorio_id = $2`,
                [email, req.usuario.id]
            );
            if (emailExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Ya existe un paciente con este email' });
            }
        }

        // 2. Verificar si ya existe un paciente con el mismo nombre y email
        const duplicado = await pool.query(
            `SELECT id FROM pacientes 
             WHERE nombre = $1 AND email = $2 AND consultorio_id = $3`,
            [nombre, email || null, req.usuario.id]
        );
        if (duplicado.rows.length > 0) {
            return res.status(400).json({ error: 'Ya existe un paciente con este nombre y email' });
        }
        // ==================================================

        // Validar teléfono
        if (telefono) {
            const telefonoRegex = /^[0-9]{8,15}$/;
            if (!telefonoRegex.test(telefono)) {
                return res.status(400).json({ error: 'El teléfono debe contener solo números (8-15 dígitos)' });
            }
        }

        // Validar fecha de nacimiento (no futura)
        if (fecha_nacimiento) {
            const fechaNac = new Date(fecha_nacimiento);
            const hoy = new Date();
            hoy.setHours(0, 0, 0, 0);
            if (fechaNac > hoy) {
                return res.status(400).json({ error: 'La fecha de nacimiento no puede ser futura' });
            }
        }

        const result = await pool.query(
            `INSERT INTO pacientes (consultorio_id, nombre, email, telefono, fecha_nacimiento, direccion, activo) 
             VALUES ($1, $2, $3, $4, $5, $6, true) 
             RETURNING *`,
            [req.usuario.id, nombre, email, telefono, fecha_nacimiento, direccion]
        );

        res.status(201).json({ message: 'Paciente creado exitosamente', paciente: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ========== ENDPOINTS DE CITAS ==========
app.get('/api/citas', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, 
                    p.nombre as paciente_nombre,
                    u.nombre as medico_nombre
             FROM citas c
             JOIN pacientes p ON c.paciente_id = p.id
             JOIN medicos m ON c.medico_id = m.id
             JOIN usuarios u ON m.usuario_id = u.id
             WHERE c.consultorio_id = $1 AND c.estado_cita = 'pendiente'
             ORDER BY c.fecha_hora ASC`,
            [req.usuario.id]
        );
        res.json({ citas: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/citas', verificarToken, async (req, res) => {
    try {
        const { paciente_id, medico_id, fecha_hora, duracion, notas } = req.body;

        if (!paciente_id || !medico_id || !fecha_hora) {
            return res.status(400).json({ error: 'Paciente, médico y fecha/hora son requeridos' });
        }

        const fechaCita = new Date(fecha_hora);
        const ahora = new Date();

        // Validar que no sea fecha pasada
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);
        const fechaCitaDate = new Date(fechaCita);
        fechaCitaDate.setHours(0, 0, 0, 0);

        if (fechaCitaDate < hoy) {
            return res.status(400).json({ error: 'No se pueden agendar citas en fechas pasadas' });
        }

        // Validar hora pasada solo si es hoy
        if (fechaCitaDate.getTime() === hoy.getTime()) {
            const ahoraMinutos = ahora.getHours() * 60 + ahora.getMinutes();
            const citaMinutos = fechaCita.getHours() * 60 + fechaCita.getMinutes();

            if (citaMinutos <= ahoraMinutos) {
                return res.status(400).json({ error: 'No se pueden agendar citas en horarios que ya pasaron' });
            }
        }

        // Validar médico
        const medicoExiste = await pool.query(
            'SELECT id FROM medicos WHERE id = $1 AND consultorio_id = $2',
            [medico_id, req.usuario.id]
        );
        if (medicoExiste.rows.length === 0) {
            return res.status(400).json({ error: 'Médico no válido' });
        }

        // Validar paciente
        const pacienteExiste = await pool.query(
            'SELECT id FROM pacientes WHERE id = $1 AND consultorio_id = $2',
            [paciente_id, req.usuario.id]
        );
        if (pacienteExiste.rows.length === 0) {
            return res.status(400).json({ error: 'Paciente no válido' });
        }

        // Verificar conflicto de horario con el médico
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

app.delete('/api/citas/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query(
            `UPDATE citas SET estado_cita = 'cancelada' WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.id]
        );
        res.json({ message: 'Cita cancelada' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== ELIMINAR SERVICIO DE CITA ==========
app.delete('/api/citas/:cita_id/servicios/:servicio_cita_id', verificarToken, async (req, res) => {
    try {
        const { cita_id, servicio_cita_id } = req.params;

        // Verificar que la cita existe y pertenece al consultorio
        const cita = await pool.query(
            `SELECT id FROM citas WHERE id = $1 AND consultorio_id = $2`,
            [cita_id, req.usuario.id]
        );
        if (cita.rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        // Eliminar el servicio
        await pool.query(
            `DELETE FROM cita_servicios WHERE id = $1 AND cita_id = $2`,
            [servicio_cita_id, cita_id]
        );

        // Calcular nuevo total de servicios
        const total = await pool.query(
            `SELECT SUM(cantidad * precio_unitario) as total FROM cita_servicios WHERE cita_id = $1`,
            [cita_id]
        );
        const nuevoTotal = total.rows[0].total || 0;

        // Actualizar la deuda si existe
        await pool.query(
            `UPDATE cobranza SET monto = $1 WHERE cita_id = $2`,
            [nuevoTotal, cita_id]
        );

        res.json({ message: 'Servicio eliminado exitosamente', total: nuevoTotal });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ========== COMPLETAR CITA Y GENERAR DEUDA ==========
app.put('/api/citas/:id/completar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Verificar que la cita existe
        const cita = await pool.query(
            `SELECT * FROM citas WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.id]
        );
        if (cita.rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        // 2. Verificar que la cita tenga al menos un servicio
        const servicios = await pool.query(
            `SELECT COUNT(*) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );
        if (parseInt(servicios.rows[0].total) === 0) {
            return res.status(400).json({ error: 'No se puede completar la cita sin servicios' });
        }

        // 3. Calcular el total de los servicios
        const totalServicios = await pool.query(
            `SELECT SUM(cantidad * precio_unitario) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );
        const total = parseFloat(totalServicios.rows[0].total) || 0;

        // 4. Crear la deuda
        const pacienteId = cita.rows[0].paciente_id;
        const resultado = await pool.query(
            `INSERT INTO cobranza (consultorio_id, paciente_id, cita_id, monto, concepto, estado, registrado_por) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *`,
            [req.usuario.id, pacienteId, id, total, `Cita del ${new Date().toLocaleDateString()}`, 'pendiente', req.usuario.id]
        );

        // 5. Actualizar el estado de la cita
        await pool.query(
            `UPDATE citas SET estado_cita = 'completada' WHERE id = $1`,
            [id]
        );

        res.json({
            message: 'Cita completada y deuda generada exitosamente',
            deuda: resultado.rows[0]
        });
    } catch (error) {
        console.error('❌ Error al completar cita:', error);
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

app.get('/api/citas/:id/servicios', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT cs.*, s.nombre as servicio_nombre 
             FROM cita_servicios cs
             JOIN servicios s ON cs.servicio_id = s.id
             WHERE cs.cita_id = $1`,
            [id]
        );
        res.json({ servicios: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/citas/:id/servicios', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { servicio_id, cantidad } = req.body;

        const servicio = await pool.query('SELECT precio FROM servicios WHERE id = $1', [servicio_id]);
        if (servicio.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }

        await pool.query(
            `INSERT INTO cita_servicios (cita_id, servicio_id, cantidad, precio_unitario) 
             VALUES ($1, $2, $3, $4)`,
            [id, servicio_id, cantidad || 1, servicio.rows[0].precio]
        );

        res.status(201).json({ message: 'Servicio agregado' });
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
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.consultorio_id = $1 AND c.estado != 'pagado'
             ORDER BY c.fecha DESC`,
            [req.usuario.id]
        );
        res.json({ deudas: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cobranza/historial', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.consultorio_id = $1 
               AND c.estado = 'pagado'
               AND c.fecha >= CURRENT_DATE - INTERVAL '7 days'
             ORDER BY c.fecha DESC`,
            [req.usuario.id]
        );
        res.json({ historial: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cobranza/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.id = $1 AND c.consultorio_id = $2`,
            [id, req.usuario.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }
        res.json({ deuda: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== REGISTRAR ABONO O DESCUENTO ==========
app.post('/api/cobranza/:id/abonar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { monto, metodo_pago, es_descuento } = req.body;

        if (!monto || monto <= 0) {
            return res.status(400).json({ error: 'El monto debe ser mayor a 0' });
        }

        // Obtener la deuda actual
        const deuda = await pool.query(
            `SELECT * FROM cobranza WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.id]
        );
        if (deuda.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }

        const deudaActual = deuda.rows[0];
        let saldoPendiente = parseFloat(deudaActual.saldo_pendiente);

        // Validar que el monto no sea mayor al saldo pendiente
        if (parseFloat(monto) > saldoPendiente) {
            return res.status(400).json({ error: `El monto no puede ser mayor al saldo pendiente ($${saldoPendiente.toFixed(2)})` });
        }

        let nuevoMonto = parseFloat(deudaActual.monto);
        let nuevoPagado = parseFloat(deudaActual.monto_pagado);

        if (es_descuento) {
            // Descuento: reduce el monto total de la deuda
            nuevoMonto = parseFloat(deudaActual.monto) - parseFloat(monto);
            // El monto_pagado no cambia
        } else {
            // Abono normal: aumenta el monto_pagado
            nuevoPagado = parseFloat(deudaActual.monto_pagado) + parseFloat(monto);
        }

        // Calcular nuevo saldo pendiente
        const nuevoSaldo = nuevoMonto - nuevoPagado;
        const nuevoEstado = nuevoSaldo <= 0 ? 'pagado' : (nuevoPagado > 0 ? 'parcial' : 'pendiente');

        // Actualizar la deuda
        await pool.query(
            `UPDATE cobranza 
             SET monto = $1, monto_pagado = $2, estado = $3 
             WHERE id = $4`,
            [nuevoMonto, nuevoPagado, nuevoEstado, id]
        );

        // Registrar la transacción (pago o descuento)
        const tipo = es_descuento ? 'descuento' : (metodo_pago || 'efectivo');
        await pool.query(
            `INSERT INTO pagos (deuda_id, monto, metodo_pago, registrado_por) 
             VALUES ($1, $2, $3, $4)`,
            [id, monto, tipo, req.usuario.id]
        );

        res.json({
            message: es_descuento ? 'Descuento aplicado exitosamente' : 'Abono registrado exitosamente',
            nuevo_saldo: nuevoSaldo,
            nuevo_estado: nuevoEstado
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ========== EDITAR DEUDA (AGREGAR SERVICIOS) ==========
app.put('/api/cobranza/:id/editar', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nuevos_servicios } = req.body; // Array de { servicio_id, cantidad, precio_unitario }

        // Verificar que la deuda existe
        const deuda = await pool.query(
            `SELECT * FROM cobranza WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.id]
        );
        if (deuda.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }

        let montoAdicional = 0;

        // Insertar los nuevos servicios en cita_servicios
        for (const servicio of nuevos_servicios) {
            await pool.query(
                `INSERT INTO cita_servicios (cita_id, servicio_id, cantidad, precio_unitario) 
                 VALUES ($1, $2, $3, $4)`,
                [deuda.rows[0].cita_id, servicio.servicio_id, servicio.cantidad, servicio.precio_unitario]
            );
            montoAdicional += servicio.cantidad * servicio.precio_unitario;
        }

        // Actualizar el monto de la deuda
        const nuevoMonto = parseFloat(deuda.rows[0].monto) + montoAdicional;
        await pool.query(
            `UPDATE cobranza SET monto = $1 WHERE id = $2`,
            [nuevoMonto, id]
        );

        res.json({
            message: 'Servicios agregados exitosamente',
            nuevo_monto: nuevoMonto,
            monto_agregado: montoAdicional
        });
    } catch (error) {
        console.error(error);
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

// ========== ENDPOINT PARA LIMPIAR BASE DE DATOS ==========
app.get('/api/limpiar-bd', verificarToken, async (req, res) => {
    // Solo admin puede ejecutar esto
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





// ========== DASHBOARD MÉDICO ==========

// Obtener citas del médico para hoy
app.get('/api/medico/citas/hoy', verificarToken, async (req, res) => {
    try {
        // Verificar que el usuario sea médico
        if (req.usuario.rol !== 'medico') {
            return res.status(403).json({ error: 'Acceso no autorizado' });
        }

        // Obtener el ID del médico asociado al usuario
        const medicoResult = await pool.query(
            `SELECT id FROM medicos WHERE usuario_id = $1`,
            [req.usuario.id]
        );

        if (medicoResult.rows.length === 0) {
            return res.status(404).json({ error: 'Médico no encontrado' });
        }

        const medicoId = medicoResult.rows[0].id;

        // Consulta que devuelve la hora como texto directamente desde la BD
        const result = await pool.query(
            `SELECT c.id, 
                    c.fecha_hora,
                    p.nombre as paciente_nombre,
                    p.id as paciente_id,
                    p.telefono as paciente_telefono,
                    TO_CHAR(c.fecha_hora, 'YYYY-MM-DD') as fecha,
                    TO_CHAR(c.fecha_hora, 'HH24:MI') as hora,
                    COALESCE((SELECT COUNT(*) FROM cita_servicios WHERE cita_id = c.id), 0) as tiene_servicios
             FROM citas c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.medico_id = $1
               AND c.estado_cita = 'pendiente'
               AND DATE(c.fecha_hora) = CURRENT_DATE
             ORDER BY c.fecha_hora ASC`,
            [medicoId]
        );

        res.json({ citas: result.rows });
    } catch (error) {
        console.error('Error en /api/medico/citas/hoy:', error);
        res.status(500).json({ error: error.message });
    }
});


// Obtener expediente del paciente
app.get('/api/paciente/:id/expediente', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar que el usuario sea médico
        if (req.usuario.rol !== 'medico') {
            return res.status(403).json({ error: 'Acceso no autorizado' });
        }

        const result = await pool.query(
            `SELECT e.*, u.nombre as medico_nombre
             FROM expedientes e
             LEFT JOIN usuarios u ON e.medico_id = u.id
             WHERE e.paciente_id = $1
             ORDER BY e.fecha DESC, e.created_at DESC`,
            [id]
        );

        const expedienteFormateado = result.rows.map(nota => ({
            id: nota.id,
            fecha: nota.fecha,
            medico_nombre: nota.medico_nombre || 'Sistema',
            contenido: nota.contenido,
            tipo: nota.tipo || 'nota'
        }));

        res.json({ expediente: expedienteFormateado });
    } catch (error) {
        console.error('Error en expediente:', error);
        res.status(500).json({ error: error.message });
    }
});

// Marcar cita como atendida
app.put('/api/citas/:id/atender', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar que el usuario sea médico
        if (req.usuario.rol !== 'medico') {
            return res.status(403).json({ error: 'Acceso no autorizado' });
        }

        // Verificar que la cita tenga servicios
        const servicios = await pool.query(
            `SELECT COUNT(*) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );

        if (parseInt(servicios.rows[0].total) === 0) {
            return res.status(400).json({ error: 'No se puede marcar como atendida sin servicios' });
        }

        await pool.query(
            `UPDATE citas SET estado_cita = 'atendida' WHERE id = $1`,
            [id]
        );

        res.json({ message: 'Cita marcada como atendida' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/paciente/:id/nota', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { nota, cita_id } = req.body;

        // Verificar que el usuario sea médico
        if (req.usuario.rol !== 'medico') {
            return res.status(403).json({ error: 'Acceso no autorizado' });
        }

        const result = await pool.query(
            `INSERT INTO expedientes (consultorio_id, paciente_id, medico_id, cita_id, contenido, tipo) 
             VALUES ($1, $2, $3, $4, $5, 'nota')
             RETURNING *`,
            [req.usuario.consultorioId, id, req.usuario.id, cita_id, nota]
        );

        res.status(201).json({ message: 'Nota guardada', nota: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ========== RECUPERACIÓN DE CONTRASEÑA ==========

// Solicitar recuperación de contraseña
app.post('/api/auth/recuperar', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ exito: false, mensaje: 'El email es requerido' });
        }

        // Buscar usuario en consultorios (admin) o en usuarios (médicos/secretarias)
        let usuario = await pool.query('SELECT id, email FROM consultorios WHERE email = $1', [email]);
        let esConsultorio = true;
        let usuarioData = usuario.rows[0];

        if (!usuarioData) {
            const userResult = await pool.query(
                'SELECT id, email FROM usuarios WHERE email = $1',
                [email]
            );
            usuarioData = userResult.rows[0];
            esConsultorio = false;
        }

        if (!usuarioData) {
            // Por seguridad, no revelamos si el email existe o no
            return res.json({ exito: true, mensaje: 'Si el email está registrado, recibirás un enlace para restablecer tu contraseña.' });
        }

        // Generar token único
        const token = crypto.randomBytes(32).toString('hex');
        const expira = new Date();
        expira.setHours(expira.getHours() + 1); // Token válido por 1 hora

        // Guardar token en la tabla correspondiente
        if (esConsultorio) {
            await pool.query(
                'UPDATE consultorios SET token_recuperacion = $1, token_recuperacion_expira = $2 WHERE id = $3',
                [token, expira, usuarioData.id]
            );
        } else {
            await pool.query(
                'UPDATE usuarios SET token_recuperacion = $1, token_recuperacion_expira = $2 WHERE id = $3',
                [token, expira, usuarioData.id]
            );
        }

        // Enviar email
        const urlRestablecer = `${process.env.FRONTEND_URL || 'https://mediflow-frontend-tau.vercel.app'}/restablecer/${token}`;

        await resend.emails.send({
            from: EMAIL_FROM,
            to: email,
            subject: 'Recupera tu contraseña - MediFlow Pro',
            html: `
                <h1>Recuperación de contraseña</h1>
                <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
                <p>Haz clic en el siguiente enlace para crear una nueva contraseña (válido por 1 hora):</p>
                <a href="${urlRestablecer}">${urlRestablecer}</a>
                <p>Si no solicitaste este cambio, ignora este mensaje.</p>
                <p>Saludos,<br>El equipo de MediFlow</p>
            `
        });

        res.json({ exito: true, mensaje: 'Si el email está registrado, recibirás un enlace para restablecer tu contraseña.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

// Restablecer contraseña
app.post('/api/auth/restablecer/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const { nueva_password } = req.body;

        if (!nueva_password || nueva_password.length < 6) {
            return res.status(400).json({ exito: false, mensaje: 'La contraseña debe tener al menos 6 caracteres' });
        }

        // Buscar en consultorios
        let usuario = await pool.query(
            'SELECT id, email, token_recuperacion_expira FROM consultorios WHERE token_recuperacion = $1',
            [token]
        );
        let esConsultorio = true;
        let usuarioData = usuario.rows[0];

        if (!usuarioData) {
            const userResult = await pool.query(
                'SELECT id, email, token_recuperacion_expira FROM usuarios WHERE token_recuperacion = $1',
                [token]
            );
            usuarioData = userResult.rows[0];
            esConsultorio = false;
        }

        if (!usuarioData) {
            return res.status(400).json({ exito: false, mensaje: 'Token inválido o expirado' });
        }

        // Verificar expiración
        const ahora = new Date();
        if (ahora > usuarioData.token_recuperacion_expira) {
            return res.status(400).json({ exito: false, mensaje: 'El enlace ha expirado. Solicita uno nuevo.' });
        }

        // Hashear nueva contraseña
        const password_hash = await bcrypt.hash(nueva_password, 10);

        // Actualizar contraseña y limpiar token
        if (esConsultorio) {
            await pool.query(
                'UPDATE consultorios SET password_hash = $1, token_recuperacion = NULL, token_recuperacion_expira = NULL WHERE id = $2',
                [password_hash, usuarioData.id]
            );
        } else {
            await pool.query(
                'UPDATE usuarios SET password_hash = $1, token_recuperacion = NULL, token_recuperacion_expira = NULL WHERE id = $2',
                [password_hash, usuarioData.id]
            );
        }

        res.json({ exito: true, mensaje: 'Contraseña actualizada correctamente. Ahora puedes iniciar sesión.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.get('/api/migrar-confirmacion', verificarToken, async (req, res) => {
    try {
        // Solo admin puede ejecutar esto
        if (req.usuario.rol !== 'admin') {
            return res.status(403).json({ error: 'No autorizado' });
        }

        // Agregar columnas a usuarios
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS email_verificado BOOLEAN DEFAULT FALSE`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS token_verificacion VARCHAR(255)`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS token_recuperacion VARCHAR(255)`);
        await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS token_recuperacion_expira TIMESTAMP`);

        // Crear tabla de dominios permitidos
        await pool.query(`
            CREATE TABLE IF NOT EXISTS dominios_permitidos (
                id SERIAL PRIMARY KEY,
                dominio VARCHAR(100) UNIQUE NOT NULL,
                activo BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Insertar dominios básicos
        await pool.query(`
            INSERT INTO dominios_permitidos (dominio) VALUES 
            ('gmail.com'), ('hotmail.com'), ('outlook.com'), ('yahoo.com')
            ON CONFLICT (dominio) DO NOTHING
        `);

        res.json({ mensaje: 'Migración completada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});
