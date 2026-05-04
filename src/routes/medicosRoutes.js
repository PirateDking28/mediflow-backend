const express = require('express');
const { verificarToken, verificarRol } = require('../middleware/authMiddleware');
const pool = require('../db/connection');
const bcrypt = require('bcrypt');
const router = express.Router();

// ========== OBTENER MÉDICOS DEL CONSULTORIO ==========
router.get('/', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT m.*, u.nombre, u.email, u.activo 
             FROM medicos m 
             JOIN usuarios u ON m.usuario_id = u.id 
             WHERE u.consultorio_id = $1
             ORDER BY u.nombre`,
            [req.usuario.consultorioId]
        );
        res.json({ medicos: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener médicos' });
    }
});

// ========== CREAR MÉDICO (admin y secretaria pueden) ==========
router.post('/', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { nombre, email, password, especialidad, cedula, telefono } = req.body;
        
        // Validaciones básicas
        if (!nombre || !email || !password) {
            return res.status(400).json({ error: 'Nombre, email y contraseña son requeridos' });
        }
        
        // ========== VALIDACIONES DE CAMPOS ÚNICOS ==========
        // 1. Verificar email (activo o inactivo)
        const emailExistente = await pool.query(
            `SELECT u.id FROM usuarios u
             JOIN medicos m ON u.id = m.usuario_id
             WHERE u.email = $1 AND u.consultorio_id = $2`,
            [email, req.usuario.consultorioId]
        );
        
        if (emailExistente.rows.length > 0) {
            return res.status(400).json({ error: 'Ya existe un médico con este email' });
        }
        
        // 2. Verificar cédula profesional (si se proporcionó)
        if (cedula && cedula.trim() !== '') {
            const cedulaExistente = await pool.query(
                `SELECT m.id FROM medicos m
                 JOIN usuarios u ON m.usuario_id = u.id
                 WHERE m.cedula = $1 AND u.consultorio_id = $2`,
                [cedula, req.usuario.consultorioId]
            );
            
            if (cedulaExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Ya existe un médico con esta cédula profesional' });
            }
        }
        // ==================================================
        
        const password_hash = await bcrypt.hash(password, 10);
        
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            const usuarioResult = await client.query(
                'INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol, activo) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [req.usuario.consultorioId, nombre, email, password_hash, 'medico', true]
            );
            
            await client.query(
                'INSERT INTO medicos (usuario_id, especialidad, cedula, telefono) VALUES ($1, $2, $3, $4)',
                [usuarioResult.rows[0].id, especialidad, cedula || null, telefono]
            );
            
            await client.query('COMMIT');
            res.status(201).json({ message: 'Médico creado exitosamente' });
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear médico' });
    }
});

// ========== ACTUALIZAR MÉDICO (solo admin) ==========
router.put('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, email, password, especialidad, cedula, telefono, activo } = req.body;
        
        // Validaciones básicas
        if (!nombre || !email) {
            return res.status(400).json({ error: 'Nombre y email son requeridos' });
        }
        
        // ========== VALIDACIONES DE CAMPOS ÚNICOS (excluyendo el médico actual) ==========
        // 1. Verificar email (excluyendo este médico)
        const emailExistente = await pool.query(
            `SELECT u.id FROM usuarios u
             JOIN medicos m ON u.id = m.usuario_id
             WHERE u.email = $1 AND u.consultorio_id = $2 AND m.id != $3`,
            [email, req.usuario.consultorioId, id]
        );
        
        if (emailExistente.rows.length > 0) {
            return res.status(400).json({ error: 'Ya existe otro médico con este email' });
        }
        
        // 2. Verificar cédula profesional (excluyendo este médico)
        if (cedula && cedula.trim() !== '') {
            const cedulaExistente = await pool.query(
                `SELECT id FROM medicos
                 WHERE cedula = $1 AND id != $2`,
                [cedula, id]
            );
            
            if (cedulaExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Ya existe otro médico con esta cédula profesional' });
            }
        }
        // ==================================================
        
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            // 1. Actualizar en tabla `usuarios`
            let updateUsuarioQuery;
            let updateUsuarioParams;
            
            if (password && password.trim() !== '') {
                // Si se proporcionó nueva contraseña, actualizarla
                const password_hash = await bcrypt.hash(password, 10);
                updateUsuarioQuery = `UPDATE usuarios SET nombre = $1, email = $2, password_hash = $3, activo = $4
                                      WHERE id = (SELECT usuario_id FROM medicos WHERE id = $5) RETURNING *`;
                updateUsuarioParams = [nombre, email, password_hash, activo !== undefined ? activo : true, id];
            } else {
                // Sin cambio de contraseña
                updateUsuarioQuery = `UPDATE usuarios SET nombre = $1, email = $2, activo = $3
                                      WHERE id = (SELECT usuario_id FROM medicos WHERE id = $4) RETURNING *`;
                updateUsuarioParams = [nombre, email, activo !== undefined ? activo : true, id];
            }
            
            const updateUsuario = await client.query(updateUsuarioQuery, updateUsuarioParams);
            
            if (updateUsuario.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Médico no encontrado' });
            }
            
            // 2. Actualizar en tabla `medicos`
            await client.query(
                `UPDATE medicos SET especialidad = $1, cedula = $2, telefono = $3 WHERE id = $4`,
                [especialidad, cedula || null, telefono, id]
            );
            
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
        res.status(500).json({ error: 'Error al actualizar médico' });
    }
});

// ========== DESACTIVAR MÉDICO (solo admin) ==========
router.delete('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
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
        res.status(500).json({ error: 'Error al desactivar médico' });
    }
});

// ========== ACTIVAR MÉDICO (solo admin) ==========
router.put('/:id/activar', verificarToken, verificarRol(['admin']), async (req, res) => {
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
        res.status(500).json({ error: 'Error al activar médico' });
    }
});

module.exports = router;