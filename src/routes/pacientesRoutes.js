const express = require('express');
const { verificarToken, verificarRol } = require('../middleware/authMiddleware');
const pool = require('../db/connection');
const router = express.Router();

// ========== RUTAS ESPECÍFICAS (texto fijo) - DEBEN IR PRIMERO ==========

// Obtener pacientes con citas sin deuda
router.get('/con-citas-sin-deuda', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT p.id, p.nombre 
             FROM pacientes p
             JOIN citas c ON p.id = c.paciente_id
             WHERE p.consultorio_id = $1 
               AND p.activo = true
               AND c.estado != 'cancelada'
               AND NOT EXISTS (
                   SELECT 1 FROM cobranza WHERE cita_id = c.id
               )
             ORDER BY p.nombre`,
            [req.usuario.consultorioId]
        );
        res.json({ pacientes: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener pacientes' });
    }
});

// ========== RUTAS CON PARÁMETROS DINÁMICOS ==========

// Obtener pacientes
router.get('/', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM pacientes WHERE consultorio_id = $1 ORDER BY nombre ASC`,
            [req.usuario.consultorioId]
        );
        res.json({ pacientes: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener pacientes' });
    }
});

// Actualizar paciente
router.put('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, email, telefono, fecha_nacimiento, direccion, activo } = req.body;
        
        if (!nombre) {
            return res.status(400).json({ error: 'El nombre es requerido' });
        }
        
        if (email) {
            const emailExistente = await pool.query(
                `SELECT id FROM pacientes WHERE email = $1 AND consultorio_id = $2 AND id != $3`,
                [email, req.usuario.consultorioId, id]
            );
            if (emailExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Ya existe otro paciente con este email' });
            }
        }
        
        if (telefono) {
            const telefonoRegex = /^[0-9]{8,15}$/;
            if (!telefonoRegex.test(telefono)) {
                return res.status(400).json({ error: 'El teléfono debe contener solo números (8-15 dígitos)' });
            }
        }
        
        const result = await pool.query(
            `UPDATE pacientes 
             SET nombre = $1, email = $2, telefono = $3, fecha_nacimiento = $4, direccion = $5, activo = $6
             WHERE id = $7 AND consultorio_id = $8
             RETURNING *`,
            [nombre, email, telefono, fecha_nacimiento, direccion, activo, id, req.usuario.consultorioId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }
        
        res.json({ message: 'Paciente actualizado exitosamente', paciente: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar paciente' });
    }
});

// Desactivar paciente
router.delete('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `UPDATE pacientes SET activo = false WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.consultorioId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }
        res.json({ message: 'Paciente desactivado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al desactivar paciente' });
    }
});

// Activar paciente
router.put('/:id/activar', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `UPDATE pacientes SET activo = true WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.consultorioId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Paciente no encontrado' });
        }
        res.json({ message: 'Paciente activado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al activar paciente' });
    }
});

// ========== RUTA POST (al final) ==========

// Crear paciente
router.post('/', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { nombre, email, telefono, fecha_nacimiento, direccion } = req.body;
        
        if (!nombre) {
            return res.status(400).json({ error: 'El nombre es requerido' });
        }
        
        if (email) {
            const emailExistente = await pool.query(
                `SELECT id FROM pacientes WHERE email = $1 AND consultorio_id = $2`,
                [email, req.usuario.consultorioId]
            );
            if (emailExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Ya existe un paciente con este email' });
            }
        }
        
        if (telefono) {
            const telefonoRegex = /^[0-9]{8,15}$/;
            if (!telefonoRegex.test(telefono)) {
                return res.status(400).json({ error: 'El teléfono debe contener solo números (8-15 dígitos)' });
            }
        }
        
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
            [req.usuario.consultorioId, nombre, email, telefono, fecha_nacimiento, direccion]
        );
        
        res.status(201).json({ message: 'Paciente creado exitosamente', paciente: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear paciente' });
    }
});

module.exports = router;