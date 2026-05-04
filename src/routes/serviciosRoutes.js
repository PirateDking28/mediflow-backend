const express = require('express');
const { verificarToken, verificarRol } = require('../middleware/authMiddleware');
const pool = require('../db/connection');
const router = express.Router();

// ========== OBTENER SERVICIOS ==========
router.get('/', verificarToken, async (req, res) => {
    try {
        // Admin puede ver activos e inactivos, otros roles solo activos
        let query;
        let params;
        
        if (req.usuario.rol === 'admin') {
            query = `SELECT * FROM servicios WHERE consultorio_id = $1 ORDER BY nombre`;
            params = [req.usuario.consultorioId];
        } else {
            query = `SELECT * FROM servicios WHERE consultorio_id = $1 AND activo = true ORDER BY nombre`;
            params = [req.usuario.consultorioId];
        }
        
        const result = await pool.query(query, params);
        res.json({ servicios: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener servicios' });
    }
});

// ========== CREAR SERVICIO (solo admin) ==========
router.post('/', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { nombre, descripcion, precio } = req.body;
        
        if (!nombre || !precio) {
            return res.status(400).json({ error: 'Nombre y precio son requeridos' });
        }
        
        if (precio <= 0) {
            return res.status(400).json({ error: 'El precio debe ser mayor a 0' });
        }
        
        const result = await pool.query(
            `INSERT INTO servicios (consultorio_id, nombre, descripcion, precio) 
             VALUES ($1, $2, $3, $4) 
             RETURNING *`,
            [req.usuario.consultorioId, nombre, descripcion, precio]
        );
        
        res.status(201).json({ message: 'Servicio creado exitosamente', servicio: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear servicio' });
    }
});

// ========== ACTUALIZAR SERVICIO (solo admin) ==========
router.put('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, descripcion, precio, activo } = req.body;
        
        const result = await pool.query(
            `UPDATE servicios 
             SET nombre = $1, descripcion = $2, precio = $3, activo = $4
             WHERE id = $5 AND consultorio_id = $6
             RETURNING *`,
            [nombre, descripcion, precio, activo, id, req.usuario.consultorioId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }
        
        res.json({ message: 'Servicio actualizado', servicio: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar servicio' });
    }
});

// ========== ELIMINAR SERVICIO (solo admin) ==========
router.delete('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await pool.query(
            `DELETE FROM servicios WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.consultorioId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado' });
        }
        
        res.json({ message: 'Servicio eliminado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar servicio' });
    }
});

module.exports = router;