const express = require('express');
const { verificarToken, verificarRol } = require('../middleware/authMiddleware');
const pool = require('../db/connection');
const router = express.Router();

// ========== OBTENER DEUDAS ACTIVAS ==========
router.get('/activas', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre, u.nombre as registrado_por_nombre
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             LEFT JOIN usuarios u ON c.registrado_por = u.id
             WHERE c.consultorio_id = $1 AND c.estado != 'pagado'
             ORDER BY c.fecha DESC`,
            [req.usuario.consultorioId]
        );
        res.json({ deudas: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener deudas activas' });
    }
});

// ========== OBTENER HISTORIAL DE DEUDAS (ÚLTIMOS 7 DÍAS) ==========
router.get('/historial', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre, u.nombre as registrado_por_nombre
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             LEFT JOIN usuarios u ON c.registrado_por = u.id
             WHERE c.consultorio_id = $1 
               AND c.estado = 'pagado'
               AND c.fecha >= CURRENT_DATE - INTERVAL '7 days'
             ORDER BY c.fecha DESC`,
            [req.usuario.consultorioId]
        );
        res.json({ historial: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

// ========== RESUMEN DE DEUDAS POR PACIENTE ==========
router.get('/resumen', verificarToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.id, p.nombre as paciente_nombre, 
                    COUNT(c.id) as total_deudas,
                    SUM(c.monto) as monto_total,
                    SUM(c.monto_pagado) as monto_pagado,
                    SUM(c.saldo_pendiente) as saldo_total
             FROM pacientes p
             JOIN cobranza c ON p.id = c.paciente_id
             WHERE c.consultorio_id = $1 AND c.estado != 'pagado'
             GROUP BY p.id, p.nombre
             ORDER BY saldo_total DESC`,
            [req.usuario.consultorioId]
        );
        res.json({ resumen: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener resumen' });
    }
});

// ========== OBTENER UNA DEUDA POR ID ==========
router.get('/:id', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM cobranza c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.id = $1 AND c.consultorio_id = $2`,
            [id, req.usuario.consultorioId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }
        
        res.json({ deuda: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener deuda' });
    }
});

// ========== CREAR DEUDA ==========
router.post('/', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { paciente_id, monto, concepto, fecha_limite_pago, notas } = req.body;
        
        if (!paciente_id) {
            return res.status(400).json({ error: 'El paciente es requerido' });
        }
        
        if (!monto || monto <= 0) {
            return res.status(400).json({ error: 'El monto debe ser mayor a 0' });
        }
        
        if (!concepto) {
            return res.status(400).json({ error: 'El concepto es requerido' });
        }
        
        const pacienteCheck = await pool.query(
            `SELECT id FROM pacientes WHERE id = $1 AND consultorio_id = $2`,
            [paciente_id, req.usuario.consultorioId]
        );
        
        if (pacienteCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Paciente no válido' });
        }
        
        const result = await pool.query(
            `INSERT INTO cobranza (consultorio_id, paciente_id, monto, concepto, fecha_limite_pago, notas, registrado_por) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *`,
            [req.usuario.consultorioId, paciente_id, monto, concepto, fecha_limite_pago, notas, req.usuario.id]
        );
        
        res.status(201).json({ message: 'Deuda registrada exitosamente', deuda: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar deuda' });
    }
});

// ========== REGISTRAR ABONO ==========
router.post('/:id/abonar', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;
        const { monto, metodo_pago } = req.body;
        
        if (!monto || monto <= 0) {
            return res.status(400).json({ error: 'Monto a pagar es requerido y debe ser mayor a 0' });
        }
        
        const deudaActual = await pool.query(
            `SELECT * FROM cobranza WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.consultorioId]
        );
        
        if (deudaActual.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }
        
        const deuda = deudaActual.rows[0];
        
        if (parseFloat(monto) > parseFloat(deuda.saldo_pendiente)) {
            return res.status(400).json({ error: 'El monto a pagar no puede superar el saldo pendiente' });
        }
        
        const nuevoPagado = parseFloat(deuda.monto_pagado) + parseFloat(monto);
        const nuevoEstado = nuevoPagado >= parseFloat(deuda.monto) ? 'pagado' : 'parcial';
        
        await pool.query(
            `INSERT INTO pagos (deuda_id, monto, metodo_pago, registrado_por) 
             VALUES ($1, $2, $3, $4)`,
            [id, monto, metodo_pago || 'efectivo', req.usuario.id]
        );
        
        const result = await pool.query(
            `UPDATE cobranza 
             SET monto_pagado = $1, estado = $2 
             WHERE id = $3 
             RETURNING *`,
            [nuevoPagado, nuevoEstado, id]
        );
        
        res.json({ 
            message: 'Abono registrado exitosamente', 
            deuda: result.rows[0],
            abono: { monto, metodo_pago: metodo_pago || 'efectivo', registrado_por: req.usuario.nombre }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar abono' });
    }
});

// ========== EDITAR DEUDA ==========
router.put('/:id/editar', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;
        const { servicios_ids, descuento, monto_personalizado, notas } = req.body;
        
        const deudaActual = await pool.query(
            `SELECT * FROM cobranza WHERE id = $1 AND consultorio_id = $2`,
            [id, req.usuario.consultorioId]
        );
        
        if (deudaActual.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }
        
        const deuda = deudaActual.rows[0];
        const citaId = deuda.cita_id;
        
        if (citaId) {
            await pool.query(`DELETE FROM cita_servicios WHERE cita_id = $1`, [citaId]);
            
            let subtotal = 0;
            for (const item of servicios_ids) {
                await pool.query(
                    `INSERT INTO cita_servicios (cita_id, servicio_id, cantidad, precio_unitario) 
                     VALUES ($1, $2, $3, $4)`,
                    [citaId, item.servicio_id, item.cantidad, item.precio_unitario]
                );
                subtotal += item.cantidad * item.precio_unitario;
            }
            
            let montoFinal;
            if (monto_personalizado !== undefined && monto_personalizado > 0) {
                montoFinal = monto_personalizado;
            } else {
                montoFinal = subtotal - (descuento || 0);
            }
            
            const result = await pool.query(
                `UPDATE cobranza SET monto = $1, notas = $2 WHERE id = $3 RETURNING *`,
                [montoFinal, notas, id]
            );
            
            if (montoFinal < parseFloat(deuda.monto_pagado)) {
                await pool.query(
                    `UPDATE cobranza SET monto_pagado = $1, estado = $2 WHERE id = $3`,
                    [montoFinal, 'pagado', id]
                );
            }
            
            res.json({ message: 'Deuda actualizada exitosamente', deuda: result.rows[0] });
        } else {
            res.status(400).json({ error: 'Esta deuda no está asociada a una cita' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al editar deuda' });
    }
});

// ========== ELIMINAR DEUDA ==========
router.delete('/:id', verificarToken, verificarRol(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await pool.query(
            `DELETE FROM cobranza WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.consultorioId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Deuda no encontrada' });
        }
        
        res.json({ message: 'Deuda eliminada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar deuda' });
    }
});

module.exports = router;