const express = require('express');
const { verificarToken, verificarRol } = require('../middleware/authMiddleware');
const pool = require('../db/connection');
const router = express.Router();

// ========== OBTENER CITAS (NO mostrar canceladas) ==========
router.get('/', verificarToken, async (req, res) => {
    try {
        let query;
        let params;

        if (req.usuario.rol === 'medico') {
            query = `
                SELECT c.*, p.nombre as paciente_nombre, p.telefono as paciente_telefono,
                       u.nombre as medico_nombre,
                       COALESCE((SELECT SUM(subtotal) FROM cita_servicios WHERE cita_id = c.id), 0) as total
                FROM citas c
                JOIN pacientes p ON c.paciente_id = p.id
                JOIN medicos m ON c.medico_id = m.id
                JOIN usuarios u ON m.usuario_id = u.id
                WHERE u.id = $1 AND c.consultorio_id = $2 AND c.estado != 'cancelada'
                ORDER BY c.fecha_hora ASC
            `;
            params = [req.usuario.id, req.usuario.consultorioId];
        } else {
            query = `
                SELECT c.*, p.nombre as paciente_nombre, p.telefono as paciente_telefono,
                       u.nombre as medico_nombre,
                       COALESCE((SELECT SUM(subtotal) FROM cita_servicios WHERE cita_id = c.id), 0) as total
                FROM citas c
                JOIN pacientes p ON c.paciente_id = p.id
                JOIN medicos m ON c.medico_id = m.id
                JOIN usuarios u ON m.usuario_id = u.id
                WHERE c.consultorio_id = $1 AND c.estado != 'cancelada'
                ORDER BY c.fecha_hora ASC
            `;
            params = [req.usuario.consultorioId];
        }

        const result = await pool.query(query, params);
        res.json({ citas: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener citas' });
    }
});

// ========== OBTENER HORARIOS DISPONIBLES DE UN MÉDICO ==========
router.get('/disponible/:medico_id/:fecha', verificarToken, async (req, res) => {
    try {
        const { medico_id, fecha } = req.params;
        const fechaSeleccionada = new Date(fecha);

        // Validar médico
        const medicoValido = await pool.query(
            `SELECT m.id FROM medicos m 
             JOIN usuarios u ON m.usuario_id = u.id 
             WHERE m.id = $1 AND u.consultorio_id = $2`,
            [medico_id, req.usuario.consultorioId]
        );

        if (medicoValido.rows.length === 0) {
            return res.status(400).json({ error: 'Médico no válido' });
        }

        // Generar TODOS los horarios desde 9:00 a 20:00
        const todosHorarios = [];
        for (let hora = 9; hora <= 19; hora++) {
            todosHorarios.push(`${hora.toString().padStart(2, '0')}:00`);
            todosHorarios.push(`${hora.toString().padStart(2, '0')}:30`);
        }
        todosHorarios.push('20:00');

        // Obtener citas ocupadas
        const inicioDia = new Date(fechaSeleccionada);
        inicioDia.setHours(0, 0, 0, 0);
        const finDia = new Date(fechaSeleccionada);
        finDia.setHours(23, 59, 59, 999);

        const citasOcupadas = await pool.query(
            `SELECT fecha_hora, duracion FROM citas 
             WHERE medico_id = $1 
               AND estado != 'cancelada'
               AND fecha_hora >= $2 
               AND fecha_hora <= $3`,
            [medico_id, inicioDia, finDia]
        );

        // Calcular horarios ocupados
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

        // Filtrar horarios disponibles
        const ahora = new Date();
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);

        const horariosDisponibles = todosHorarios.filter(horario => {
            if (fechaSeleccionada.toDateString() === hoy.toDateString()) {
                const [hora, minuto] = horario.split(':').map(Number);
                const horarioDate = new Date(fechaSeleccionada);
                horarioDate.setHours(hora, minuto, 0);
                if (horarioDate < ahora) {
                    return false;
                }
            }
            return !horariosOcupados.has(horario);
        });

        res.json({ horarios: horariosDisponibles });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener horarios disponibles' });
    }
});

// ========== CREAR CITA ==========
router.post('/', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { paciente_id, medico_id, fecha, hora, duracion, notas } = req.body;

        if (!paciente_id || !medico_id || !fecha || !hora) {
            return res.status(400).json({ error: 'Paciente, médico, fecha y hora son requeridos' });
        }

        const fechaHoraStr = `${fecha}T${hora}:00`;
        const fechaCita = new Date(fechaHoraStr);
        const ahora = new Date();

        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);

        if (fechaCita < ahora && fechaCita.toDateString() === hoy.toDateString()) {
            return res.status(400).json({ error: 'No se pueden agendar citas en horarios pasados' });
        }

        if (fechaCita < hoy) {
            return res.status(400).json({ error: 'No se pueden agendar citas en fechas pasadas' });
        }

        const medicoCheck = await pool.query(
            `SELECT m.id FROM medicos m 
             JOIN usuarios u ON m.usuario_id = u.id 
             WHERE m.id = $1 AND u.consultorio_id = $2`,
            [medico_id, req.usuario.consultorioId]
        );

        if (medicoCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Médico no válido' });
        }

        const pacienteCheck = await pool.query(
            `SELECT id FROM pacientes WHERE id = $1 AND consultorio_id = $2`,
            [paciente_id, req.usuario.consultorioId]
        );

        if (pacienteCheck.rows.length === 0) {
            return res.status(400).json({ error: 'Paciente no válido' });
        }

        const duracionCita = duracion || 30;
        const fechaFin = new Date(fechaCita.getTime() + duracionCita * 60000);

        // Verificar conflicto con el médico
        const citasDelDia = await pool.query(
            `SELECT id, fecha_hora, duracion FROM citas 
             WHERE medico_id = $1 
               AND estado_cita != 'cancelada'
               AND fecha_hora::date = $2::date`,
            [medico_id, fechaCita]
        );

        let hayConflicto = false;
        for (const cita of citasDelDia.rows) {
            const citaInicio = new Date(cita.fecha_hora);
            const citaFin = new Date(citaInicio.getTime() + cita.duracion * 60000);

            if (fechaCita < citaFin && fechaFin > citaInicio) {
                hayConflicto = true;
                break;
            }
        }

        if (hayConflicto) {
            return res.status(400).json({ error: 'El médico ya tiene una cita en ese horario' });
        }

        // Verificar que el paciente no tenga otra cita el mismo día
        const citasPacienteDia = await pool.query(
            `SELECT id FROM citas 
             WHERE paciente_id = $1 
               AND estado_cita != 'cancelada'
               AND fecha_hora::date = $2::date`,
            [paciente_id, fechaCita]
        );

        if (citasPacienteDia.rows.length > 0) {
            return res.status(400).json({ error: 'El paciente ya tiene una cita en este día' });
        }

        const result = await pool.query(
            `INSERT INTO citas (consultorio_id, paciente_id, medico_id, fecha_hora, duracion, notas, registrado_por, estado_cita) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING *`,
            [req.usuario.consultorioId, paciente_id, medico_id, fechaCita, duracionCita, notas, req.usuario.id, 'pendiente']
        );

        res.status(201).json({ message: 'Cita creada exitosamente', cita: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear cita' });
    }
});

// ========== CANCELAR CITA ==========
router.delete('/:id', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE citas SET estado_cita = 'cancelada' WHERE id = $1 AND consultorio_id = $2 RETURNING id`,
            [id, req.usuario.consultorioId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        res.json({ message: 'Cita cancelada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al cancelar cita' });
    }
});

// ========== MARCAR CITA COMO COMPLETADA (GENERA DEUDA) ==========
router.put('/:id/completar', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;

        // Obtener información de la cita
        const citaResult = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM citas c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.id = $1 AND c.consultorio_id = $2`,
            [id, req.usuario.consultorioId]
        );

        if (citaResult.rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        const cita = citaResult.rows[0];

        // Verificar si ya tiene deuda
        const deudaExistente = await pool.query(
            `SELECT id FROM cobranza WHERE cita_id = $1`,
            [id]
        );

        if (deudaExistente.rows.length > 0) {
            return res.status(400).json({ error: 'Esta cita ya tiene una deuda generada' });
        }

        // Verificar que la cita tiene al menos un servicio
        const serviciosResult = await pool.query(
            `SELECT COUNT(*) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );

        if (parseInt(serviciosResult.rows[0].total) === 0) {
            return res.status(400).json({ error: 'No se puede completar la cita sin servicios. Agregue al menos un servicio.' });
        }

        // Obtener servicios de la cita para calcular el total
        const serviciosDetalle = await pool.query(
            `SELECT cs.cantidad, cs.precio_unitario 
             FROM cita_servicios cs
             WHERE cs.cita_id = $1`,
            [id]
        );

        // Calcular total
        let total = 0;
        let concepto = '';

        if (serviciosDetalle.rows.length > 0) {
            total = serviciosDetalle.rows.reduce((sum, s) => sum + (s.cantidad * s.precio_unitario), 0);
            concepto = `Cita del ${new Date(cita.fecha_hora).toLocaleDateString()}: Servicios médicos`;
        } else {
            concepto = `Cita del ${new Date(cita.fecha_hora).toLocaleDateString()}`;
        }

        // Si es cortesía, monto = 0
        const esCortesia = cita.es_cortesia || false;
        const monto = esCortesia ? 0 : total;
        const estado = esCortesia ? 'pagado' : 'pendiente';

        // Crear la deuda
        const result = await pool.query(
            `INSERT INTO cobranza (consultorio_id, paciente_id, cita_id, monto, concepto, estado, registrado_por) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *`,
            [req.usuario.consultorioId, cita.paciente_id, id, monto, concepto, estado, req.usuario.id]
        );

        // Actualizar estado de la cita
        await pool.query(
            `UPDATE citas SET estado_cita = 'completada' WHERE id = $1`,
            [id]
        );

        res.status(201).json({ message: 'Cita completada y deuda generada', deuda: result.rows[0] });
    } catch (error) {
        console.error('Error en completar cita:', error);
        res.status(500).json({ error: 'Error al completar cita' });
    }
});

// ========== OBTENER SERVICIOS DE UNA CITA ==========
router.get('/:id/servicios', verificarToken, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `SELECT cs.*, s.nombre as servicio_nombre, s.descripcion 
             FROM cita_servicios cs
             JOIN servicios s ON cs.servicio_id = s.id
             WHERE cs.cita_id = $1`,
            [id]
        );

        res.json({ servicios: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener servicios de la cita' });
    }
});

// ========== AGREGAR SERVICIO A UNA CITA ==========
router.post('/:id/servicios', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;
        const { servicio_id, cantidad } = req.body;

        const servicioResult = await pool.query(
            `SELECT nombre, precio FROM servicios WHERE id = $1 AND consultorio_id = $2 AND activo = true`,
            [servicio_id, req.usuario.consultorioId]
        );

        if (servicioResult.rows.length === 0) {
            return res.status(400).json({ error: 'Servicio no encontrado o inactivo' });
        }

        const servicio = servicioResult.rows[0];
        const cantidadFinal = cantidad || 1;

        await pool.query(
            `INSERT INTO cita_servicios (cita_id, servicio_id, cantidad, precio_unitario) 
             VALUES ($1, $2, $3, $4)`,
            [id, servicio_id, cantidadFinal, servicio.precio]
        );

        // Actualizar el total de la cita en cobranza (si existe deuda)
        const totalResult = await pool.query(
            `SELECT SUM(subtotal) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );

        const nuevoTotal = totalResult.rows[0].total || 0;

        // Si ya existe deuda, actualizar el monto
        await pool.query(
            `UPDATE cobranza SET monto = $1 WHERE cita_id = $2`,
            [nuevoTotal, id]
        );

        res.status(201).json({ message: 'Servicio agregado a la cita', total: nuevoTotal });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al agregar servicio' });
    }
});

// ========== ELIMINAR SERVICIO DE UNA CITA ==========
router.delete('/:id/servicios/:servicio_cita_id', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id, servicio_cita_id } = req.params;

        await pool.query(`DELETE FROM cita_servicios WHERE id = $1 AND cita_id = $2`, [servicio_cita_id, id]);

        // Actualizar el total de la cita en cobranza (si existe deuda)
        const totalResult = await pool.query(
            `SELECT SUM(subtotal) as total FROM cita_servicios WHERE cita_id = $1`,
            [id]
        );

        const nuevoTotal = totalResult.rows[0].total || 0;

        // Si ya existe deuda, actualizar el monto
        await pool.query(
            `UPDATE cobranza SET monto = $1 WHERE cita_id = $2`,
            [nuevoTotal, id]
        );

        res.json({ message: 'Servicio eliminado de la cita', total: nuevoTotal });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar servicio' });
    }
});

// ========== GENERAR DEUDA DESDE CITA (endpoint alternativo) ==========
router.post('/:id/generar-deuda', verificarToken, verificarRol(['admin', 'secretaria']), async (req, res) => {
    try {
        const { id } = req.params;

        const citaResult = await pool.query(
            `SELECT c.*, p.nombre as paciente_nombre 
             FROM citas c
             JOIN pacientes p ON c.paciente_id = p.id
             WHERE c.id = $1 AND c.consultorio_id = $2`,
            [id, req.usuario.consultorioId]
        );

        if (citaResult.rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        const cita = citaResult.rows[0];

        const deudaExistente = await pool.query(
            `SELECT id FROM cobranza WHERE cita_id = $1`,
            [id]
        );

        if (deudaExistente.rows.length > 0) {
            return res.status(400).json({ error: 'Esta cita ya tiene una deuda generada' });
        }

        const serviciosResult = await pool.query(
            `SELECT s.nombre, cs.cantidad, cs.precio_unitario 
             FROM cita_servicios cs
             JOIN servicios s ON cs.servicio_id = s.id
             WHERE cs.cita_id = $1`,
            [id]
        );

        let total = 0;
        let concepto = '';

        if (serviciosResult.rows.length > 0) {
            total = serviciosResult.rows.reduce((sum, s) => sum + (s.cantidad * s.precio_unitario), 0);
            const serviciosList = serviciosResult.rows.map(s => `${s.nombre} (${s.cantidad})`).join(', ');
            concepto = `Cita del ${new Date(cita.fecha_hora).toLocaleDateString()}: ${serviciosList}`;
        } else {
            concepto = `Cita del ${new Date(cita.fecha_hora).toLocaleDateString()}`;
        }

        const esCortesia = cita.es_cortesia || false;
        const monto = esCortesia ? 0 : total;
        const estado = esCortesia ? 'pagado' : 'pendiente';

        const result = await pool.query(
            `INSERT INTO cobranza (consultorio_id, paciente_id, cita_id, monto, concepto, estado, es_cortesia, registrado_por) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING *`,
            [req.usuario.consultorioId, cita.paciente_id, id, monto, concepto, estado, esCortesia, req.usuario.id]
        );

        res.status(201).json({ message: 'Deuda generada exitosamente', deuda: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al generar deuda' });
    }
});

module.exports = router;