const pool = require('../db/connection');
const bcrypt = require('bcrypt');

// Crear un nuevo consultorio con usuario admin
const crearConsultorio = async (nombre, email, password, telefono, direccion) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const password_hash = await bcrypt.hash(password, 10);
        
        // Crear consultorio
        const consultorioResult = await client.query(
            'INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [nombre, email, password_hash, telefono, direccion]
        );
        const consultorioId = consultorioResult.rows[0].id;
        
        // Crear usuario admin
        const usuarioResult = await client.query(
            'INSERT INTO usuarios (consultorio_id, nombre, email, password_hash, rol) VALUES ($1, $2, $3, $4, $5) RETURNING id, nombre, email, rol',
            [consultorioId, nombre, email, password_hash, 'admin']
        );
        
        await client.query('COMMIT');
        return { consultorio: { id: consultorioId, nombre, email }, usuario: usuarioResult.rows[0] };
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
};

const encontrarPorEmail = async (email) => {
    const result = await pool.query(
        `SELECT u.*, c.nombre as consultorio_nombre, c.plan 
         FROM usuarios u 
         JOIN consultorios c ON u.consultorio_id = c.id 
         WHERE u.email = $1`,
        [email]
    );
    return result.rows[0];
};

module.exports = { crearConsultorio, encontrarPorEmail };