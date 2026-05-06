const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: '*' }));
app.use(express.json());

// Conexión a base de datos
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Endpoint de prueba
app.get('/api/test', (req, res) => {
    res.json({ mensaje: 'Test exitoso', timestamp: new Date() });
});

// Endpoint de registro
app.post('/api/auth/registro', async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;
        
        if (!nombre || !email || !password) {
            return res.status(400).json({ exito: false, mensaje: 'Faltan campos' });
        }
        
        const bcrypt = require('bcrypt');
        const password_hash = await bcrypt.hash(password, 10);
        
        const result = await pool.query(
            `INSERT INTO consultorios (nombre, email, password_hash, telefono, direccion) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id, nombre, email`,
            [nombre, email, password_hash, telefono, direccion]
        );
        
        res.json({ exito: true, mensaje: 'Registrado', consultorio: result.rows[0] });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ exito: false, mensaje: error.message });
    }
});

app.get('/', (req, res) => {
    res.json({ mensaje: 'Backend funcionando 🚀' });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});