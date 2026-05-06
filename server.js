const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

console.log('🔧 Iniciando configuración...');

app.use(cors({ origin: '*' }));
app.use(express.json());

console.log('🔧 Conectando a base de datos...');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
    if (err) {
        console.error('❌ Error conectando a la base de datos:', err);
    } else {
        console.log('✅ Conexión a base de datos exitosa');
    }
});

console.log('🔧 Configurando rutas...');

// Endpoint de prueba
app.get('/api/test', (req, res) => {
    console.log('📡 Petición a /api/test recibida');
    res.json({ mensaje: 'Test exitoso', timestamp: new Date() });
});

app.get('/', (req, res) => {
    res.json({ mensaje: 'Backend funcionando 🚀' });
});

console.log('🔧 Iniciando servidor...');

app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});