const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');
const medicosRoutes = require('./routes/medicosRoutes');
const pacientesRoutes = require('./routes/pacientesRoutes');
const citasRoutes = require('./routes/citasRoutes');
const cobranzaRoutes = require('./routes/cobranzaRoutes');
const serviciosRoutes = require('./routes/serviciosRoutes');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Rutas
app.use('/api/auth', authRoutes);
app.use('/api/medicos', medicosRoutes);
app.use('/api/pacientes', pacientesRoutes);
app.use('/api/citas', citasRoutes);
app.use('/api/cobranza', cobranzaRoutes);
app.use('/api/servicios', serviciosRoutes);

app.get('/', (req, res) => {
    res.json({ message: 'Backend funcionando 🚀' });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});