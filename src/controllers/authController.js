const usuarioModel = require('../models/usuario');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const registrar = async (req, res) => {
    try {
        const { nombre, email, password, telefono, direccion } = req.body;
        
        if (!nombre || !email || !password) {
            return res.status(400).json({ error: 'Faltan campos requeridos' });
        }
        
        const existe = await usuarioModel.encontrarPorEmail(email);
        if (existe) {
            return res.status(400).json({ error: 'Email ya registrado' });
        }
        
        const { consultorio, usuario } = await usuarioModel.crearConsultorio(nombre, email, password, telefono, direccion);
        res.status(201).json({ message: 'Consultorio registrado exitosamente', consultorio, usuario });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const usuario = await usuarioModel.encontrarPorEmail(email);
        if (!usuario) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        
        const passwordValida = await bcrypt.compare(password, usuario.password_hash);
        if (!passwordValida) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }
        
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email, rol: usuario.rol, consultorioId: usuario.consultorio_id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login exitoso',
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                email: usuario.email,
                rol: usuario.rol,
                consultorio: usuario.consultorio_nombre
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
};

module.exports = { registrar, login };