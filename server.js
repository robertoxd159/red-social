const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;

// Configuración de la base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('Base de datos conectada');
});

// Middleware
app.use(express.json());

// Registro de usuarios
app.post('/registro', async (req, res) => {
    const { nombre, correo, contraseña } = req.body;
    const hash = await bcrypt.hash(contraseña, 10);
    const sql = `INSERT INTO usuarios (nombre, correo, contraseña) VALUES (?, ?, ?)`;

    db.query(sql, [nombre, correo, hash], (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.send('Usuario registrado');
    });
});

// Inicio de sesión
app.post('/login', (req, res) => {
    const { correo, contraseña } = req.body;
    const sql = `SELECT * FROM usuarios WHERE correo = ?`;

    db.query(sql, [correo], async (err, results) => {
        if (err || results.length === 0) return res.status(404).send('Usuario no encontrado');
        const user = results[0];
        const valid = await bcrypt.compare(contraseña, user.contraseña);

        if (!valid) return res.status(401).send('Contraseña incorrecta');

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Escuchar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
