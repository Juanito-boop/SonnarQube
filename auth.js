const jwt = require('jsonwebtoken');

const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ mensaje: 'Token requerido' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // { id, rol, pais_id }
    next();
  } catch (error) {
    return res.status(403).json({ mensaje: 'Token inválido o expirado' });
  }
};

const soloSuperadmin = (req, res, next) => {
  if (req.usuario.rol !== 'superadmin') {
    return res.status(403).json({ mensaje: 'Acceso denegado: se requiere superadmin' });
  }
  next();
};

module.exports = { verificarToken, soloSuperadmin };