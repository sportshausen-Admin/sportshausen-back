const jwt = require('jsonwebtoken');
const axios = require('axios');

const JWT_SECRET  = process.env.JWT_SECRET || 'fallback-secret-change-me';
const TOKEN_TTL_S = (parseInt(process.env.TOKEN_TTL_HOURS, 10) || 8) * 3600;

const extractBearer = (req) => {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : h || null;
};

const errUnauth = (res, msg = 'Token inválido o expirado') =>
  res.status(401).json({ success: false, error: msg, message: 'Por favor inicia sesión nuevamente' });

// Firma nuestro JWT envolviendo el token de Xano
const storeToken = (xanoToken, userData) => {
  return jwt.sign(
    {
      xanoToken,
      id:    userData.id    || userData.user_id || null,
      email: userData.email || null,
      role:  userData.role  || 'luchador',
    },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL_S }
  );
};

// JWT stateless: el logout lo maneja el cliente limpiando sessionStorage
const removeToken = (_token) => {};

const decodeOurJWT = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

const verifyAuth = (req, res, next) => {
  const token = extractBearer(req);
  if (!token) return errUnauth(res, 'No se proporcionó token de autenticación');

  const decoded = decodeOurJWT(token);
  if (!decoded) return errUnauth(res);

  req.user  = { id: decoded.id, email: decoded.email, role: decoded.role };
  req.token = decoded.xanoToken || token;
  next();
};

const protect = verifyAuth;

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: 'Usuario no autenticado' });
  const userRole = req.user.role;
  if (!userRole || !roles.includes(userRole)) {
    return res.status(403).json({
      success: false,
      error: 'Permiso denegado',
      message: `Se requiere uno de los siguientes roles: ${roles.join(', ')}`,
    });
  }
  next();
};

const softProtect = async (req, res, next) => {
  const rawToken = extractBearer(req);
  if (!rawToken) return res.status(401).json({ success: false, error: 'Token requerido' });

  // Si es nuestro JWT, no necesitamos llamar a Xano
  const decoded = decodeOurJWT(rawToken);
  if (decoded) {
    req.token = decoded.xanoToken || rawToken;
    req.user  = { id: decoded.id, role: decoded.role };
    return next();
  }

  // Fallback por compatibilidad: validar token directo de Xano
  const xanoBase = process.env.XANO_API_URL;
  const authCfg  = { headers: { Authorization: `Bearer ${rawToken}` }, timeout: 5000 };
  const endpoints = ['/auth/me', '/user', '/auth/user', '/users/me'];

  for (const ep of endpoints) {
    try {
      const { data } = await axios.get(`${xanoBase}${ep}`, authCfg);
      if (data && (data.id || data.user_id)) {
        req.token = rawToken;
        req.user  = { id: data.id || data.user_id, role: data.role || data.tipo_usuario || null };
        return next();
      }
    } catch (_) {}
  }

  return res.status(401).json({ success: false, error: 'Token inválido o expirado' });
};

// Saca el token de Xano de la request, sea que ya lo procesó un middleware o no
const getXanoToken = (req) => {
  if (req.token) return req.token;
  const h = req.headers.authorization || '';
  const raw = h.startsWith('Bearer ') ? h.slice(7) : h || null;
  if (!raw) return null;
  const decoded = decodeOurJWT(raw);
  return decoded?.xanoToken || raw;
};

module.exports = { verifyAuth, storeToken, removeToken, protect, requireRole, softProtect, getXanoToken };
