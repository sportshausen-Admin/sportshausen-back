const bcrypt      = require('bcryptjs');
const xanoService = require('../services/xanoService');
const userMapService = require('../services/userMapService');
const { storeToken, removeToken } = require('../middlewares/authMiddleware');

const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 10;

const EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

const validatePasswordComplexity = (pwd) => {
  if (!pwd || typeof pwd !== 'string') return 'Contraseña requerida';
  if (pwd.length < 8)  return 'La contraseña debe tener al menos 8 caracteres';
  if (!/[A-Z]/.test(pwd)) return 'La contraseña debe contener al menos una letra mayúscula';
  if (!/[a-z]/.test(pwd)) return 'La contraseña debe contener al menos una letra minúscula';
  if (!/[0-9]/.test(pwd)) return 'La contraseña debe contener al menos un número';
  if (!/[^A-Za-z0-9]/.test(pwd)) return 'La contraseña debe contener al menos un carácter especial (!@#$%^&*)';
  return null;
};

const extractToken = (obj) => {
  if (!obj) return null;
  for (const k of ['authToken', 'token', 'access_token', 'auth_token']) {
    if (obj[k] && typeof obj[k] === 'string') return obj[k];
  }
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === 'string' && key.toLowerCase().includes('token')) return val;
    if (val && typeof val === 'object') {
      const nested = extractToken(val);
      if (nested) return nested;
    }
  }
  // último recurso: buscar cualquier string con forma JWT
  const findJWT = (o) => {
    if (!o) return null;
    if (typeof o === 'string' && o.split('.').length === 3 && o.length > 20) return o;
    if (typeof o === 'object') {
      for (const k of Object.keys(o)) { const r = findJWT(o[k]); if (r) return r; }
    }
    return null;
  };
  return findJWT(obj);
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email y contraseña son requeridos' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ success: false, error: 'Formato de email inválido' });
    }

    // Si tenemos el hash guardado localmente, validamos antes de ir a Xano
    const storedHash = userMapService.getPasswordHash(email);
    if (storedHash) {
      const passwordValid = await bcrypt.compare(password, storedHash);
      if (!passwordValid) {
        return res.status(401).json({ success: false, error: 'Credenciales inválidas' });
      }
    }

    const xanoResponse = await xanoService.login(email, password);
    if (!xanoResponse.success) {
      return res.status(xanoResponse.status || 401).json({ success: false, error: 'Credenciales inválidas' });
    }

    // Primera vez que inicia sesión: guardar el hash para futuros logins
    if (!storedHash) {
      const userId = xanoResponse.data?.user_id || xanoResponse.data?.id;
      const migrationHash = await bcrypt.hash(password, SALT_ROUNDS);
      userMapService.saveUser(email, null, { user_id: userId, passwordHash: migrationHash });
    }

    return _buildLoginResponse(res, xanoResponse, email, password);

  } catch (err) {
    console.error('[login] Error interno');
    return res.status(500).json({ success: false, error: 'Error interno del servidor' });
  }
};

const signup = async (req, res) => {
  try {
    const { name, email, password, role = 'luchador' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Nombre, email y contraseña son requeridos' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ success: false, error: 'Formato de email inválido' });
    }
    if (name.trim().length < 2) {
      return res.status(400).json({ success: false, error: 'El nombre debe tener al menos 2 caracteres' });
    }

    const pwdError = validatePasswordComplexity(password);
    if (pwdError) {
      return res.status(400).json({ success: false, error: pwdError });
    }

    const validRoles = ['luchador', 'booker', 'agrupacion'];
    let finalRole = (role || 'luchador').toLowerCase().trim();
    if (finalRole === 'agrupación') finalRole = 'agrupacion';
    if (!validRoles.includes(finalRole)) {
      return res.status(400).json({ success: false, error: 'Rol inválido. Debe ser: luchador, booker o agrupacion' });
    }

    const xanoResponse = await xanoService.signup(name, email, password, finalRole);
    if (!xanoResponse.success) {
      return res.status(xanoResponse.status || 400).json({
        success: false,
        error: xanoResponse.error,
        message: 'Error al crear la cuenta',
      });
    }

    const token  = xanoResponse.data?.authToken || xanoResponse.data?.token;
    const userId = xanoResponse.data?.user_id   || xanoResponse.data?.id;

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    userMapService.saveUser(email, finalRole, {
      nombre_artistico: name,
      user_id: userId,
      passwordHash,
    });

    const ourJWT = token
      ? storeToken(token, { id: userId, email, role: finalRole })
      : null;

    if (userId) {
      xanoService.sendWelcomeEmail(userId).catch(() => {});
    }

    return res.status(201).json({
      success: true,
      data: {
        authToken: ourJWT || token,
        user: { id: userId, email, nombre_artistico: name, role: finalRole },
      },
      message: 'Cuenta creada exitosamente',
    });

  } catch (err) {
    console.error('[signup] Error interno');
    return res.status(500).json({ success: false, error: 'Error interno del servidor' });
  }
};

const logout = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    if (token) {
      removeToken(token);
      xanoService.logout(token).catch(() => {});
    }

    return res.status(200).json({ success: true, message: 'Sesión cerrada exitosamente' });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Error interno del servidor' });
  }
};

const _normalizeRole = (val) => {
  if (!val) return null;
  const s = String(val).toLowerCase().trim().normalize('NFD').replace(/[̀-ͯ]/g, '');
  if (s === 'agrupacion') return 'agrupacion';
  if (s === 'booker') return 'booker';
  if (s === 'luchador') return 'luchador';
  return null;
};

const _extractRoleFromData = (data) => {
  if (!data) return null;
  return _normalizeRole(data.role) ||
         _normalizeRole(data.tipo_usuario) ||
         _normalizeRole(data.type) ||
         _normalizeRole(data.user_type) ||
         null;
};

const _buildLoginResponse = async (res, xanoResponse, email, _pwd) => {
  const token  = extractToken(xanoResponse.data);
  const userId = xanoResponse.data?.user_id || xanoResponse.data?.id || xanoResponse.data?.user?.id;

  // Traer el perfil completo desde Xano para obtener el rol real y el nombre
  let profileData = null;
  try {
    if (token) {
      const me = await xanoService.getMe(token);
      if (me.success && me.data) {
        profileData = me.data;
      } else if (userId) {
        const profile = await xanoService.getProfileById(token, userId);
        if (profile.success && profile.data) {
          profileData = profile.data;
        } else {
          const ud = await xanoService.getUserData(token, userId);
          if (ud.success && ud.data) profileData = ud.data;
        }
      }
    }
  } catch (e) {
    console.error('[_buildLoginResponse] error obteniendo perfil:', e.message);
  }

  let userRole =
    _extractRoleFromData(profileData) ||
    _extractRoleFromData(xanoResponse.data) ||
    _extractRoleFromData(xanoResponse.data?.user) ||
    userMapService.getUserRole(email) ||
    'luchador';

  console.log(`[login] rol detectado para ${email}: ${userRole}`);

  if (userMapService.getUserRole(email) !== userRole) {
    userMapService.updateRole(email, userRole);
  }

  const ourJWT = token
    ? storeToken(token, { id: userId, email, role: userRole })
    : null;

  const responseData = {
    authToken: ourJWT || token,
    user: {
      ...(profileData || {}),
      role: userRole,
      email,
      id: userId,
    },
  };

  return res.status(200).json({ success: true, data: responseData, message: 'Login exitoso' });
};

module.exports = { login, signup, logout };
