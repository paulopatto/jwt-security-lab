import express, { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { createClient } from 'redis';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'fallback_secret';
const ISSUER = 'lab-api';
const AUDIENCE = 'lab-app';

// Configuração do Redis
const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (err) => console.error('Redis Client Error', err));
redis.connect().then(() => console.log('Redis conectado!'));

// ==========================================
// 5. Rate limit no endpoint de login
// ==========================================
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 5, // Limite de 5 tentativas por IP
  message: { error: 'Muitas tentativas de login. Tente novamente em 1 minuto.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ==========================================
// Middleware Seguro (Pontos 1, 2, 4 e 6)
// ==========================================
async function secureAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  try {
    // 1 e 2. Algoritmo explícito e Validação de Claims obrigatórias
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      issuer: ISSUER,
      audience: AUDIENCE
    }) as jwt.JwtPayload;

    // 4. Verificação na Blacklist (Redis)
    if (decoded.jti) {
      const isRevoked = await redis.get(`revoked:${decoded.jti}`);
      if (isRevoked) {
        console.warn(`[SEGURANÇA] Tentativa de uso de token revogado: ${decoded.jti}`);
        return res.status(401).json({ error: 'Token inválido ou expirado' }); // Erro genérico pro cliente
      }
    }

    (req as any).user = decoded;
    next();
  } catch (err: any) {
    // 6. Erro genérico pro cliente, log detalhado pro time
    console.error(`[AUTH ERROR] Falha na verificação: ${err.message}`, { token: token.substring(0, 10) + '...' });
    res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ==========================================
// ROTAS DO LABORATÓRIO
// ==========================================

// ==========================================
// Middleware INSEGURO
// ==========================================
function insecureAuthMiddleware(req: Request, res: Response, next: NextFunction) { 
  const token = req.headers.authorization?.split(' ')[1]; 
  if (!token) return res.status(401).json({error: 'no token'}); 
  
  try { 
    // VULNERABILIDADE: Sem checagem de algoritmo, sem checagem de claims (issuer/audience), sem blacklist.
    (req as any).user = jwt.verify(token, SECRET); 
    next(); 
  } catch { 
    res.status(401).json({error: 'invalid token'}); 
  } 
}

// Rota Insegura
app.get('/dados-inseguros', insecureAuthMiddleware, (req: Request, res: Response) => {
  res.json({ message: 'Acesso concedido (Inseguro)', user: (req as any).user });
});

// Rota de Login (Gera o Token com JTI, ISS e AUD)
app.post('/login', loginLimiter, (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Mock de validação de usuário
  if (username !== 'admin' || password !== '1234') {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  const jti = uuidv4(); // Identificador único do token
  
  // 3. Access token curto (ex: 15 min)
  const token = jwt.sign({ username }, SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
    issuer: ISSUER,
    audience: AUDIENCE,
    jwtid: jti
  });

  res.json({ token, jti });
});

// Rota de Logout (Adiciona na Blacklist)
app.post('/logout', secureAuthMiddleware, async (req: Request, res: Response) => {
  const user = (req as any).user;
  
  // Calcula tempo restante do token para definir o TTL no Redis
  const exp = user.exp; // Timestamp de expiração
  const now = Math.floor(Date.now() / 1000);
  const timeRemaining = exp - now;

  if (timeRemaining > 0) {
    // 4. Blacklist de token revogado com TTL
    await redis.setEx(`revoked:${user.jti}`, timeRemaining, 'true');
  }

  res.json({ message: 'Logout realizado. Token revogado.' });
});

// Rota Protegida
app.get('/dados-sensiveis', secureAuthMiddleware, (req: Request, res: Response) => {
  res.json({ message: 'Sucesso! Você acessou dados protegidos.', user: (req as any).user });
});


if (require.main === module) {
  app.listen(3000, () => console.log('Servidor rodando na porta 3000'));
}
export default app;
